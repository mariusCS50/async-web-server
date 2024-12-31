// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <sys/eventfd.h>
#include <libaio.h>
#include <errno.h>

#include "aws.h"
#include "utils/util.h"
#include "utils/debug.h"
#include "utils/sock_util.h"
#include "utils/w_epoll.h"

/* server socket file descriptor */
static int listenfd;

/* epoll file descriptor */
static int epollfd;

static io_context_t ctx;

static int aws_on_path_cb(http_parser *p, const char *buf, size_t len)
{
	struct connection *conn = (struct connection *)p->data;

	memcpy(conn->request_path, buf, len);
	conn->request_path[len] = '\0';
	conn->have_path = 1;

	return 0;
}

static void connection_prepare_send_reply_header(struct connection *conn)
{
	/* Prepare the connection buffer to send the reply header. */
	char header[BUFSIZ] = "HTTP/1.1 200 OK\r\n"
		"Date: Sun, 08 May 2011 09:26:16 GMT\r\n"
		"Server: Apache/2.2.9\r\n"
		"Last-Modified: Mon, 02 Aug 2010 17:55:28 GMT\r\n"
		"Accept-Ranges: bytes\r\n"
		"Content-Length: %ld\r\n"
		"Vary: Accept-Encoding\r\n"
		"Connection: close\r\n"
		"Content-Type: text/html\r\n\r\n";
	conn->send_len = snprintf(conn->send_buffer, BUFSIZ, header, conn->file_size);
	conn->state = STATE_SENDING_HEADER;
	return;
}

static void connection_prepare_send_404(struct connection *conn)
{
	/* Prepare the connection buffer to send the 404 header. */
	char header[BUFSIZ] = "HTTP/1.1 404 Not Found\r\n"
		"Date: Sun, 08 May 2011 09:26:16 GMT\r\n"
		"Server: Apache/2.2.9\r\n"
		"Last-Modified: Mon, 02 Aug 2010 17:55:28 GMT\r\n"
		"Accept-Ranges: bytes\r\n"
		"Content-Length: %ld\r\n"
		"Vary: Accept-Encoding\r\n"
		"Connection: close\r\n"
		"Content-Type: text/html\r\n\r\n";
	conn->send_len = snprintf(conn->send_buffer, BUFSIZ, header, conn->file_size);
	conn->state = STATE_SENDING_404;
	return;
}

static enum resource_type connection_get_resource_type(struct connection *conn)
{
	/* Get resource type depending on request path/filename. Filename should
	 * point to the static or dynamic folder.
	 */
	if (strstr(conn->request_path, "static"))
		return RESOURCE_TYPE_STATIC;

	if (strstr(conn->request_path, "dynamic"))
		return RESOURCE_TYPE_DYNAMIC;

	return RESOURCE_TYPE_NONE;
}


struct connection *connection_create(int sockfd)
{
	struct connection *conn = malloc(sizeof(struct connection));

	DIE(conn == NULL, "malloc");

	conn->ctx = ctx;
	conn->sockfd = sockfd;
	conn->state = STATE_INITIAL;
	conn->request_parser.data = conn;
	memset(conn->recv_buffer, 0, BUFSIZ);
	memset(conn->send_buffer, 0, BUFSIZ);
	memset(conn->request_path, 0, BUFSIZ);

	return conn;
}

void connection_remove(struct connection *conn)
{
	/* Remove connection from epoll and close it */
	dlog(LOG_DEBUG, "Closing connection\n");
	if (conn->sockfd)
		close(conn->sockfd);
	conn->state = STATE_CONNECTION_CLOSED;
	free(conn);
}

void handle_new_connection(void)
{
	/* Handle a new connection request on the server socket. */
	static int sockfd;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	struct connection *conn;
	int rc;

	/* Accept new connection. */
	sockfd = accept(listenfd, (SSA *) &addr, &addrlen);
	DIE(sockfd == -1, "accept() error");

	/* Set socket to be non-blocking. */
	fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);
	DIE(sockfd == -1, "fcntl() error");

	/* Instantiate new connection handler. */
	conn = connection_create(sockfd);

	/* Add socket to epoll. */
	rc = w_epoll_add_ptr_in(epollfd, sockfd, conn);
	DIE(rc == -1, "w_epoll_add_in() error");

	/* Initialize HTTP_REQUEST parser. */
	http_parser_init(&conn->request_parser, HTTP_REQUEST);
	dlog(LOG_DEBUG, "Connection established\n");
}

void receive_data(struct connection *conn)
{
	/* Receive message on socket.
	 * Store message in recv_buffer in struct connection.
	 */
	ssize_t bytes_recv;
	int rc;
	char abuffer[64];

	rc = get_peer_address(conn->sockfd, abuffer, 64);
	if (rc < 0) {
		connection_remove(conn);
		return conn->state;
	}

	ssize_t total_recieved = 0;

	while (total_recieved < BUFSIZ) {
        bytes_recv = recv(conn->sockfd, conn->recv_buffer + total_recieved, BUFSIZ - total_recieved, 0);
        if (bytes_recv < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;

            connection_remove(conn);
            return conn->state;
        }

        total_recieved += bytes_recv;

        if (strstr(conn->recv_buffer, "\r\n\r\n")) {
            break;
        }
    }

	dlog(LOG_DEBUG, "Received message from: %s\n", abuffer);

	conn->recv_len = total_recieved;
	conn->state = STATE_REQUEST_RECEIVED;

	rc = w_epoll_update_ptr_out(epollfd, conn->sockfd, conn);
	DIE(rc < 0, "w_epoll_add_ptr_out() error");

	return STATE_REQUEST_RECEIVED;
}

int connection_open_file(struct connection *conn)
{
	/* Open file and update connection fields. */
	char full_path[BUFSIZ];
    snprintf(full_path, BUFSIZ, ".%s", conn->request_path);

	// dlog(LOG_DEBUG, "Path: %s\n", conn->request_path);

	if (strcmp(full_path, "./") == 0) {
		return -1;
	}

    int fd = open(full_path, O_RDONLY, 0744);
	if (fd == -1) {
		conn->state = STATE_SENDING_404;
		return -1;
	}
	struct stat st;

	conn->fd = fd;
	fstat(fd, &st);
	conn->file_size = st.st_size;

	char *filename = strrchr(conn->request_path, '/') + 1;
	strcpy(conn->filename, filename);

	conn->state = STATE_SENDING_HEADER;

	return 0;
}

int connection_send_dynamic(struct connection *conn)
{
	/* Read data asynchronously.
	 * Returns 0 on success and -1 on error.
	 */
	struct io_event event;
	u_int64_t rc;

	conn->state = STATE_ASYNC_ONGOING;
	conn->file_pos = 0;

	conn->piocb[0] = &conn->iocb;

	while (conn->file_pos < conn->file_size) {
		io_prep_pread(conn->piocb[0], conn->fd, conn->send_buffer, BUFSIZ, conn->file_pos);
		io_submit(conn->ctx, 1, conn->piocb);
		io_getevents(conn->ctx, 1, 100, &event, NULL);

		io_prep_pwrite(conn->piocb[0], conn->sockfd, conn->send_buffer, BUFSIZ, 0);
		io_submit(conn->ctx, 1, conn->piocb);
		io_getevents(conn->ctx, 1, 100, &event, NULL);

        conn->file_pos += BUFSIZ;
    }


	conn->state = STATE_DATA_SENT;
	return 0;
}

int parse_header(struct connection *conn)
{
	/* Parse the HTTP header and extract the file path. */
	/* Use mostly null settings except for on_path callback. */
	http_parser_settings settings_on_path = {
		.on_message_begin = 0,
		.on_header_field = 0,
		.on_header_value = 0,
		.on_path = aws_on_path_cb,
		.on_url = 0,
		.on_fragment = 0,
		.on_query_string = 0,
		.on_body = 0,
		.on_headers_complete = 0,
		.on_message_complete = 0
	};
	http_parser_execute(&conn->request_parser, &settings_on_path, conn->recv_buffer, conn->recv_len);
	return 0;
}

enum connection_state connection_send_static(struct connection *conn)
{
	/* Send static data using sendfile(2). */
	ssize_t bytes_sent;
	int rc;
	char abuffer[64];

	rc = get_peer_address(conn->sockfd, abuffer, 64);
	if (rc < 0) {
		connection_remove(conn);
		return conn->state;
	}

	ssize_t total_sent = 0;
	int offset = 0;

    while (total_sent < conn->file_size) {
        bytes_sent = sendfile(conn->sockfd, conn->fd, &offset, conn->file_size - total_sent);
        if (bytes_sent < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;

            connection_remove(conn);
            return conn->state;
        }

        total_sent += bytes_sent;
    }

	dlog(LOG_DEBUG, "File sent\n");

	rc = w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
	DIE(rc == -1, "w_epoll_remove_ptr() error");

	connection_remove(conn);
	return STATE_DATA_SENT;
}

int connection_send_data(struct connection *conn)
{
	/* Send as much data as possible from the connection send buffer.
	 * Returns the number of bytes sent or -1 if an error occurred
	 */
	enum resource_type file_type = connection_get_resource_type(conn);

	if (file_type == RESOURCE_TYPE_STATIC) {
		dlog(LOG_DEBUG, "Static file\n");
		connection_send_static(conn);
	}

	if (file_type == RESOURCE_TYPE_DYNAMIC) {
		dlog(LOG_DEBUG, "Dynamic file\n");
		connection_send_dynamic(conn);
	}

	return 0;
}

int connection_prepare_header(struct connection *conn)
{
	/* Prepares the header to be sent based on the requested file */
	parse_header(conn);

	if (connection_open_file(conn) == -1) {
		connection_prepare_send_404(conn);
	} else {
		connection_prepare_send_reply_header(conn);
	}

	return 0;
}

int connection_send_header(struct connection *conn)
{
	/* Sent the header corresponding to the requested file */
	ssize_t bytes_sent;
	int rc;
	char abuffer[64];

	rc = get_peer_address(conn->sockfd, abuffer, 64);
	if (rc < 0) {
		connection_remove(conn);
		return conn->state;
	}

    ssize_t total_sent = 0;

    while (total_sent < conn->send_len) {
        bytes_sent = send(conn->sockfd, conn->send_buffer + total_sent, conn->send_len - total_sent, 0);
        if (bytes_sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;

            connection_remove(conn);
            return conn->state;
        }

        total_sent += bytes_sent;
    }

    dlog(LOG_DEBUG, "Header sent\n");
    conn->state = (conn->state == STATE_SENDING_404 ? STATE_404_SENT : STATE_HEADER_SENT);

    return 0;
}

void handle_input(struct connection *conn)
{
	/* Handle input information: may be a new message or notification of
	 * completion of an asynchronous I/O operation.
	 */
	switch (conn->state) {
	case STATE_INITIAL:
		receive_data(conn);
		break;
	default:
		printf("shouldn't get here %d\n", conn->state);
	}
}

void handle_output(struct connection *conn)
{
	/* Handle output information: may be a new valid requests or notification of
	 * completion of an asynchronous I/O operation or invalid requests.
	 */
	switch (conn->state) {
		case STATE_REQUEST_RECEIVED:
			connection_prepare_header(conn);
			break;
		case STATE_SENDING_404:
			connection_send_header(conn);
			break;
		case STATE_SENDING_HEADER:
			connection_send_header(conn);
			break;
		case STATE_404_SENT:
			connection_remove(conn);
			break;
		case STATE_HEADER_SENT:
			connection_send_data(conn);
			break;
		case STATE_ASYNC_ONGOING:
			//dlog(LOG_DEBUG, "async ongoing\n");
			break;
		case STATE_DATA_SENT:
			connection_remove(conn);
			break;
	default:
		printf("shouldn't get here %d\n", conn->state);
		exit(1);
	}
}

void handle_client(uint32_t event, struct connection *conn)
{
	/* Handle new client. There can be input and output connections.
	 * Take care of what happened at the end of a connection.
	 */
	if (event & EPOLLIN)
		handle_input(conn);
	else if (event & EPOLLOUT)
		handle_output(conn);
}

int main(void)
{
	int rc;

	/* Initialize asynchronous operations. */
	rc = io_setup(100, &ctx);
	DIE(rc == -1, "io_setup() error");

	/* Initialize multiplexing. */
	epollfd = w_epoll_create();
	DIE(epollfd == -1, "w_epoll_create() error");

	/* Create server socket. */
	listenfd = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);
	DIE(listenfd == -1, "tcp_create_listener() error");

	/* Add server socket to epoll object*/
	rc = w_epoll_add_fd_in(epollfd, listenfd);
	DIE(rc == -1, "w_epoll_add_fd_in() error");

	/* Uncomment the following line for debugging. */
	dlog(LOG_INFO, "Server waiting for connections on port %d\n", AWS_LISTEN_PORT);

	/* server main loop */
	while (1) {
		struct epoll_event rev;

		/* Wait for events. */
		rc = w_epoll_wait_infinite(epollfd, &rev);
		DIE(rc == -1, "w_epoll_wait_infinite() error");

		/* Switch event types; consider
		 *   - new connection requests (on server socket)
		 *   - socket communication (on connection sockets)
		 */
		if (rev.data.fd == listenfd) {
			if (rev.events & EPOLLIN)
				handle_new_connection();
		} else {
			handle_client(rev.events, rev.data.ptr);
		}
	}

	return 0;
}
