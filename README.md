# Asynchronous Web Server

This project implements a high-performance, asynchronous web server in C. It demonstrates advanced I/O operations including non-blocking sockets, asynchronous file reading, and zero-copying file transfers. The server handles basic HTTP requests by serving files from distinct directories for static and dynamic content.

## Features

- **Asynchronous I/O:**
  Utilizes asynchronous file operations and non-blocking sockets with epoll-based multiplexing for efficient connection handling.

- **HTTP Protocol Support:**
  Constructs precise HTTP response headers with dynamic fields (Date, Server, Content-Length, etc.) for successful resource requests and prepares proper 404 responses when files are not found.

- **State Machine per Connection:**
  Each client connection is managed by a dedicated state machine that handles transitions through:
  - Receiving data
  - Preparing and sending reply headers
  - Asynchronous file I/O for serving content
  - Sending file data or 404 responses as needed

- **Zero-Copy File Transfer:**
  Leverages system calls like sendfile for efficient, low-overhead transfer of file data directly from disk to socket.

- **Integrated Testing and Linting:**
  Automated tests are available in the tests/ directory. Linting is set up using cpplint and shellcheck to ensure code quality.

- **Docker-based Checker:**
  Scripts and Docker configuration allow you to build a containerized environment for running functionality tests and style checks.

## Building the Project

The project contains multiple Makefiles to compile the web server executable and run the tests.

```bash
# Build the server executable from the src/ directory
make all
```

```bash
# Run the test suite from the tests/ directory
make check
```

```bash
# Clean build artifacts
make clean
```

## Example Usage

After building, you can run the server directly. For local Docker testing using the provided scripts:

```bash
./local.sh docker build   # Build the Docker image for the project
./local.sh checker         # Run the local checker to test functionality and style
```

## Implementation Details

- **HTTP Header Preparation:**
  The server builds HTTP response headers using functions like `connection_prepare_send_reply_header`, ensuring that all responses include accurate fields (including dynamic fields such as Date and Content-Length).

- **404 Response Handling:**
  When a requested resource is not found, the function `connection_prepare_send_404` creates and sends a proper HTTP 404 Not Found response.

- **State Machine Management:**
  Each connection uses a well-defined state machine (e.g., STATE_RECEIVING_DATA, STATE_SENDING_HEADER, STATE_SENDING_DATA, STATE_404_SENT) to manage transitions from receiving a request to sending the response, ensuring smooth and efficient processing.

- **Asynchronous File I/O:**
  Asynchronous operations are implemented using libaio (with context and iocb structures) to allow non-blocking file reads, which is critical for dynamically processing and serving file content.

- **HTTP Parsing Callbacks:**
  Integration with the HTTP parser module includes callbacks (such as `aws_on_path_cb`) that extract the request path, allowing the server to route the request appropriately for static or dynamic content.

- **Modular Design:**
  Core functionalities (socket operations, debugging, and utility functions) are split into modular components, promoting readability, ease of testing, and maintainability. The implementation is primarily found in [`src/aws.c`](src/aws.c) and correlates with headers and utilities in the project.

## Technical Notes

For testing the server functionality, you can run the server directly from the terminal and test with standard networking tools. For example, follow these steps:

```bash
# In one terminal, start the server on port 8080:
./aws
```

Once the server is running, open another terminal and fetch a file using wget:

```bash
wget http://localhost:8080/static/small00.dat
```

This will download the `small00.dat` file served by the web server. Ensure that the file exists in the designated static content directory. The server logs will reflect the incoming HTTP request and the corresponding response status.