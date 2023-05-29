FROM gitlab.cs.pub.ro:5050/operating-systems/assignments-docker-base

RUN apt update -yqq
RUN apt install -yqq libaio-dev
RUN apt install -yqq lsof
RUN apt install -yqq netcat

COPY ./checker ${CHECKER_DATA_DIRECTORY}
RUN mkdir ${CHECKER_DATA_DIRECTORY}/../tests
COPY ./tests ${CHECKER_DATA_DIRECTORY}/../tests
