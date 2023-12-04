CC	= gcc
CFLAGS	= 
LDFLAGS	= -pthread

.PHONY: all
all: client server

client: TCPClient.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $^
server: TCPServer.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $^