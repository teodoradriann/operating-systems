// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"

int guard_let(int n, char *err)
{
	if (n==-1) {
		perror(err);
		exit(EXIT_FAILURE);
	}
	return n;
}


int create_socket(void)
{
	int server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un *server_address = (sockaddr_un *)malloc(sizeof(sockaddr_un));
	server = server_address;
	server_address->sun_family = AF_UNIX;
	snprintf(server_address->sun_path, sizeof(server_address->sun_path), "%s", SOCKET_NAME);
	socklen_t slen = sizeof(server_address);
	guard_let(
		bind(server_socket, (struct sockaddr *) &server_address, slen),
		"bind error"
	);
	guard_let(listen(server_socket, MAX_CLIENTS), "listen error");
	return server_socket;
}

int connect_socket(int fd)
{
<<<<<<< HEAD
	struct sockaddr_un server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sun_family = AF_UNIX;
	strncpy(server_address.sun_path, SOCKET_NAME, sizeof(server_address.sun_path) - 1);
	return guard_let(
        connect(fd, (struct sockaddr*)&server_address, sizeof(server_address)),
=======
	if (!server) {
        fprintf(stderr, "Error: server address is not initialized.\n");
        exit(EXIT_FAILURE);
    }

    return guard_let(
        connect(fd, (struct sockaddr *)server, sizeof(struct sockaddr_un)),
>>>>>>> origin/main
        "connect error"
    );
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	ssize_t bytes_sent = 0;
	while (bytes_sent < len) {
		ssize_t sent = send(fd, buf + bytes_sent, len - bytes_sent, 0);
		bytes_sent += sent;
	}
	return bytes_sent;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	return guard_let(recv(fd, buf, len, 0), "recv error");
}

void close_socket(int fd)
{
<<<<<<< HEAD
	 guard_let(close(fd), "Error on close.");
=======
	if (server) {
        free(server);
        server = NULL;
    }
	guard_let(close(fd), "can't close the socket");
>>>>>>> origin/main
}
