// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "ipc.h"
#include "server.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

static int lib_prehooks(struct lib *lib)
{
	if (!lib) return -1;
	lib->handle = dlopen(lib->libname, RTLD_LAZY);

	if (!lib->handle) {
		fprintf(stderr, "dleopen err: %s\n", dlerror());
		return -1;
	}

	return 0;
}

static int lib_load(struct lib *lib)
{
	if (!lib) return -1;

	const char *func_to_load = lib->funcname ? lib->funcname : "run";
	*(void **)(&lib->run) = dlsym(lib->handle, func_to_load);
	char *error = dlerror();

	if (error != NULL) {
		fprintf(stderr, "dlsym error (funcname: %s): %s\n", lib->funcname, error);
        dlclose(lib->handle);
        return -1;
	}

	if (lib->filename != NULL) {
        lib->p_run = (lambda_param_func_t)dlsym(lib->handle, func_to_load);
        error = dlerror();
        if (error != NULL) {
            fprintf(stderr, "dlsym error (filename: %s): %s\n", lib->filename, error);
            dlclose(lib->handle);
            return -1;
        }
    }

	char *temp = strdup(OUTPUT_TEMPLATE);
    if (!temp) {
        perror("Error: strdup could not be executed.\n");
        dlclose(lib->handle);
        return -1;
    }

    int fd = mkstemp(temp);
    if (fd == -1) {
        perror("Error: mkstemp could not be executed.\n");
        free(temp);
        dlclose(lib->handle);
        return -1;
    }

	lib->outputfile = temp;
    close(fd);
	return 0;
}

static int lib_execute(struct lib *lib)
{
	printf("AICI");
	if (!lib || !lib->handle) {
        fprintf(stderr, "library not loaded.\n");
        return -1;
    }

    if (!lib->run && !lib->p_run) {
        fprintf(stderr, "no function loaded.\n");
        return -1;
    }
	
	int fd = open(lib->outputfile, O_WRONLY | O_TRUNC);
    if (fd == -1) {
        perror("Error: open could not be executed.\n");
        return -1;
    }

	int saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout == -1) {
        perror("Error: dup could not be executed.\n");
        close(fd);
        return -1;
    }

	if (dup2(fd, STDOUT_FILENO) == -1) {
        perror("Error: dup2 could not be executed.\n");
        close(fd);
        close(saved_stdout);
        return -1;
    }

	if (lib->filename && lib->p_run) {
        lib->p_run(lib->filename);
    } else if (lib->run) {
        lib->run();
    }

	fflush(stdout);

    if (dup2(saved_stdout, STDOUT_FILENO) == -1) {
        perror("Error: dup2 could not be executed.\n");
    }

    close(saved_stdout);
    close(fd);
	return 0;
}

static int lib_close(struct lib *lib)
{
	if (!lib) return -1;
	
	if (lib->handle) {
		dlclose(lib->handle);
		lib->handle = NULL;
	}

	lib->run = NULL;
	lib->p_run = NULL;

	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	if (!lib || !lib->outputfile) {
        fprintf(stderr, "Error: No output file generated.\n");
        return -1;
    }
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;
	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	unlink(SOCKET_NAME);

	int server_socket = guard_let(create_socket(), "error on creating socket");

	struct sockaddr_un server_address;
	server_address.sun_family = AF_UNIX;
	snprintf(server_address.sun_path, sizeof(server_address.sun_path), "%s", SOCKET_NAME);
	socklen_t slen = sizeof(server_address);

	guard_let(
		bind(server_socket, (struct sockaddr *)&server_address, slen),
		"bind error"
	);

	printf("Server created\n");
	guard_let(listen(server_socket, MAX_CLIENTS), "listen error");
	printf("Server is listening on socket: %s\n", SOCKET_NAME);
	struct lib lib;
	int ret;

	while (1) {
		int client;
		client = accept(server_socket, NULL, NULL);
		printf("Client %d acepted.\n", client);
		if (client < 0) {
			perror("can't connect to client");
			continue;
		}

		char recv_buffer[BUFSIZE];
		size_t recv_buffer_len = 0;
		memset(recv_buffer, 0, BUFSIZE);
		ssize_t offset = 0;

		//recv_socket(client, recv_buffer + recv_buffer_len, BUFSIZE);
		while((offset = recv_socket(client, recv_buffer, BUFSIZE)) > 0) {
			recv_buffer_len += offset;
			printf("Received %zd bytes from client %d.\n", offset, client);
			if (recv_buffer_len >= BUFSIZE - 1) {
				printf("Buffer full, stopping reception.\n");
				break;
        	}
			printf("Finished receiving data from client %d.\n", client);
			recv_buffer[recv_buffer_len] = '\0';
			printf("Received command: %s\n", recv_buffer);

			char name[BUFSIZE];
			char func[BUFSIZE];
			char params[BUFSIZE];
			memset(name, 0, BUFSIZE);
			memset(func, 0, BUFSIZE);
			memset(params, 0, BUFSIZE);

			parse_command(recv_buffer, name, func, params);
			memset(&lib, 0, sizeof(lib));
			lib.libname = name;
			lib.funcname = func;
			lib.filename = params;
			ret = lib_run(&lib);
			if (ret < 0) {
				fprintf(stderr, "lib_run encountered an error.\n");
			} else {
				send_socket(client, lib.outputfile, strlen(lib.outputfile));
				close(client);
			}
		}
	}
	close_socket(server_socket);
	printf("Connection closed.\n");
}
