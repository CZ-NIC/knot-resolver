#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <uv.h>

#include <libknot/internal/sockaddr.h>
#include "lib/resolve.h"
#include "worker.h"

void signal_handler(uv_signal_t *handle, int signum)
{
	uv_stop(uv_default_loop());
	uv_signal_stop(handle);
}

static void help(void)
{
	printf("Usage: %sd [parameters]\n",
	       PACKAGE_NAME);
	printf("\nParameters:\n"
	       " -a, --addr=[addr]   Server address (default localhost#53).\n"
	       " -V, --version       Print version of the server.\n"
	       " -h, --help          Print help and usage.\n");
}

static int set_addr(struct sockaddr_storage *ss, char *addr)
{
	char *port = strchr(addr, '#');
	if (port) {
		sockaddr_port_set(ss, atoi(port + 1));
		*port = '\0';
	}
	
	int family = AF_INET;
	if (strchr(addr, ':')) {
		family = AF_INET6;
	}
	
	return sockaddr_set(ss, family, addr, sockaddr_port(ss));
}

int main(int argc, char **argv)
{
	
	struct sockaddr_storage addr;
	sockaddr_set(&addr, AF_INET, "127.0.0.1", 53);

	/* Long options. */
	int c = 0, li = 0, ret = 0;
	struct option opts[] = {
		{"addr", required_argument, 0, 'a'},
		{"version",   no_argument,  0, 'V'},
		{"help",      no_argument,  0, 'h'},
		{0, 0, 0, 0}
	};
	while ((c = getopt_long(argc, argv, "a:Vh", opts, &li)) != -1) {
		switch (c)
		{
		case 'a':
			ret = set_addr(&addr, optarg);
			if (ret != 0) {
				fprintf(stderr, "Address '%s': %s\n", optarg, knot_strerror(ret));
				return EXIT_FAILURE;
			}
			break;
		case 'V':
			printf("%s, version %s\n", "Knot DNS Resolver", PACKAGE_VERSION);
			return EXIT_SUCCESS;
		case 'h':
		case '?':
			help();
			return EXIT_SUCCESS;
		default:
			help();
			return EXIT_FAILURE;
		}
	}

	mm_ctx_t mm;
	mm_ctx_init(&mm);

	uv_loop_t *loop = uv_default_loop();

	/* Block signals. */
	uv_signal_t sigint;
	uv_signal_init(loop, &sigint);
	uv_signal_start(&sigint, signal_handler, SIGINT);

	/* Bind to sockets. */
	char addr_str[SOCKADDR_STRLEN] = {'\0'};
	sockaddr_tostr(&addr, addr_str, sizeof(addr_str));
	uv_udp_t udp_sock;
	memset(&udp_sock, 0, sizeof(uv_udp_t));
	uv_udp_init(loop, &udp_sock);
	ret = uv_udp_bind(&udp_sock, (struct sockaddr *)&addr, 0);
	if (ret == 0) {
		printf("[system] listening on '%s'\n", addr_str);
	} else {
		fprintf(stderr, "[system] failed to bind to '%s'\n", addr_str);
		return EXIT_FAILURE;
	}

	/* Start a worker. */
	struct worker_ctx worker;
	worker_init(&worker, &mm);
	worker_start(&udp_sock, &worker);

	/* Run the event loop. */
	ret = uv_run(loop, UV_RUN_DEFAULT);

	/* Cleanup. */
	worker_stop(&udp_sock);
	worker_deinit(&worker);

	return ret;
}
