/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <uv.h>
#include <libknot/internal/sockaddr.h>
#include <ucw/mempool.h>

#include "lib/defines.h"
#include "lib/resolve.h"
#include "daemon/network.h"
#include "daemon/worker.h"
#include "daemon/engine.h"
#include "daemon/bindings.h"
#include "daemon/bindings/kres.h"

static void tty_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	if (stream && buf && nread > 0) {
		/* Trim endln */
		char *cmd = buf->base;
		cmd[nread - 1] = '\0';
		/* Execute */
		engine_cmd((struct engine *)stream->data, cmd);
		free(buf->base);
	}

	printf("> ");
	fflush(stdout);
}

static void tty_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
	buf->len = suggested;
	buf->base = malloc(suggested);
}

void signal_handler(uv_signal_t *handle, int signum)
{
	uv_stop(uv_default_loop());
	uv_signal_stop(handle);
}

static void help(int argc, char *argv[])
{
	printf("Usage: %s [parameters] [rundir]\n", argv[0]);
	printf("\nParameters:\n"
	       " -a, --addr=[addr]   Server address (default: localhost#53).\n"
	       " -v, --version       Print version of the server.\n"
	       " -h, --help          Print help and usage.\n"
	       "Options:\n"
	       " [rundir]            Path to the working directory (default: .)\n");
}

static const char *set_addr(char *addr, int *port)
{
	char *p = strchr(addr, '#');
	if (p) {
		*port = atoi(p + 1);
		*p = '\0';
	}

	return addr;
}

int main(int argc, char **argv)
{
	const char *addr = NULL;
	int port = 53;

	/* Long options. */
	int c = 0, li = 0, ret = 0;
	struct option opts[] = {
		{"addr", required_argument, 0, 'a'},
		{"version",   no_argument,  0, 'v'},
		{"help",      no_argument,  0, 'h'},
		{0, 0, 0, 0}
	};
	while ((c = getopt_long(argc, argv, "a:vh", opts, &li)) != -1) {
		switch (c)
		{
		case 'a':
			addr = set_addr(optarg, &port);
			break;
		case 'v':
			printf("%s, version %s\n", "Knot DNS Resolver", PACKAGE_VERSION);
			return EXIT_SUCCESS;
		case 'h':
		case '?':
			help(argc, argv);
			return EXIT_SUCCESS;
		default:
			help(argc, argv);
			return EXIT_FAILURE;
		}
	}

	/* Switch to rundir. */
	if (optind < argc) {
		const char *rundir = argv[optind];
		if (access(rundir, W_OK) != 0) {
			fprintf(stderr, "[system] rundir '%s': not writeable\n", rundir);
			return EXIT_FAILURE;
		}
		ret = chdir(rundir);
		if (ret != 0) {
			fprintf(stderr, "[system] rundir '%s': %s\n", rundir, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	/* Block signals. */
	uv_loop_t *loop = uv_default_loop();
	uv_signal_t sigint;
	uv_signal_init(loop, &sigint);
	uv_signal_start(&sigint, signal_handler, SIGINT);

	/* Create a server engine. */
	mm_ctx_t pool = {
		.ctx = mp_new (4096),
		.alloc = (mm_alloc_t) mp_alloc
	};
	struct engine engine;
	ret = engine_init(&engine, &pool);
	if (ret != 0) {
		fprintf(stderr, "[system] failed to initialize engine: %s\n", kr_strerror(ret));
		return EXIT_FAILURE;
	}

	/* Load bindings */
	engine_lualib(&engine, "modules", lib_modules);
	engine_lualib(&engine, "net",     lib_net);
	engine_lualib(&engine, "cache",   lib_cache);
	engine_lualib(&engine, "event",   lib_event);
	engine_lualib(&engine, "kres",    lib_kres);

	/* Create main worker. */
	struct worker_ctx *worker = mm_alloc(&pool, sizeof(*worker));
	if(!worker) {
		fprintf(stderr, "[system] not enough memory\n");
		return EXIT_FAILURE;
	}
	memset(worker, 0, sizeof(*worker));
	worker->engine = &engine,
	worker->loop = loop;
	loop->data = worker;
	worker_reserve(worker, MP_FREELIST_SIZE);

	/* Bind to sockets. */
	if (addr != NULL) {
		ret = network_listen(&engine.net, addr, (uint16_t)port, NET_UDP|NET_TCP);
		if (ret != 0) {
			fprintf(stderr, "[system] bind to '%s#%d' %s\n", addr, port, knot_strerror(ret));
			ret = EXIT_FAILURE;
		}
	}

	if (ret == 0) {
		/* Interactive stdin */
		uv_pipe_t pipe;
		if (!feof(stdin)) {
			printf("[system] started in interactive mode, type 'help()'\n");
			uv_pipe_init(loop, &pipe, 0);
			uv_pipe_open(&pipe, 0);
			pipe.data = &engine;
			tty_read(NULL, 0, NULL);
			uv_read_start((uv_stream_t*) &pipe, tty_alloc, tty_read);
		}

		/* Run the event loop. */
		ret = engine_start(&engine);
		if (ret == 0) {
			ret = uv_run(uv_default_loop(), UV_RUN_DEFAULT);
		}
	}

	/* Cleanup. */
	fprintf(stderr, "\n[system] quitting\n");
	engine_deinit(&engine);
	worker_reclaim(worker);
	mp_delete(pool.ctx);

	if (ret != 0) {
		ret = EXIT_FAILURE;
	}
	return ret;
}
