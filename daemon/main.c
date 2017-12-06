/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <uv.h>
#include <assert.h>
#include <contrib/cleanup.h>
#include <contrib/ucw/mempool.h>
#include <contrib/ccan/asprintf/asprintf.h>
#include <libknot/error.h>
#ifdef HAS_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "lib/defines.h"
#include "lib/resolve.h"
#include "lib/dnssec.h"
#include "daemon/network.h"
#include "daemon/worker.h"
#include "daemon/engine.h"
#include "daemon/bindings.h"
#include "daemon/tls.h"

/* We can fork early on Linux 3.9+ and do SO_REUSEPORT for better performance. */
#if defined(UV_VERSION_HEX) && defined(SO_REUSEPORT) && defined(__linux__)
 #define CAN_FORK_EARLY 1
#endif

/*
 * Globals
 */
static bool g_quiet = false;
static bool g_interactive = true;

/* lua_pcall helper function */
static inline char *lua_strerror(int lua_err) {
	switch (lua_err) {
	case LUA_ERRRUN: return "a runtime error";
	case LUA_ERRMEM: return "memory allocation error.";
	case LUA_ERRERR: return "error while running the error handler function.";
	default: return "a unknown error";
	}
}

/**
 * TTY control: process input and free() the buffer.
 *
 * For parameters see http://docs.libuv.org/en/v1.x/stream.html#c.uv_read_cb
 *
 * - This is just basic read-eval-print; libedit is supported through krsec;
 */
static void tty_process_input(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	auto_free char *cmd = buf ? buf->base : NULL; /* To be free()d on return. */

	/* Execute */
	if (stream && cmd && nread > 0) {
		/* Ensure cmd is 0-terminated */
		if (cmd[nread - 1] == '\n') {
			cmd[nread - 1] = '\0';
		} else {
			if (nread >= buf->len) { /* only equality should be possible */
				char *newbuf = realloc(cmd, nread + 1);
				if (!newbuf)
					return;
				cmd = newbuf;
			}
			cmd[nread] = '\0';
		}

		struct engine *engine = ((struct worker_ctx *)stream->loop->data)->engine;
		lua_State *L = engine->L;
		int ret = engine_cmd(L, cmd, false);
		const char *message = "";
		if (lua_gettop(L) > 0) {
			message = lua_tostring(L, -1);
		}
		/* Log to standard streams */
		const char *delim = g_quiet ? "" : "> ";
		FILE *fp_out = ret ? stderr : stdout;
		if (message)
			fprintf(fp_out, "%s", message);
		if (message || !g_quiet)
			fprintf(fp_out, "\n");
		fprintf(fp_out, "%s", delim);
		fflush(fp_out);
		lua_settop(L, 0);
	}
}

static void tty_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
	buf->len = suggested;
	buf->base = malloc(suggested);
}

static void signal_handler(uv_signal_t *handle, int signum)
{
	uv_stop(uv_default_loop());
	uv_signal_stop(handle);
}

/** Split away port from the address. */
static const char *set_addr(char *addr, int *port)
{
	char *p = strchr(addr, '@');
	if (!p) {
		p = strchr(addr, '#');
	}
	if (p) {
		*port = atoi(p + 1);
		*p = '\0';
	}

	return addr;
}

/*
 * Server operation.
 */

static int fork_workers(int forks)
{
	/* Fork subprocesses if requested */
	for (int id = 1; id < forks; ++id) {
		int pid = fork();
		if (pid < 0) {
			perror("[system] fork");
			return kr_error(errno);
		}

		/* Forked process */
		if (pid == 0) {
			return id;
		}
	}

	/* Parent process */
	return 0;
}

static void help(int argc, char *argv[])
{
	printf("Usage: %s [parameters] [rundir]\n", argv[0]);
	printf("\nParameters:\n"
	       " -a, --addr=[addr]      Server address (default: localhost@53).\n"
	       " -t, --tls=[addr]       Server address for TLS (default: off).\n"
	       " -S, --fd=[fd]          Listen on given fd (handed out by supervisor).\n"
	       " -T, --tlsfd=[fd]       Listen using TLS on given fd (handed out by supervisor).\n"
	       " -c, --config=[path]    Config file path (relative to [rundir]) (default: config).\n"
	       " -k, --keyfile=[path]   File containing trust anchors (DS or DNSKEY).\n"
	       " -m, --moduledir=[path] Override the default module path (" MODULEDIR ").\n"
	       " -f, --forks=N          Start N forks sharing the configuration.\n"
	       " -q, --quiet            Quiet output, no prompt in interactive mode.\n"
	       " -v, --verbose          Run in verbose mode."
#ifdef NOVERBOSELOG
	           " (Recompile without -DNOVERBOSELOG to activate.)"
#endif
	           "\n"
	       " -V, --version        Print version of the server.\n"
	       " -h, --help           Print help and usage.\n"
	       "Options:\n"
	       " [rundir]             Path to the working directory (default: .)\n");
}

static int run_worker(uv_loop_t *loop, struct engine *engine)
{
	/* Control sockets or TTY */
	if (g_interactive) {
		if (!g_quiet)
			printf("[system] interactive mode\n> ");
		fflush(stdout);

		uv_pipe_t pipe;
		uv_pipe_init(loop, &pipe, 0);
		pipe.data = 0;
		uv_pipe_open(&pipe, 0);
		uv_read_start((uv_stream_t*) &pipe, tty_alloc, tty_process_input);
	}

	/* Notify supervisor. */
#ifdef HAS_SYSTEMD
	sd_notify(0, "READY=1");
#endif

	/* Run event loop */
	uv_run(loop, UV_RUN_DEFAULT);
	return kr_ok();
}

#ifdef HAS_SYSTEMD
static void free_sd_socket_names(char **socket_names, int count)
{
	for (int i = 0; i < count; i++) {
		free(socket_names[i]);
	}
	free(socket_names);
}
#endif

int main(int argc, char **argv)
{
	int forks = 1;
	array_t(char*) addr_set;
	array_t(char*) tls_set;
	array_init(addr_set);
	array_init(tls_set);
	array_t(int) fd_set;
	array_init(fd_set);
	array_t(int) tls_fd_set;
	array_init(tls_fd_set);
	char *keyfile = NULL;
	char *moduledir = MODULEDIR;
	const char *config = NULL;
	int control_fd = -1;
	uv_loop_t *loop = NULL;

	/* Long options. */
	int c = 0, li = 0, ret = 0;
	struct option opts[] = {
		{"addr", required_argument,   0, 'a'},
		{"tls",  required_argument,   0, 't'},
		{"fd",   required_argument,   0, 'S'},
		{"tlsfd", required_argument,  0, 'T'},
		{"config", required_argument, 0, 'c'},
		{"keyfile",required_argument, 0, 'k'},
		{"forks",required_argument,   0, 'f'},
		{"moduledir", required_argument, 0, 'm'},
		{"verbose",    no_argument,   0, 'v'},
		{"quiet",      no_argument,   0, 'q'},
		{"version",   no_argument,    0, 'V'},
		{"help",      no_argument,    0, 'h'},
		{0, 0, 0, 0}
	};
	while ((c = getopt_long(argc, argv, "a:t:S:T:c:f:m:k:vqVh", opts, &li)) != -1) {
		switch (c)
		{
		case 'a':
			array_push(addr_set, optarg);
			break;
		case 't':
			array_push(tls_set, optarg);
			break;
		case 'S':
			array_push(fd_set,  atoi(optarg));
			break;
		case 'T':
			array_push(tls_fd_set,  atoi(optarg));
			break;
		case 'c':
			config = optarg;
			break;
		case 'f':
			g_interactive = false;
			forks = atoi(optarg);
			if (forks <= 0) {
				kr_log_error("[system] error '-f' requires a positive"
						" number, not '%s'\n", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'k':
			keyfile = optarg;
			break;
		case 'm':
			moduledir = optarg;
			break;
		case 'v':
			kr_verbose_set(true);
#ifdef NOVERBOSELOG
			kr_log_info("--verbose flag has no effect due to compilation with -DNOVERBOSELOG.\n");
#endif
			break;
		case 'q':
			g_quiet = true;
			break;
		case 'V':
			kr_log_info("%s, version %s\n", "Knot DNS Resolver", PACKAGE_VERSION);
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

#ifdef HAS_SYSTEMD
	/* Accept passed sockets from systemd supervisor. */
	char **socket_names = NULL;
	int sd_nsocks = sd_listen_fds_with_names(0, &socket_names);
	for (int i = 0; i < sd_nsocks; ++i) {
		int fd = SD_LISTEN_FDS_START + i;
		/* when run under systemd supervision, do not use interactive mode */
		g_interactive = false;
		if (forks != 1) {
			kr_log_error("[system] when run under systemd-style supervision, "
				     "use single-process only (bad: --fork=%d).\n", forks);
			free_sd_socket_names(socket_names, sd_nsocks);
			return EXIT_FAILURE;
		}
		if (!strcasecmp("control",socket_names[i])) {
			control_fd = fd;
		} else if (!strcasecmp("tls",socket_names[i])) {
			array_push(tls_fd_set, fd);
		} else {
			array_push(fd_set, fd);
		}
	}
	free_sd_socket_names(socket_names, sd_nsocks);
#endif

	/* Switch to rundir. */
	if (optind < argc) {
		const char *rundir = argv[optind];
		/* FIXME: access isn't a good way if we start as root and drop privileges later */
		if (access(rundir, W_OK) != 0) {
			kr_log_error("[system] rundir '%s': %s\n", rundir, strerror(errno));
			return EXIT_FAILURE;
		}
		ret = chdir(rundir);
		if (ret != 0) {
			kr_log_error("[system] rundir '%s': %s\n", rundir, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	if (config && strcmp(config, "-") != 0 && access(config, R_OK) != 0) {
		kr_log_error("[system] config '%s': %s\n", config, strerror(errno));
		return EXIT_FAILURE;
	}
	if (!config && access("config", R_OK) == 0) {
		config = "config";
	}

	/* Create control socket directory if not running in managed mode */
	auto_free char *sock_file = NULL;
	if (control_fd < 0) {
		(void) mkdir(CONTROLDIR, S_IRWXU|S_IRWXG);
		sock_file = afmt(CONTROLDIR "/%ld", getpid());
	}

	/* Clear stale control sockets from control directory */
	DIR *dir = opendir(CONTROLDIR);
	if (dir != NULL) {
		struct dirent *result = NULL;
		while ((result = readdir(dir)) != NULL) {
			/* Select only UNIX sockets (if supported by the FS) */
			if (result->d_type != DT_SOCK && result->d_type != DT_UNKNOWN) {
				continue;
			}
			/* Remove stale sockets (without live PID) */
			auto_free char *stale_socket = afmt(CONTROLDIR "/%s", result->d_name);
			if (stale_socket) {
				long pid = atol(result->d_name);
				if (pid > 0 && getpgid(pid) < 0) {
					kr_log_info("[system] clearing stale control socket '%s'\n", stale_socket);
					unlink(stale_socket);	
				}
			}
		}
		closedir(dir);
	}

#ifndef CAN_FORK_EARLY
	/* Forking is currently broken with libuv. We need libuv to bind to
	 * sockets etc. before forking, but at the same time can't touch it before
	 * forking otherwise it crashes, so it's a chicken and egg problem.
	 * Disabling until https://github.com/libuv/libuv/pull/846 is done. */
	 if (forks > 1 && fd_set.len == 0 && tls_fd_set.len == 0) {
	 	kr_log_error("[system] forking >1 workers supported only on Linux 3.9+ or with supervisor\n");
	 	return EXIT_FAILURE;
	 }
#endif

	/* Fork subprocesses if requested */
	int fork_id = fork_workers(forks);
	if (fork_id < 0) {
		return EXIT_FAILURE;
	}

	kr_crypto_init();

	/* Create a server engine. */
	knot_mm_t pool = {
		.ctx = mp_new (4096),
		.alloc = (knot_mm_alloc_t) mp_alloc
	};
	struct engine engine;
	ret = engine_init(&engine, &pool);
	if (ret != 0) {
		kr_log_error("[system] failed to initialize engine: %s\n", kr_strerror(ret));
		return EXIT_FAILURE;
	}

	/* Create worker */
	struct worker_ctx *worker = worker_create(&engine, &pool, fork_id, forks, control_fd);
	if (!worker) {
		kr_log_error("[system] not enough memory\n");
		return EXIT_FAILURE;
	}
	/* Bind to passed fds and run */
	for (size_t i = 0; i < fd_set.len; ++i) {
		ret = network_listen_fd(&engine.net, fd_set.at[i], false);
		if (ret != 0) {
			kr_log_error("[system] listen on fd=%d %s\n", fd_set.at[i], kr_strerror(ret));
			ret = EXIT_FAILURE;
			break;
		}
	}
	/* Do the same for TLS */
	for (size_t i = 0; i < tls_fd_set.len; ++i) {
		ret = network_listen_fd(&engine.net, tls_fd_set.at[i], true);
		if (ret != 0) {
			kr_log_error("[system] TLS listen on fd=%d %s\n", tls_fd_set.at[i], kr_strerror(ret));
			ret = EXIT_FAILURE;
			break;
		}
	}
	/* Bind to sockets and run */
	if (ret == 0) {
		for (size_t i = 0; i < addr_set.len; ++i) {
			int port = 53;
			const char *addr = set_addr(addr_set.at[i], &port);
			ret = network_listen(&engine.net, addr, (uint16_t)port, NET_UDP|NET_TCP);
			if (ret != 0) {
				kr_log_error("[system] bind to '%s@%d' %s\n", addr, port, kr_strerror(ret));
				ret = EXIT_FAILURE;
				break;
			}
		}
	}
	/* Bind to TLS sockets */
	if (ret == 0) {
		for (size_t i = 0; i < tls_set.len; ++i) {
			int port = KR_DNS_TLS_PORT;
			const char *addr = set_addr(tls_set.at[i], &port);
			ret = network_listen(&engine.net, addr, (uint16_t)port, NET_TCP|NET_TLS);
			if (ret != 0) {
				kr_log_error("[system] bind to '%s@%d' (TLS) %s\n", addr, port, kr_strerror(ret));
				ret = EXIT_FAILURE;
				break;
			}
		}
	}

	/* Workaround for https://github.com/libuv/libuv/issues/45
	 * (Write after ECONNRESET crash.) */
	if (ret == 0 && signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		kr_log_error("[system] can't block SIGPIPE signal: %s\n",
				strerror(errno));
		ret = EXIT_FAILURE;
	}

	if (ret != 0) {
		goto cleanup;
	}

	engine_set_moduledir(&engine, moduledir);

	/* Block signals. */
	loop = uv_default_loop();
	uv_signal_t sigint, sigterm;
	uv_signal_init(loop, &sigint);
	uv_signal_init(loop, &sigterm);
	uv_signal_start(&sigint, signal_handler, SIGINT);
	uv_signal_start(&sigterm, signal_handler, SIGTERM);
	/* Start the scripting engine */
	worker->loop = loop;
	loop->data = worker;

	ret = engine_start(&engine, config);
	if (ret != 0) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	if (keyfile) {
		auto_free char *dirname_storage = strdup(keyfile);
		if (!dirname_storage) {
			kr_log_error("[system] not enough memory: %s\n",
				     strerror(errno));
			ret = EXIT_FAILURE;
			goto cleanup;
		}
		auto_free char *basename_storage = strdup(keyfile);
		if (!basename_storage) {
			kr_log_error("[system] not enough memory: %s\n",
				     strerror(errno));
			ret = EXIT_FAILURE;
			goto cleanup;
		}

		/* Resolve absolute path to the keyfile directory */
		auto_free char *keyfile_dir = malloc(PATH_MAX);
		if (realpath(dirname(dirname_storage), keyfile_dir) == NULL) {
			kr_log_error("[ ta ]: keyfile '%s' directory: %s\n",
				     keyfile, strerror(errno));
			ret = EXIT_FAILURE;
			goto cleanup;
		}

		char *_filename = basename(basename_storage);
		int dirlen = strlen(keyfile_dir);
		int namelen = strlen(_filename);
		if (dirlen + 1 + namelen >= PATH_MAX) {
			kr_log_error("[ ta ]: keyfile '%s' PATH_MAX exceeded\n",
				     keyfile);
			ret = EXIT_FAILURE;
			goto cleanup;
		}
		keyfile_dir[dirlen++] = '/';
		keyfile_dir[dirlen] = '\0';

		auto_free char *keyfile_path = malloc(dirlen + namelen + 1);
		memcpy(keyfile_path, keyfile_dir, dirlen);
		memcpy(keyfile_path + dirlen, _filename, namelen + 1);

		int unmanaged = 0;

		/* Note: config has been executed, so access() is OK,
		 * as we've dropped privileges already if configured. */
		if (access(keyfile_path, F_OK) != 0) {
			kr_log_info("[ ta ] keyfile '%s': doesn't exist, bootstrapping\n", keyfile_path);
			if (access(keyfile_dir, W_OK) != 0) {
				kr_log_error("[ ta ] keyfile '%s': write access to '%s' needed\n", keyfile_path, keyfile_dir);
				ret = EXIT_FAILURE;
				goto cleanup;
			}
		} else if (access(keyfile_path, R_OK) == 0) {
			if ((access(keyfile_path, W_OK) != 0) || (access(keyfile_dir, W_OK) != 0)) {
				kr_log_error("[ ta ] keyfile '%s': not writeable, starting in unmanaged mode\n", keyfile_path);
				unmanaged = 1;
			}
		} else {
			kr_log_error("[ ta ] keyfile '%s': %s\n", keyfile_path, strerror(errno));
			ret = EXIT_FAILURE;
			goto cleanup;
		}

		auto_free char *cmd = afmt("trust_anchors.config('%s',%s)", keyfile_path, unmanaged?"true":"nil");
		if (!cmd) {
			kr_log_error("[system] not enough memory\n");
			ret =  EXIT_FAILURE;
			goto cleanup;
		}
		int lua_ret = engine_cmd(engine.L, cmd, false);
		if (lua_ret != 0) {
			if (lua_gettop(engine.L) > 0) {
				kr_log_error("%s", lua_tostring(engine.L, -1));
			} else {
				kr_log_error("[ ta ] keyfile '%s': failed to load (%s)\n",
						keyfile_path, lua_strerror(lua_ret));
			}
			ret = EXIT_FAILURE;
			goto cleanup;
		}
		lua_settop(engine.L, 0);
	}

	/* Run the event loop */
	ret = run_worker(loop, &engine);
	if (ret != 0) {
		perror("[system] worker failed");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

cleanup:/* Cleanup. */
	engine_deinit(&engine);
	worker_reclaim(worker);
	if (loop != NULL) {
		uv_loop_close(loop);	
	}
	mp_delete(pool.ctx);
	array_clear(addr_set);
	array_clear(tls_set);
	kr_crypto_cleanup();
	if (sock_file) {
		unlink(sock_file);
	}
	return ret;
}
