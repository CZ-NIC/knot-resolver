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
#include <assert.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kresconfig.h"

#include <lua.h>
#include <uv.h>
#ifdef HAS_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
#include <libknot/error.h>

#include <contrib/cleanup.h>
#include <contrib/ucw/mempool.h>
#include <contrib/ccan/asprintf/asprintf.h>
#include "lib/defines.h"
#include "lib/resolve.h"
#include "lib/dnssec.h"
#include "daemon/network.h"
#include "daemon/worker.h"
#include "daemon/engine.h"
#include "daemon/tls.h"
#include "lib/dnssec/ta.h"

/* We can fork early on Linux 3.9+ and do SO_REUSEPORT for better performance. */
#if defined(UV_VERSION_HEX) && defined(SO_REUSEPORT) && defined(__linux__)
 #define CAN_FORK_EARLY 1
#endif

/* @internal Array of ip address shorthand. */
typedef array_t(char*) addr_array_t;

struct args {
	int forks;
	addr_array_t addr_set;
	addr_array_t tls_set;
	fd_array_t fd_set;
	fd_array_t tls_fd_set;
	char *keyfile;
	int keyfile_unmanaged;
	const char *config;
	int control_fd;
	const char *rundir;
	bool interactive;
	bool quiet;
	bool tty_binary_output;
};

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
 * - This is just basic read-eval-print; libedit is supported through kresc;
 * - stream->data contains program arguments (struct args);
 */
static void tty_process_input(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	char *cmd = buf ? buf->base : NULL; /* To be free()d on return. */

	/* Set output streams */
	FILE *out = stdout;
	uv_os_fd_t stream_fd = 0;
	struct args *args = stream->data;
	if (uv_fileno((uv_handle_t *)stream, &stream_fd)) {
		uv_close((uv_handle_t *)stream, (uv_close_cb) free);
		free(cmd);
		return;
	}
	if (stream_fd != STDIN_FILENO) {
		if (nread < 0) { /* Close if disconnected */
			uv_close((uv_handle_t *)stream, (uv_close_cb) free);
		}
		if (nread <= 0) {
			free(cmd);
			return;
		}
		uv_os_fd_t dup_fd = dup(stream_fd);
		if (dup_fd >= 0) {
			out = fdopen(dup_fd, "w");
		}
	}

	/* Execute */
	if (stream && cmd && nread > 0) {
		/* Ensure cmd is 0-terminated */
		if (cmd[nread - 1] == '\n') {
			cmd[nread - 1] = '\0';
		} else {
			if (nread >= buf->len) { /* only equality should be possible */
				char *newbuf = realloc(cmd, nread + 1);
				if (!newbuf)
					goto finish;
				cmd = newbuf;
			}
			cmd[nread] = '\0';
		}

		/* Pseudo-command for switching to "binary output"; */
		if (strcmp(cmd, "__binary") == 0) {
			args->tty_binary_output = true;
			goto finish;
		}

		struct engine *engine = ((struct worker_ctx *)stream->loop->data)->engine;
		lua_State *L = engine->L;
		int ret = engine_cmd(L, cmd, false);
		const char *message = "";
		if (lua_gettop(L) > 0) {
			message = lua_tostring(L, -1);
		}

		/* Simpler output in binary mode */
		if (args->tty_binary_output) {
			size_t len_s = strlen(message);
			if (len_s > UINT32_MAX)
				goto finish;
			uint32_t len_n = htonl(len_s);
			fwrite(&len_n, sizeof(len_n), 1, out);
			fwrite(message, len_s, 1, out);
			lua_settop(L, 0);
			goto finish;
		}

		/* Log to remote socket if connected */
		const char *delim = args->quiet ? "" : "> ";
		if (stream_fd != STDIN_FILENO) {
			fprintf(stdout, "%s\n", cmd); /* Duplicate command to logs */
			if (message)
				fprintf(out, "%s", message); /* Duplicate output to sender */
			if (message || !args->quiet)
				fprintf(out, "\n");
			fprintf(out, "%s", delim);
		}
		/* Log to standard streams */
		FILE *fp_out = ret ? stderr : stdout;
		if (message)
			fprintf(fp_out, "%s", message);
		if (message || !args->quiet)
			fprintf(fp_out, "\n");
		fprintf(fp_out, "%s", delim);
		lua_settop(L, 0);
	}
finish:
	free(cmd);
	/* Close if redirected */
	if (stream_fd != STDIN_FILENO) {
		fclose(out);
	}
}

static void tty_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
	buf->len = suggested;
	buf->base = malloc(suggested);
}

static void tty_accept(uv_stream_t *master, int status)
{
	uv_tcp_t *client = malloc(sizeof(*client));
	struct args *args = master->data;
	if (client) {
		 uv_tcp_init(master->loop, client);
		 if (uv_accept(master, (uv_stream_t *)client) != 0) {
			free(client);
			return;
		 }
		 client->data = args;
		 uv_read_start((uv_stream_t *)client, tty_alloc, tty_process_input);
		 /* Write command line */
		 if (!args->quiet) {
		 	uv_buf_t buf = { "> ", 2 };
		 	uv_try_write((uv_stream_t *)client, &buf, 1);
		 }
	}
}

/* @internal AF_LOCAL reads may still be interrupted, loop it. */
static bool ipc_readall(int fd, char *dst, size_t len)
{
	while (len > 0) {
		int rb = read(fd, dst, len);
		if (rb > 0) {
			dst += rb;
			len -= rb;
		} else if (errno != EAGAIN && errno != EINTR) {
			return false;
		}
	}
	return true;
}

static void ipc_activity(uv_poll_t *handle, int status, int events)
{
	struct engine *engine = handle->data;
	if (status != 0) {
		kr_log_error("[system] ipc: %s\n", uv_strerror(status));
		return;
	}
	/* Get file descriptor from handle */
	uv_os_fd_t fd = 0;
	(void) uv_fileno((uv_handle_t *)(handle), &fd);
	/* Read expression from IPC pipe */
	uint32_t len = 0;
	auto_free char *rbuf = NULL;
	if (!ipc_readall(fd, (char *)&len, sizeof(len))) {
		goto failure;
	}
	if (len < UINT32_MAX) {
		rbuf = malloc(len + 1);
	} else {
		errno = EINVAL;
	}
	if (!rbuf) {
		goto failure;
	}
	if (!ipc_readall(fd, rbuf, len)) {
		goto failure;
	}
	rbuf[len] = '\0';
	/* Run expression */
	const char *message = "";
	int ret = engine_ipc(engine, rbuf);
	if (ret > 0) {
		message = lua_tostring(engine->L, -1);
	}
	/* Clear the Lua stack */
	lua_settop(engine->L, 0);
	/* Send response back */
	len = strlen(message);
	if (write(fd, &len, sizeof(len)) != sizeof(len) ||
		write(fd, message, len) != len) {
		goto failure;
	}
	return; /* success! */
failure:
	/* Note that if the piped command got read or written partially,
	 * we would get out of sync and only receive rubbish now.
	 * Therefore we prefer to stop IPC, but we try to continue with all else.
	 */
	kr_log_error("[system] stopping ipc because of: %s\n", strerror(errno));
	uv_poll_stop(handle);
	uv_close((uv_handle_t *)handle, (uv_close_cb)free);
}

static bool ipc_watch(uv_loop_t *loop, struct engine *engine, int fd)
{
	uv_poll_t *poller = malloc(sizeof(*poller));
	if (!poller) {
		return false;
	}
	int ret = uv_poll_init(loop, poller, fd);
	if (ret != 0) {
		free(poller);
		return false;
	}
	poller->data = engine;
	ret = uv_poll_start(poller, UV_READABLE, ipc_activity);
	if (ret != 0) {
		free(poller);
		return false;
	}
	/* libuv sets O_NONBLOCK whether we want it or not */
	(void) fcntl(fd, F_SETFD, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
	return true;
}

static void signal_handler(uv_signal_t *handle, int signum)
{
	uv_stop(uv_default_loop());
	uv_signal_stop(handle);
}

/** SIGBUS -> attempt to remove the overflowing cache file and abort. */
static void sigbus_handler(int sig, siginfo_t *siginfo, void *ptr)
{
	/* We can't safely assume that printf-like functions work, but write() is OK.
	 * See POSIX for the safe functions, e.g. 2017 version just above this link:
	 * http://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_04_04
	 */
	#define WRITE_ERR(err_charray) \
		(void)write(STDERR_FILENO, err_charray, sizeof(err_charray))
	/* Unfortunately, void-cast on the write isn't enough to avoid the warning. */
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wunused-result"
	const char msg_typical[] =
		"\nSIGBUS received; this is most likely due to filling up the filesystem where cache resides.\n",
		msg_unknown[] = "\nSIGBUS received, cause unknown.\n",
		msg_deleted[] = "Cache file deleted.\n",
		msg_del_fail[] = "Cache file deletion failed.\n",
		msg_final[] = "kresd can not recover reliably by itself, exiting.\n";
	if (siginfo->si_code != BUS_ADRERR) {
		WRITE_ERR(msg_unknown);
		goto end;
	}
	WRITE_ERR(msg_typical);
	if (!kr_cache_emergency_file_to_remove) goto end;
	if (unlink(kr_cache_emergency_file_to_remove)) {
		WRITE_ERR(msg_del_fail);
	} else {
		WRITE_ERR(msg_deleted);
	}
end:
	WRITE_ERR(msg_final);
	_exit(128 - sig); /*< regular return from OS-raised SIGBUS can't work anyway */
	#undef WRITE_ERR
	#pragma GCC diagnostic pop
}


/*
 * Server operation.
 */

static int fork_workers(fd_array_t *ipc_set, int forks)
{
	/* Fork subprocesses if requested */
	while (--forks > 0) {
		int sv[2] = {-1, -1};
		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) < 0) {
			perror("[system] socketpair");
			return kr_error(errno);
		}
		int pid = fork();
		if (pid < 0) {
			perror("[system] fork");
			return kr_error(errno);
		}

		/* Forked process */
		if (pid == 0) {
			array_clear(*ipc_set);
			array_push(*ipc_set, sv[0]);
			close(sv[1]);
			return forks;
		/* Parent process */
		} else {
			array_push(*ipc_set, sv[1]);
			/* Do not share parent-end with other forks. */
			(void) fcntl(sv[1], F_SETFD, FD_CLOEXEC);
			close(sv[0]);
		}
	}
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
	       " -k, --keyfile=[path]   File with root domain trust anchors (DS or DNSKEY), automatically updated.\n"
	       " -K, --keyfile-ro=[path] File with read-only root domain trust anchors, for use with an external updater.\n"
	       " -f, --forks=N          Start N forks sharing the configuration.\n"
	       " -q, --quiet            No command prompt in interactive mode.\n"
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

/** \return exit code for main()  */
static int run_worker(uv_loop_t *loop, struct engine *engine, fd_array_t *ipc_set, bool leader, struct args *args)
{
	/* Only some kinds of stdin work with uv_pipe_t.
	 * Otherwise we would abort() from libuv e.g. with </dev/null */
	if (args->interactive) switch (uv_guess_handle(0)) {
	case UV_TTY:		/* standard terminal */
		/* TODO: it has worked OK so far, but we'd better use uv_tty_*
		 * for this case instead of uv_pipe_*. */
	case UV_NAMED_PIPE:	/* echo 'quit()' | kresd ... */
		break;
	default:
		kr_log_error(
			"[system] error: standard input is not a terminal or pipe; "
			"use '-f 1' if you want non-interactive mode.  "
			"Commands can be simply added to your configuration file or sent over the tty/$PID control socket.\n"
			);
		return EXIT_FAILURE;
	}

	if (setvbuf(stdout, NULL, _IONBF, 0) || setvbuf(stderr, NULL, _IONBF, 0)) {
		kr_log_error("[system] failed to to set output buffering (ignored): %s\n",
				strerror(errno));
		fflush(stderr);
	}

	/* Control sockets or TTY */
	auto_free char *sock_file = NULL;
	uv_pipe_t pipe;
	uv_pipe_init(loop, &pipe, 0);
	pipe.data = args;
	if (args->interactive) {
		if (!args->quiet)
			printf("[system] interactive mode\n> ");
		uv_pipe_open(&pipe, 0);
		uv_read_start((uv_stream_t*) &pipe, tty_alloc, tty_process_input);
	} else {
		int pipe_ret = -1;
		if (args->control_fd != -1) {
			pipe_ret = uv_pipe_open(&pipe, args->control_fd);
		} else {
			(void) mkdir("tty", S_IRWXU|S_IRWXG);
			sock_file = afmt("tty/%ld", (long)getpid());
			if (sock_file) {
				pipe_ret = uv_pipe_bind(&pipe, sock_file);
			}
		}
		if (!pipe_ret)
			uv_listen((uv_stream_t *) &pipe, 16, tty_accept);
	}
	/* Watch IPC pipes (or just assign them if leading the pgroup). */
	if (!leader) {
		for (size_t i = 0; i < ipc_set->len; ++i) {
			if (!ipc_watch(loop, engine, ipc_set->at[i])) {
				kr_log_error("[system] failed to create poller: %s\n", strerror(errno));
				close(ipc_set->at[i]);
			}
		}
	}
	memcpy(&engine->ipc_set, ipc_set, sizeof(*ipc_set));

	/* Notify supervisor. */
#ifdef HAS_SYSTEMD
	sd_notify(0, "READY=1");
#endif
	/* Run event loop */
	uv_run(loop, UV_RUN_DEFAULT);
	if (sock_file) {
		unlink(sock_file);
	}
	uv_close((uv_handle_t *)&pipe, NULL); /* Seems OK even on the stopped loop. */
	return EXIT_SUCCESS;
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

static int set_keyfile(struct engine *engine, char *keyfile, bool unmanaged)
{
	assert(keyfile != NULL);
	auto_free char *cmd = afmt("trust_anchors.config('%s',%s)",
				   keyfile, unmanaged ? "true" : "nil");
	if (!cmd) {
		kr_log_error("[system] not enough memory\n");
		return kr_error(ENOMEM);
	}
	int lua_ret = engine_cmd(engine->L, cmd, false);
	if (lua_ret != 0) {
		if (lua_gettop(engine->L) > 0) {
			kr_log_error("%s\n", lua_tostring(engine->L, -1));
		} else {
			kr_log_error("[ ta ] keyfile '%s': failed to load (%s)\n",
					keyfile, lua_strerror(lua_ret));
		}
		return lua_ret;
	}

	lua_settop(engine->L, 0);
	return kr_ok();
}


static void args_init(struct args *args)
{
	memset(args, 0, sizeof(struct args));
	args->forks = 1;
	array_init(args->addr_set);
	array_init(args->tls_set);
	array_init(args->fd_set);
	array_init(args->tls_fd_set);
	args->control_fd = -1;
	args->interactive = true;
	args->quiet = false;
}

static long strtol_10(const char *s)
{
	if (!s) abort();
	/* ^^ This shouldn't ever happen.  When getopt_long() returns an option
	 * character that has a mandatory parameter, optarg can't be NULL. */
	return strtol(s, NULL, 10);
}

/** Process arguments into struct args.
 * @return >=0 if main() should be exited immediately.
 */
static int parse_args(int argc, char **argv, struct args *args)
{
	/* Long options. */
	int c = 0, li = 0;
	struct option opts[] = {
		{"addr",       required_argument, 0, 'a'},
		{"tls",        required_argument, 0, 't'},
		{"fd",         required_argument, 0, 'S'},
		{"tlsfd",      required_argument, 0, 'T'},
		{"config",     required_argument, 0, 'c'},
		{"keyfile",    required_argument, 0, 'k'},
		{"keyfile-ro", required_argument, 0, 'K'},
		{"forks",      required_argument, 0, 'f'},
		{"verbose",          no_argument, 0, 'v'},
		{"quiet",            no_argument, 0, 'q'},
		{"version",          no_argument, 0, 'V'},
		{"help",             no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};
	while ((c = getopt_long(argc, argv, "a:t:S:T:c:f:m:K:k:vqVh", opts, &li)) != -1) {
		switch (c)
		{
		case 'a':
			array_push(args->addr_set, optarg);
			break;
		case 't':
			array_push(args->tls_set, optarg);
			break;
		case 'S':
			array_push(args->fd_set, strtol_10(optarg));
			break;
		case 'T':
			array_push(args->tls_fd_set, strtol_10(optarg));
			break;
		case 'c':
			args->config = optarg;
			break;
		case 'f':
			args->interactive = false;
			args->forks = strtol_10(optarg);
			if (args->forks <= 0) {
				kr_log_error("[system] error '-f' requires a positive"
						" number, not '%s'\n", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'K':
			args->keyfile_unmanaged = 1;
		case 'k':
			if (args->keyfile != NULL) {
				kr_log_error("[system] error only one of '--keyfile' and '--keyfile-ro' allowed\n");
				return EXIT_FAILURE;
			}
			args->keyfile = optarg;
			break;
		case 'v':
			kr_verbose_set(true);
#ifdef NOVERBOSELOG
			kr_log_info("--verbose flag has no effect due to compilation with -DNOVERBOSELOG.\n");
#endif
			break;
		case 'q':
			args->quiet = true;
			break;
		case 'V':
			kr_log_info("%s, version %s\n", "Knot Resolver", PACKAGE_VERSION);
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
	if (optind < argc) {
		args->rundir = argv[optind];
	}
	return -1;
}

static int bind_fds(struct network *net, fd_array_t *fd_set, bool tls) {
	int ret = 0;
	for (size_t i = 0; i < fd_set->len; ++i) {
		ret = network_listen_fd(net, fd_set->at[i], tls);
		if (ret != 0) {
			kr_log_error("[system] %slisten on fd=%d %s\n",
				 tls ? "TLS " : "", fd_set->at[i], kr_strerror(ret));
			break;
		}
	}
	return ret;
}

static int bind_sockets(struct network *net, addr_array_t *addr_set, bool tls) {
	uint32_t flags = tls ? NET_TCP|NET_TLS : NET_UDP|NET_TCP;
	for (size_t i = 0; i < addr_set->len; ++i) {
		uint16_t port = tls ? KR_DNS_TLS_PORT : KR_DNS_PORT;
		char addr_str[INET6_ADDRSTRLEN + 1];
		int ret = kr_straddr_split(addr_set->at[i], addr_str, &port);
		if (ret == 0)
			ret = network_listen(net, addr_str, port, flags);
		if (ret != 0) {
			kr_log_error("[system] bind to '%s' %s%s\n",
				addr_set->at[i], tls ? "(TLS) " : "", kr_strerror(ret));
			return ret;
		}
	}
	return kr_ok();
}

int main(int argc, char **argv)
{
	int ret = 0;
	struct args args;
	args_init(&args);
	if ((ret = parse_args(argc, argv, &args)) >= 0) {
		return ret;
	}

#ifdef HAS_SYSTEMD
	/* Accept passed sockets from systemd supervisor. */
	char **socket_names = NULL;
	int sd_nsocks = sd_listen_fds_with_names(0, &socket_names);
	for (int i = 0; i < sd_nsocks; ++i) {
		int fd = SD_LISTEN_FDS_START + i;
		/* when run under systemd supervision, do not use interactive mode */
		args.interactive = false;
		if (args.forks != 1) {
			kr_log_error("[system] when run under systemd-style supervision, "
				     "use single-process only (bad: --forks=%d).\n", args.forks);
			free_sd_socket_names(socket_names, sd_nsocks);
			return EXIT_FAILURE;
		}
		if (!strcasecmp("control",socket_names[i])) {
			args.control_fd = fd;
		} else if (!strcasecmp("tls",socket_names[i])) {
			array_push(args.tls_fd_set, fd);
		} else {
			array_push(args.fd_set, fd);
		}
	}
	free_sd_socket_names(socket_names, sd_nsocks);
#endif

	/* Switch to rundir. */
	if (args.rundir != NULL) {
		/* FIXME: access isn't a good way if we start as root and drop privileges later */
		if (access(args.rundir, W_OK) != 0) {
			kr_log_error("[system] rundir '%s': %s\n", args.rundir, strerror(errno));
			return EXIT_FAILURE;
		}
		ret = chdir(args.rundir);
		if (ret != 0) {
			kr_log_error("[system] rundir '%s': %s\n", args.rundir, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	if (args.config && strcmp(args.config, "-") != 0 && access(args.config, R_OK) != 0) {
		kr_log_error("[system] config '%s': %s\n", args.config, strerror(errno));
		return EXIT_FAILURE;
	}
	if (!args.config && access("config", R_OK) == 0) {
		args.config = "config";
	}

#ifndef CAN_FORK_EARLY
	/* Forking is currently broken with libuv. We need libuv to bind to
	 * sockets etc. before forking, but at the same time can't touch it before
	 * forking otherwise it crashes, so it's a chicken and egg problem.
	 * Disabling until https://github.com/libuv/libuv/pull/846 is done. */
	 if (args.forks > 1 && args.fd_set.len == 0 && args.tls_fd_set.len == 0) {
	 	kr_log_error("[system] forking >1 workers supported only on Linux 3.9+ or with supervisor\n");
	 	return EXIT_FAILURE;
	 }
#endif

	/* Connect forks with local socket */
	fd_array_t ipc_set;
	array_init(ipc_set);
	/* Fork subprocesses if requested */
	int fork_id = fork_workers(&ipc_set, args.forks);
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
	struct worker_ctx *worker = worker_create(&engine, &pool, fork_id, args.forks);
	if (!worker) {
		kr_log_error("[system] not enough memory\n");
		return EXIT_FAILURE;
	}

	uv_loop_t *loop = uv_default_loop();
	worker->loop = loop;
	loop->data = worker;

	/* Catch some signals. */
	uv_signal_t sigint, sigterm;
	if (true) ret = uv_signal_init(loop, &sigint);
	if (!ret) ret = uv_signal_init(loop, &sigterm);
	if (!ret) ret = uv_signal_start(&sigint, signal_handler, SIGINT);
	if (!ret) ret = uv_signal_start(&sigterm, signal_handler, SIGTERM);
	/* Block SIGPIPE; see https://github.com/libuv/libuv/issues/45 */
	if (!ret && signal(SIGPIPE, SIG_IGN) == SIG_ERR) ret = errno;
	if (!ret) {
		/* Catching SIGBUS via uv_signal_* can't work; see:
		 * https://github.com/libuv/libuv/pull/1987 */
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_sigaction = sigbus_handler;
		sa.sa_flags = SA_SIGINFO;
		if (sigaction(SIGBUS, &sa, NULL)) {
			ret = errno;
		}
	}
	if (ret) {
		kr_log_error("[system] failed to set up signal handlers: %s\n",
				strerror(abs(errno)));
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/* Bind to passed fds and sockets*/
	if (bind_fds(&engine.net, &args.fd_set, false) != 0 ||
	    bind_fds(&engine.net, &args.tls_fd_set, true) != 0 ||
	    bind_sockets(&engine.net, &args.addr_set, false) != 0 ||
	    bind_sockets(&engine.net, &args.tls_set, true) != 0
	) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/* Start the scripting engine */
	if (engine_load_sandbox(&engine) != 0) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}
	if (args.config != NULL && strcmp(args.config, "-") != 0) {
		if(engine_loadconf(&engine, args.config) != 0) {
			ret = EXIT_FAILURE;
			goto cleanup;
		}
		lua_settop(engine.L, 0);
	}
	if (args.keyfile != NULL && set_keyfile(&engine, args.keyfile, args.keyfile_unmanaged) != 0) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}
	if (args.config == NULL || strcmp(args.config, "-") !=0) {
		if(engine_load_defaults(&engine) != 0) {
			ret = EXIT_FAILURE;
			goto cleanup;
		}
	}
	if (engine_start(&engine) != 0) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/* Run the event loop */
	ret = run_worker(loop, &engine, &ipc_set, fork_id == 0, &args);

cleanup:/* Cleanup. */
	engine_deinit(&engine);
	worker_reclaim(worker);
	if (loop != NULL) {
		uv_loop_close(loop);
	}
	mp_delete(pool.ctx);
	array_clear(args.addr_set);
	array_clear(args.tls_set);
	kr_crypto_cleanup();
	return ret;
}
