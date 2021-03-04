/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "kresconfig.h"

#include "contrib/ccan/asprintf/asprintf.h"
#include "contrib/cleanup.h"
#include "contrib/ucw/mempool.h"
#include "daemon/engine.h"
#include "daemon/io.h"
#include "daemon/network.h"
#include "daemon/tls.h"
#include "daemon/udp_queue.h"
#include "daemon/worker.h"
#include "lib/defines.h"
#include "lib/dnssec.h"
#include "lib/dnssec/ta.h"
#include "lib/resolve.h"

#include <arpa/inet.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#if ENABLE_CAP_NG
#include <cap-ng.h>
#endif

#include <lua.h>
#include <uv.h>
#if ENABLE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif
#include <libknot/error.h>


struct args the_args_value;  /** Static allocation for the_args singleton. */

static void signal_handler(uv_signal_t *handle, int signum)
{
	switch (signum) {
	case SIGINT:  /* Fallthrough. */
	case SIGTERM:
		uv_stop(uv_default_loop());
		uv_signal_stop(handle);
		break;
	case SIGCHLD:
		/* Wait for all dead processes. */
		while (waitpid(-1, NULL, WNOHANG) > 0);
		break;
	default:
		kr_log_error("unhandled signal: %d\n", signum);
		break;
	}
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

static int fork_workers(int forks)
{
	/* Fork subprocesses if requested */
	while (--forks > 0) {
		int pid = fork();
		if (pid < 0) {
			perror("[system] fork");
			return kr_error(errno);
		}

		/* Forked process */
		if (pid == 0) {
			return forks;
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
	       " -S, --fd=[fd:kind]     Listen on given fd (handed out by supervisor, :kind is optional).\n"
	       " -c, --config=[path]    Config file path (relative to [rundir]) (default: config).\n"
	       " -n, --noninteractive   Don't start the read-eval-print loop for stdin+stdout.\n"
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
static int run_worker(uv_loop_t *loop, struct engine *engine, bool leader, struct args *args)
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
			"use '-n' if you want non-interactive mode.  "
			"Commands can be simply added to your configuration file or sent over the control socket.\n"
			);
		return EXIT_FAILURE;
	}

	/* Control sockets or TTY */
	uv_pipe_t *pipe = malloc(sizeof(*pipe));
	uv_pipe_init(loop, pipe, 0);
	if (args->interactive) {
		if (!args->quiet)
			printf("[system] interactive mode\n> ");
		pipe->data = io_tty_alloc_data();
		uv_pipe_open(pipe, 0);
		uv_read_start((uv_stream_t*)pipe, io_tty_alloc, io_tty_process_input);
	} else if (args->control_fd != -1 && uv_pipe_open(pipe, args->control_fd) == 0) {
		uv_listen((uv_stream_t *)pipe, 16, io_tty_accept);
	}

	/* Notify supervisor. */
#if ENABLE_LIBSYSTEMD
	sd_notify(0, "READY=1");
#endif
	/* Run event loop */
	uv_run(loop, UV_RUN_DEFAULT);
	/* Free pipe's data.  Seems OK even on the stopped loop.
	 * In interactive case it may have been done in callbacks already (single leak). */
	if (!args->interactive) {
		uv_close((uv_handle_t *)pipe, NULL);
		free(pipe);
	}
	return EXIT_SUCCESS;
}

static void args_init(struct args *args)
{
	memset(args, 0, sizeof(struct args));
	/* Zeroed arrays are OK. */
	args->forks = 1;
	args->control_fd = -1;
	args->interactive = true;
	args->quiet = false;
}

/* Free pointed-to resources. */
static void args_deinit(struct args *args)
{
	array_clear(args->addrs);
	array_clear(args->addrs_tls);
	for (int i = 0; i < args->fds.len; ++i)
		free_const(args->fds.at[i].flags.kind);
	array_clear(args->fds);
	array_clear(args->config);
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
		{"config",     required_argument, 0, 'c'},
		{"forks",      required_argument, 0, 'f'},
		{"noninteractive",   no_argument, 0, 'n'},
		{"verbose",          no_argument, 0, 'v'},
		{"quiet",            no_argument, 0, 'q'},
		{"version",          no_argument, 0, 'V'},
		{"help",             no_argument, 0, 'h'},
		{"fd",         required_argument, 0, 'S'},
		{0, 0, 0, 0}
	};
	while ((c = getopt_long(argc, argv, "a:t:c:f:nvqVhS:", opts, &li)) != -1) {
		switch (c)
		{
		case 'a':
			kr_require(optarg);
			array_push(args->addrs, optarg);
			break;
		case 't':
			kr_require(optarg);
			array_push(args->addrs_tls, optarg);
			break;
		case 'c':
			kr_require(optarg);
			array_push(args->config, optarg);
			break;
		case 'f':
			kr_require(optarg);
			args->forks = strtol(optarg, NULL, 10);
			if (args->forks == 1) {
				kr_log_deprecate("use --noninteractive instead of --forks=1\n");
			} else {
				kr_log_deprecate("support for running multiple --forks will be removed\n");
			}
			if (args->forks <= 0) {
				kr_log_error("[system] error '-f' requires a positive"
						" number, not '%s'\n", optarg);
				return EXIT_FAILURE;
			}
			/* fall through */
		case 'n':
			args->interactive = false;
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
		case 'S':
			kr_require(optarg);
			flagged_fd_t ffd = { 0 };
			char *endptr;
			ffd.fd = strtol(optarg, &endptr, 10);
			if (endptr != optarg && endptr[0] == '\0') {
				/* Plain DNS */
				ffd.flags.tls = false;
			} else if (endptr[0] == ':' && strcasecmp(endptr + 1, "tls") == 0) {
				/* DoT */
				ffd.flags.tls = true;
				/* We know what .sock_type should be but it wouldn't help. */
			} else if (endptr[0] == ':' && endptr[1] != '\0') {
				/* Some other kind; no checks here. */
				ffd.flags.kind = strdup(endptr + 1);
			} else {
				kr_log_error("[system] incorrect value passed to '-S/--fd': %s\n",
						optarg);
				return EXIT_FAILURE;
			}
			array_push(args->fds, ffd);
			break;
		}
	}
	if (optind < argc) {
		args->rundir = argv[optind];
	}
	return -1;
}

/** Just convert addresses to file-descriptors; clear *addrs on success.
 * @note AF_UNIX is supported (starting with '/').
 * @return zero or exit code for main()
 */
static int bind_sockets(addr_array_t *addrs, bool tls, flagged_fd_array_t *fds)
{
	bool has_error = false;
	for (size_t i = 0; i < addrs->len; ++i) {
		/* Get port and separate address string. */
		uint16_t port = tls ? KR_DNS_TLS_PORT : KR_DNS_PORT;
		char addr_buf[INET6_ADDRSTRLEN + 1];
		int ret;
		const char *addr_str;
		const int family = kr_straddr_family(addrs->at[i]);
		if (family == AF_UNIX) {
			ret = 0;
			addr_str = addrs->at[i];
		} else { /* internet socket (or garbage) */
			ret = kr_straddr_split(addrs->at[i], addr_buf, &port);
			addr_str = addr_buf;
		}
		/* Get sockaddr. */
		struct sockaddr *sa = NULL;
		if (ret == 0) {
			sa = kr_straddr_socket(addr_str, port, NULL);
			if (!sa) ret = kr_error(EINVAL); /* could be ENOMEM but unlikely */
		}
		flagged_fd_t ffd = { .flags = { .tls = tls } };
		if (ret == 0 && !tls && family != AF_UNIX) {
			/* AF_UNIX can do SOCK_DGRAM, but let's not support that *here*. */
			ffd.fd = io_bind(sa, SOCK_DGRAM, NULL);
			if (ffd.fd < 0)
				ret = ffd.fd;
			else if (array_push(*fds, ffd) < 0)
				ret = kr_error(ENOMEM);
		}
		if (ret == 0) { /* common for TCP and TLS, including AF_UNIX cases */
			ffd.fd = io_bind(sa, SOCK_STREAM, NULL);
			if (ffd.fd < 0)
				ret = ffd.fd;
			else if (array_push(*fds, ffd) < 0)
				ret = kr_error(ENOMEM);
		}
		free(sa);
		if (ret != 0) {
			kr_log_error("[system] bind to '%s'%s: %s\n",
				addrs->at[i], tls ? " (TLS)" : "", kr_strerror(ret));
			has_error = true;
		}
	}
	array_clear(*addrs);
	return has_error ? EXIT_FAILURE : kr_ok();
}

static int start_listening(struct network *net, flagged_fd_array_t *fds) {
	int some_bad_ret = 0;
	for (size_t i = 0; i < fds->len; ++i) {
		flagged_fd_t *ffd = &fds->at[i];
		int ret = network_listen_fd(net, ffd->fd, ffd->flags);
		if (ret != 0) {
			some_bad_ret = ret;
			/* TODO: try logging address@port.  It's not too important,
			 * because typical problems happen during binding already.
			 * (invalid address, permission denied) */
			kr_log_error("[system] listen on fd=%d: %s\n",
					ffd->fd, kr_strerror(ret));
			/* Continue printing all of these before exiting. */
		} else {
			ffd->flags.kind = NULL; /* ownership transferred */
		}
	}
	return some_bad_ret;
}

/* Drop POSIX 1003.1e capabilities. */
static void drop_capabilities(void)
{
#if ENABLE_CAP_NG
	/* Drop all capabilities when running under non-root user. */
	if (geteuid() == 0) {
		kr_log_verbose("[system] running as root, no capabilities dropped\n");
		return;
	}
	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
		capng_clear(CAPNG_SELECT_BOTH);

		/* Apply. */
		if (capng_apply(CAPNG_SELECT_BOTH) < 0) {
			kr_log_error("[system] failed to set process capabilities: %s\n",
			          strerror(errno));
		} else {
			kr_log_verbose("[system] all capabilities dropped\n");
		}
	} else {
		/* If user() was called, the capabilities were already dropped along with SETPCAP. */
		kr_log_verbose("[system] process not allowed to set capabilities, skipping\n");
	}
#endif /* ENABLE_CAP_NG */
}

int main(int argc, char **argv)
{
	if (setvbuf(stdout, NULL, _IONBF, 0) || setvbuf(stderr, NULL, _IONBF, 0)) {
		kr_log_error("[system] failed to to set output buffering (ignored): %s\n",
				strerror(errno));
		fflush(stderr);
	}
	if (strcmp("linux", OPERATING_SYSTEM) != 0)
		kr_log_info("[warn] Knot Resolver is tested on Linux, other platforms might exhibit bugs.\n"
				"Please report issues to https://gitlab.nic.cz/knot/knot-resolver/issues/\n"
				"Thank you for your time and interest!\n");

	the_args = &the_args_value;
	args_init(the_args);
	int ret = parse_args(argc, argv, the_args);
	if (ret >= 0) goto cleanup_args;

	ret = bind_sockets(&the_args->addrs, false, &the_args->fds);
	if (ret) goto cleanup_args;
	ret = bind_sockets(&the_args->addrs_tls, true, &the_args->fds);
	if (ret) goto cleanup_args;

	/* Switch to rundir. */
	if (the_args->rundir != NULL) {
		/* FIXME: access isn't a good way if we start as root and drop privileges later */
		if (access(the_args->rundir, W_OK) != 0
		    || chdir(the_args->rundir) != 0) {
			kr_log_error("[system] rundir '%s': %s\n",
					the_args->rundir, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	/* Select which config files to load and verify they are read-able. */
	bool load_defaults = true;
	size_t i = 0;
	while (i < the_args->config.len) {
		const char *config = the_args->config.at[i];
		if (strcmp(config, "-") == 0) {
			load_defaults = false;
			array_del(the_args->config, i);
			continue;  /* don't increment i */
		} else if (access(config, R_OK) != 0) {
			char cwd[PATH_MAX];
			get_workdir(cwd, sizeof(cwd));
			kr_log_error("[system] config '%s' (workdir '%s'): %s\n",
				config, cwd, strerror(errno));
			return EXIT_FAILURE;
		}
		i++;
	}
	if (the_args->config.len == 0 && access("config", R_OK) == 0)
		array_push(the_args->config, "config");
	if (load_defaults)
		array_push(the_args->config, LIBDIR "/postconfig.lua");

	/* File-descriptor count limit: soft->hard. */
	struct rlimit rlim;
	ret = getrlimit(RLIMIT_NOFILE, &rlim);
	if (ret == 0 && rlim.rlim_cur != rlim.rlim_max) {
		kr_log_verbose("[system] increasing file-descriptor limit: %ld -> %ld\n",
				(long)rlim.rlim_cur, (long)rlim.rlim_max);
		rlim.rlim_cur = rlim.rlim_max;
		ret = setrlimit(RLIMIT_NOFILE, &rlim);
	}
	if (ret) {
		kr_log_error("[system] failed to get or set file-descriptor limit: %s\n",
				strerror(errno));
	} else if (rlim.rlim_cur < 512*1024) {
		kr_log_info("[system] warning: hard limit for number of file-descriptors is only %ld but recommended value is 524288\n",
				(long)rlim.rlim_cur);
	}

	/* Fork subprocesses if requested */
	int fork_id = fork_workers(the_args->forks);
	if (fork_id < 0) {
		return EXIT_FAILURE;
	}

	kr_crypto_init();

	/* Create a server engine. */
	knot_mm_t pool;
	mm_ctx_mempool(&pool, MM_DEFAULT_BLKSIZE);
	static struct engine engine;
	ret = engine_init(&engine, &pool);
	if (ret != 0) {
		kr_log_error("[system] failed to initialize engine: %s\n", kr_strerror(ret));
		return EXIT_FAILURE;
	}
	/* Initialize the worker */
	ret = worker_init(&engine, the_args->forks);
	if (ret != 0) {
		kr_log_error("[system] failed to initialize worker: %s\n", kr_strerror(ret));
		return EXIT_FAILURE;
	}

	uv_loop_t *loop = uv_default_loop();
	/* Catch some signals. */
	static uv_signal_t sigint, sigterm, sigchld;
	if (true) ret = uv_signal_init(loop, &sigint);
	if (!ret) ret = uv_signal_init(loop, &sigterm);
	if (!ret) ret = uv_signal_init(loop, &sigchld);
	if (!ret) ret = uv_signal_start(&sigint, signal_handler, SIGINT);
	if (!ret) ret = uv_signal_start(&sigterm, signal_handler, SIGTERM);
	if (!ret) ret = uv_signal_start(&sigchld, signal_handler, SIGCHLD);
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
	/* Profiling: avoid SIGPROF waking up the event loop.  Otherwise the profiles
	 * (of the usual type) may skew results, e.g. epoll_pwait() taking lots of time. */
	ret = uv_loop_configure(loop, UV_LOOP_BLOCK_SIGNAL, SIGPROF);
	if (ret) {
		kr_log_info("[system] failed to block SIGPROF in event loop, ignoring: %s\n",
				uv_strerror(ret));
	}

	/* Start listening, in the sense of network_listen_fd(). */
	if (start_listening(&engine.net, &the_args->fds) != 0) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	ret = udp_queue_init_global(loop);
	if (ret) {
		kr_log_error("[system] failed to initialize UDP queue: %s\n",
				kr_strerror(ret));
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/* Start the scripting engine */
	if (engine_load_sandbox(&engine) != 0) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	for (i = 0; i < the_args->config.len; ++i) {
		const char *config = the_args->config.at[i];
		if (engine_loadconf(&engine, config) != 0) {
			ret = EXIT_FAILURE;
			goto cleanup;
		}
		lua_settop(engine.L, 0);
	}

	drop_capabilities();

	if (engine_start(&engine) != 0) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	if (network_engage_endpoints(&engine.net)) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/* Run the event loop */
	ret = run_worker(loop, &engine, fork_id == 0, the_args);

cleanup:/* Cleanup. */
	engine_deinit(&engine);
	worker_deinit();
	if (loop != NULL) {
		uv_loop_close(loop);
	}
	mp_delete(pool.ctx);
cleanup_args:
	args_deinit(the_args);
	kr_crypto_cleanup();
	return ret;
}
