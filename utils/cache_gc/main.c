/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/defines.h"
#include "lib/utils.h"
#include <libknot/libknot.h>
#include <lmdb.h>

#include "kresconfig.h"
#include "kr_cache_gc.h"

static volatile int killed = 0;
static volatile int exit_code = 0;

static void got_killed(int signum)
{
	(void)signum;
	switch (++killed) {
	case 1:
		break;
	case 2:
		exit_code = 5;
		break;
	default:
		abort();
	}
}

static void print_help(void)
{
	printf("Usage: kr_cache_gc -c <resolver_cache> [ optional params... ]\n");
	printf("Optional params:\n");
	printf(" -d <garbage_interval(millis)>\n");
	printf(" -l <deletes_per_txn>\n");
	printf(" -L <reads_per_txn>\n");
	printf(" -m <rw_txn_duration(usecs)>\n");
	printf(" -u <cache_max_usage(percent)>\n");
	printf(" -f <cache_to_be_freed(percent-of-current-usage)>\n");
	printf(" -w <wait_next_rw_txn(usecs)>\n");
	printf(" -t <temporary_memory(MBytes)>\n");
	printf(" -n (= dry run)\n");
}

static long get_nonneg_optarg(void)
{
	char *end;
	const long result = strtol(optarg, &end, 10);
	if (result >= 0 && end && *end == '\0')
		return result;
	// not OK
	print_help();
	exit(2);
}

int main(int argc, char *argv[])
{
	printf("Knot Resolver Cache Garbage Collector, version %s\n", PACKAGE_VERSION);
	if (setvbuf(stdout, NULL, _IONBF, 0) || setvbuf(stderr, NULL, _IONBF, 0)) {
		(void)fprintf(stderr, "Failed to to set output buffering (ignored): %s\n",
				strerror(errno));
		(void)fflush(stderr);
	}

	struct sigaction act = {
		.sa_handler = got_killed,
		.sa_flags = SA_RESETHAND,
	};
	sigemptyset(&act.sa_mask);
	kr_assert(!sigaction(SIGTERM, &act, NULL));
	kr_assert(!sigaction(SIGPIPE, &act, NULL));
	kr_assert(!sigaction(SIGCHLD, &act, NULL));
	kr_assert(!sigaction(SIGINT, &act, NULL));

	kr_cache_gc_cfg_t cfg = {
		.ro_txn_items = 200,
		.rw_txn_items = 100,
		.cache_max_usage = 80,
		.cache_to_be_freed = 10
	};

	int o;
	while ((o = getopt(argc, argv, "hnvc:d:l:L:m:u:f:w:t:")) != -1) {
		switch (o) {
		case 'c':
			cfg.cache_path = optarg;
			break;
		case 'd':
			cfg.gc_interval = get_nonneg_optarg();
			cfg.gc_interval *= 1000;
			break;
		case 'l':
			cfg.rw_txn_items = get_nonneg_optarg();
			break;
		case 'L':
			cfg.ro_txn_items = get_nonneg_optarg();
			break;
		case 'm':
			cfg.rw_txn_duration = get_nonneg_optarg();
			break;
		case 'u':
			cfg.cache_max_usage = get_nonneg_optarg();
			break;
		case 'f':
			cfg.cache_to_be_freed = get_nonneg_optarg();
			break;
		case 'w':
			cfg.rw_txn_delay = get_nonneg_optarg();
			break;
		case 't':
			cfg.temp_keys_space = get_nonneg_optarg();
			cfg.temp_keys_space *= 1048576;
			break;
		case 'n':
			cfg.dry_run = true;
			break;
		case 'v':
			kr_log_level_set(LOG_DEBUG);
			break;
		case ':':
		case '?':
		case 'h':
			print_help();
			return 1;
		default:
			kr_assert(false);
		}
	}

	if (cfg.cache_path == NULL) {
		print_help();
		return 1;
	}

	kr_cache_gc_state_t *gc_state = NULL;
	bool last_espace = false;
	do {
		int ret = kr_cache_gc(&cfg, &gc_state);

		/* Let's tolerate ESPACE unless twice in a row. */
		if (ret == KNOT_ESPACE) {
			if (!last_espace)
				ret = KNOT_EOK;
			last_espace = true;
		} else {
			last_espace = false;
		}

		// ENOENT: kresd may not be started yet or cleared the cache now
		// MDB_MAP_RESIZED: GC bailed out but on next iteration it should be OK
		if (ret && ret != KNOT_ENOENT && ret != kr_error(MDB_MAP_RESIZED)) {
			printf("Error (%s)\n", knot_strerror(ret));
			exit_code = 10;
			break;
		}

		usleep(cfg.gc_interval);
	} while (cfg.gc_interval > 0 && !killed);

	kr_cache_gc_free_state(&gc_state);

	return exit_code;
}
