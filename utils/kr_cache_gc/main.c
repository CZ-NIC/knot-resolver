#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <lib/defines.h>

#include "kr_cache_gc.h"

volatile static int killed = 0;

static void got_killed(int signum)
{
	(void)signum;
	switch (++killed) {
	case 1:
		break;
	case 2:
		exit(5);
		break;
	case 3:
		abort();
	default:
		assert(0);
	}
}

static void print_help()
{
	printf("Usage: kr_cache_gc -c <resolver_cache> [ optional params... ]\n");
	printf("Optional params:\n");
	printf(" -d <garbage_interval(millis)>\n");
	printf(" -l <deletes_per_txn>\n");
	printf(" -m <rw_txn_duration(usecs)>\n");
	printf(" -w <wait_next_rw_txn(usecs)>\n");
	printf(" -t <temporary_memory(MBytes)>\n");
	printf(" -n (= dry run)\n");
}

int main(int argc, char *argv[])
{
	printf("Knot Resolver Cache Garbage Collector v. %s\n", KR_CACHE_GC_VERSION);

	signal(SIGTERM, got_killed);
	signal(SIGKILL, got_killed);
	signal(SIGPIPE, got_killed);
	signal(SIGCHLD, got_killed);
	signal(SIGINT, got_killed);

	kr_cache_gc_cfg_t cfg = { 0 };

	int o;
	while ((o = getopt(argc, argv, "hnc:d:l:m:w:t:")) != -1) {
		switch (o) {
		case 'c':
			cfg.cache_path = optarg;
			break;
#define get_nonneg_optarg(to) do { if (atol(optarg) < 0) { print_help(); return 2; } to = atol(optarg); } while (0)
		case 'd':
			get_nonneg_optarg(cfg.gc_interval);
			cfg.gc_interval *= 1000;
			break;
		case 'l':
			get_nonneg_optarg(cfg.rw_txn_items);
			break;
		case 'm':
			get_nonneg_optarg(cfg.rw_txn_duration);
			break;
		case 'w':
			get_nonneg_optarg(cfg.rw_txn_delay);
			break;
		case 't':
			get_nonneg_optarg(cfg.temp_keys_space);
			cfg.temp_keys_space *= 1048576;
			break;
#undef get_nonneg_optarg
		case 'n':
			cfg.dry_run = true;
			break;
		case ':':
		case '?':
		case 'h':
			print_help();
			return 1;
		default:
			assert(0);
		}
	}

	if (cfg.cache_path == NULL) {
		print_help();
		return 1;
	}

	do {
		int ret = kr_cache_gc(&cfg);
		if (ret) {
			printf("Error (%s)\n", kr_strerror(ret));
			return 10;
		}

		usleep(cfg.gc_interval);
	} while (cfg.gc_interval > 0 && !killed);

	return 0;
}

