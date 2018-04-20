#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <lib/defines.h>

#include "kr_cache_gc.h"

static int killed = 0;

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
	printf("Usage: kr_cache_gc -c <resolver_cache> [ -d <garbage_interval(ms)> ]\n");
}

int main(int argc, char *argv[])
{
	printf("Knot Resolver Cache Garbage Collector v. %s\n", KR_CACHE_GC_VERSION);

	signal(SIGTERM, got_killed);
	signal(SIGKILL, got_killed);
	signal(SIGPIPE, got_killed);
	signal(SIGCHLD, got_killed);
	signal(SIGINT, got_killed);

	const char *cache_path = NULL;
	unsigned long interval = 0;

	int o;
	while ((o = getopt(argc, argv, "hc:d:")) != -1) {
		switch (o) {
		case 'c':
			cache_path = optarg;
			break;
		case 'd':
			if (atol(optarg) < 0) {
				print_help();
				return 2;
			}
			interval = atol(optarg) * 1000;
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

	if (cache_path == NULL) {
		print_help();
		return 1;
	}

	do {
		int ret = kr_cache_gc(cache_path);
		if (ret) {
			printf("Error (%s)\n", kr_strerror(ret));
			return 10;
		}

		usleep(interval);
	} while (interval > 0 && !killed);

	return 0;
}

