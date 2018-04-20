#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <lib/defines.h>

#include "kr_cache_gc.h"

static void print_help()
{
	printf("Usage: kr_cache_gc -c <resolver_cache>\n");
}

int main(int argc, char *argv[])
{
	printf("Knot Resolver Cache Garbage Collector v. %s\n", KR_CACHE_GC_VERSION);

	const char *cache_path = NULL;

	int o;
	while ((o = getopt(argc, argv, "hc:")) != -1) {
		switch (o) {
		case 'c':
			cache_path = optarg;
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

	int ret = kr_cache_gc(cache_path);
	if (ret) {
		printf("Error (%s)\n", kr_strerror(ret));
		return 10;
	}

	return 0;
}

