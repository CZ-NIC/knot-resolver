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

/**
 * Partial sweep is not feasible as we don't have a list of items sorted
 * by age nor any sort of LRU/MRU, completely random replace is not possible
 * as well.
 * - Idea - make poor man's LRU with two databases doing following:
 *   - Fill up 1, mark that it's unwritable
 *   - Fill up 2, mark that it's unwritable
 *   - Clear 1, all writes will now go in there
 *   - This gives us LR(written) with resolution 2
 */

#include <time.h>

#include "daemon/engine.h"
#include "lib/module.h"
#include "lib/cache.h"

/* Max number of records pruned at one go. */
#define PRUNE_GRANULARITY UINT16_MAX

/*
 * Properties.
 */

/** Return boolean true if a record is expired. */
static bool is_expired(struct kr_cache_entry *entry, uint32_t drift)
{
	return drift > entry->ttl;
}

/**
 * Prune expired/invalid records.
 *
 * Input:  N/A
 * Output: { pruned: int }
 *
 */
static char* prune(void *env, struct kr_module *module, const char *args)
{
	struct engine *engine = env;
	struct kr_cache *cache = &engine->resolver.cache;
	const namedb_api_t *storage = cache->api;

	struct kr_cache_txn txn;
	int ret = kr_cache_txn_begin(cache, &txn, 0);
	if (ret != 0) {
		return NULL;
	}

	/* Iterate cache and find expired records. */
	int pruned = 0;
	int prune_max = 0;
	if (args) {
		prune_max = atoi(args);
	}
	/* Default pruning granularity */
	if (prune_max == 0) {
		prune_max = PRUNE_GRANULARITY;
	}
	/* Fetch current time and start iterating */
	struct timeval now;
	gettimeofday(&now, NULL);
	namedb_iter_t *it = storage->iter_begin(&txn.t, 0);
	while (it && pruned < prune_max) {
		/* Fetch RR from cache */
		namedb_val_t key, val;
		if (storage->iter_key(it, &key) != 0 ||
		    storage->iter_val(it, &val) != 0) {
			break;
		}
		/* Prune expired records. */
		struct kr_cache_entry *entry = val.data;
		if (entry->timestamp > now.tv_sec) {
			continue;
		}
		if (is_expired(entry, now.tv_sec - entry->timestamp)) {
			storage->del(&txn.t, &key);
			cache->stats.delete += 1;
			pruned += 1;
		}
		it = storage->iter_next(it);
	}

	/* Commit and format result. */
	char *result = NULL;
	if (kr_cache_txn_commit(&txn) != 0) {
		asprintf(&result, "{ \"pruned\": %d, \"error\": \"%s\" }", pruned, knot_strerror(ret));
	} else {
		asprintf(&result, "{ \"pruned\": %d }", pruned);
	}

	return result;
}

/**
 * Clear all records.
 *
 * Input:  N/A
 * Output: { result: bool }
 *
 */
static char* clear(void *env, struct kr_module *module, const char *args)
{
	struct engine *engine = env;

	struct kr_cache_txn txn;
	int ret = kr_cache_txn_begin(&engine->resolver.cache, &txn, 0);
	if (ret != 0) {
		return NULL;
	}

	/* Clear cache and commit. */
	ret = kr_cache_clear(&txn);
	if (ret == 0) {
		ret = kr_cache_txn_commit(&txn);
	} else {
		kr_cache_txn_abort(&txn);
	}

	char *result = NULL;
	asprintf(&result, "{ \"result\": %s }", ret == 0 ? "true" : "false");
	return result;
}

/*
 * Module implementation.
 */

struct kr_prop *cachectl_props(void)
{
	static struct kr_prop prop_list[] = {
	    { &prune,    "prune", "Prune expired/invalid records.", },
	    { &clear,    "clear", "Clear all cache records.", },
	    { NULL, NULL, NULL }
	};
	return prop_list;
}

KR_MODULE_EXPORT(cachectl);
