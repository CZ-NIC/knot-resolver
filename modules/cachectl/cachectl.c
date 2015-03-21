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

#include "lib/module.h"
#include "lib/context.h"
#include "lib/cache.h"

/*
 * Properties.
 */

/**
 * Return number of cached records.
 *
 * Input:  N/A
 * Output: { size: int }
 * 
 */
static char* get_size(struct kr_context *ctx, struct kr_module *module, const char *args)
{
	char *result = NULL;
	const namedb_api_t *storage = kr_cache_storage();

	/* Fetch item count */
	namedb_txn_t txn;
	int ret = kr_cache_txn_begin(ctx->cache, &txn, NAMEDB_RDONLY);
	if (ret == 0) {
		asprintf(&result, "{ \"size\": %d }", storage->count(&txn));
		kr_cache_txn_abort(&txn);
	}
	
	return result;
}

/** Return boolean true if a record in the RR set is expired. */
static int is_expired(struct kr_cache_rrset *rr, uint32_t drift)
{
	/* Initialize set. */
	knot_rdataset_t rrs;
	rrs.rr_count = rr->count;
	rrs.data =  rr->data;

	for (unsigned i = 0; i < rrs.rr_count; ++i) {
		const knot_rdata_t *rd = knot_rdataset_at(&rrs, i);
		if (knot_rdata_ttl(rd) <= drift) {
			return 1;
		}
	}

	return 0;
}

/**
 * Prune expired/invalid records.
 *
 * Input:  N/A
 * Output: { pruned: int }
 * 
 */
static char* prune(struct kr_context *ctx, struct kr_module *module, const char *args)
{
	const namedb_api_t *storage = kr_cache_storage();

	namedb_txn_t txn;
	int ret = kr_cache_txn_begin(ctx->cache, &txn, 0);
	if (ret != 0) {
		return NULL;
	}

	/* Iterate cache and find expired records. */
	int pruned = 0;
	uint32_t now = time(NULL);
	namedb_iter_t *it = storage->iter_begin(&txn, 0);
	while (it) {
		/* Fetch RR from cache */
		namedb_val_t key, val;
		if (storage->iter_key(it, &key) != 0 ||
		    storage->iter_val(it, &val)) {
			break;
		}
		/* Prune expired records. */
		struct kr_cache_rrset *rr = val.data;
		if (is_expired(rr, now - rr->timestamp)) {
			storage->del(&txn, &key);
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
static char* clear(struct kr_context *ctx, struct kr_module *module, const char *args)
{
	namedb_txn_t txn;
	int ret = kr_cache_txn_begin(ctx->cache, &txn, 0);
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
        { &get_size, "size",  "Return number of cached records.", },
        { &prune,    "prune", "Prune expired/invalid records.", },
        { &clear,    "clear", "Clear all cache records.", },
        { NULL, NULL, NULL }
    };
    return prop_list;
}

KR_MODULE_EXPORT(cachectl);
