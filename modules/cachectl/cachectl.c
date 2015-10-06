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
#include <libknot/descriptor.h>
#include <ccan/json/json.h>

#include "daemon/engine.h"
#include "lib/module.h"
#include "lib/cache.h"

/* Max number of records pruned at one go. */
#define PRUNE_GRANULARITY UINT16_MAX

/*
 * Properties.
 */

typedef int (*cache_cb_t)(struct kr_cache_txn *txn, namedb_iter_t *it, namedb_val_t *key, void *baton);

/** @internal Prefix walk. */
static int cache_prefixed(struct engine *engine, const char *args, unsigned txn_flags, cache_cb_t cb, void *baton)
{
	/* Decode parameters */
	uint8_t namespace = 'R';
	char *extra = (char *)strchr(args, ' ');
	if (extra != NULL) {
		extra[0] = '\0';
		namespace = extra[1];
	}

	/* Convert to domain name */
	uint8_t buf[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(buf, args, sizeof(buf))) {
		return kr_error(EINVAL);
	}
	/* '*' starts subtree search */
	const uint8_t *dname = buf;
	bool subtree_match = false;
	if (dname[0] == '\1' && dname[1] == '*') {
		subtree_match = true;
		dname = knot_wire_next_label(dname, NULL);
	}
	/* Convert to search key prefix */
	uint8_t prefix[sizeof(uint8_t) + KNOT_DNAME_MAXLEN];
	int ret = knot_dname_lf(prefix, dname, NULL);
	if (ret != 0) {
		return kr_error(EINVAL);
	}
	size_t prefix_len = prefix[0] + sizeof(uint8_t);
	prefix[0] = namespace;

	/* Start search transaction */
	struct kr_cache *cache = &engine->resolver.cache;
	const namedb_api_t *api = cache->api;
	struct kr_cache_txn txn;
	ret = kr_cache_txn_begin(cache, &txn, txn_flags);
	if (ret != 0) {
		return kr_error(EIO);
	}

	/* Walk through cache records matching given prefix.
	 * Note that since the backend of the cache is opaque, there's no exactly efficient
	 * way to do prefix search (i.e. Redis uses hashtable but offers SCAN, LMDB can do lexical closest match, ...). */
	namedb_val_t key = { prefix, prefix_len };
	namedb_iter_t *it = api->iter_begin(&txn.t, 0);
	if (it) { /* Seek first key matching the prefix. */
		it = api->iter_seek(it, &key, NAMEDB_GEQ);
	}
	while (it != NULL) {
		if (api->iter_key(it, &key) != 0) {
			break;
		}
		/* If not subtree match, allow only keys with the same length. */
		if (!subtree_match && key.len != prefix_len + sizeof(uint16_t)) {
			break;
		}
		/* Allow equal or longer keys with the same prefix. */
		if (key.len < prefix_len || memcmp(key.data, prefix, prefix_len) != 0) {
			break;
		}
		/* Callback */
		ret = cb(&txn, it, &key, baton);
		if (ret != 0) {
			break;
		}
		/* Next key */
		it = api->iter_next(it);
	}
	api->iter_finish(it);
	kr_cache_txn_commit(&txn);
	return ret;
}

/** Return boolean true if a record is expired. */
static bool is_expired(struct kr_cache_entry *entry, uint32_t drift)
{
	return drift > entry->ttl;
}

/** @internal Delete iterated key. */
static int cache_delete_cb(struct kr_cache_txn *txn, namedb_iter_t *it, namedb_val_t *key, void *baton)
{
	struct kr_cache *cache = txn->owner;
	return cache->api->del(&txn->t, key);
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
	ret = kr_cache_txn_commit(&txn);
	if (ret != 0) {
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

	/* Partial clear (potentially slow/unsupported). */
	if (args && strlen(args) > 0) {
		int ret = cache_prefixed(env, args, 0, &cache_delete_cb, NULL);
		if (ret != 0) {
			return strdup(kr_strerror(ret));
		}
		return strdup("true");
	}

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

	/* Clear reputation tables */
	lru_deinit(engine->resolver.cache_rtt);
	lru_deinit(engine->resolver.cache_rep);
	lru_init(engine->resolver.cache_rtt, LRU_RTT_SIZE);
	lru_init(engine->resolver.cache_rep, LRU_REP_SIZE);
	return strdup(ret == 0 ? "true" : kr_strerror(ret));
}

/** @internal Serialize cached record name into JSON. */
static int cache_dump_cb(struct kr_cache_txn *txn, namedb_iter_t *it, namedb_val_t *key, void *baton)
{
	JsonNode* json_records = baton;
	char buf[KNOT_DNAME_MAXLEN];
	/* Extract type */
	uint16_t type = 0;
	const char *endp = (const char *)key->data + key->len - sizeof(uint16_t);
	memcpy(&type, endp, sizeof(uint16_t));
	endp -= 1;
	/* Extract domain name */
	char *dst = buf;
	const char *scan = endp - 1;
	while (scan > (const char *)key->data) {
		if (*scan == '\0') {
			const size_t lblen = endp - scan - 1;
			memcpy(dst, scan + 1, lblen);
			dst += lblen;
			*dst++ = '.';
			endp = scan;
		}
		--scan;
	}
	memcpy(dst, scan + 1, endp - scan);
	JsonNode *json_item = json_find_member(json_records, buf);
	if (!json_item) {
		json_item = json_mkarray();
		json_append_member(json_records, buf, json_item);
	}
	knot_rrtype_to_string(type, buf, sizeof(buf));
	json_append_element(json_item, json_mkstring(buf));
	return kr_ok();
}

/**
 * Query cached records.
 *
 * Input:  [string] domain name
 * Output: { result: bool }
 *
 */
static char* get(void *env, struct kr_module *module, const char *args)
{
	if (!args) {
		return NULL;
	}
	/* Dump all keys matching prefix */
	char *result = NULL;
	JsonNode *json_records = json_mkobject();
	if (json_records) {
		int ret = cache_prefixed(env, args, NAMEDB_RDONLY, &cache_dump_cb, json_records);
		if (ret == 0) {
			result = json_encode(json_records);
		}
		json_delete(json_records);
	}

	return result;
}

/*
 * Module implementation.
 */

struct kr_prop *cachectl_props(void)
{
	static struct kr_prop prop_list[] = {
	    { &prune,    "prune", "Prune expired/invalid records." },
	    { &clear,    "clear", "Clear cache records." },
	    { &get,      "get",   "Get a list of cached record(s)." },
	    { NULL, NULL, NULL }
	};
	return prop_list;
}

KR_MODULE_EXPORT(cachectl);
