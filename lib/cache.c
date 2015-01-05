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

#include <assert.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <libknot/internal/mempattern.h>
#include <libknot/internal/namedb/namedb_lmdb.h>
#include <libknot/dnssec/random.h>
#include <libknot/errcode.h>
#include <libknot/descriptor.h>

#include "lib/cache.h"
#include "lib/defines.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[cache] " fmt, ## __VA_ARGS__)
#define db_api namedb_lmdb_api()

namedb_t *kr_cache_open(const char *handle, mm_ctx_t *mm, size_t maxsize)
{
	struct namedb_lmdb_opts opts = NAMEDB_LMDB_OPTS_INITIALIZER;
	opts.mapsize = maxsize;
	opts.path = handle;

	namedb_t *db = NULL;
	int ret = db_api->init(&db, mm, &opts);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	return db;
}

void kr_cache_close(namedb_t *cache)
{
	db_api->deinit(cache);
}

int kr_cache_txn_begin(namedb_t *cache, namedb_txn_t *txn, unsigned flags)
{
	return db_api->txn_begin(cache, txn, flags);
}

int kr_cache_txn_commit(namedb_txn_t *txn)
{
	int ret = db_api->txn_commit(txn);
	if (ret != KNOT_EOK) {
		kr_cache_txn_abort(txn);
	}
	return ret;
}

void kr_cache_txn_abort(namedb_txn_t *txn)
{
	return db_api->txn_abort(txn);
}

static size_t cache_key(uint8_t *buf, const knot_dname_t *name, uint16_t type)
{
	size_t len = knot_dname_to_wire(buf, name, KNOT_DNAME_MAXLEN);
	memcpy(buf + len, &type, sizeof(uint16_t));
	return len + sizeof(uint16_t);
}

static struct kr_cache_rrset *cache_rr(namedb_txn_t *txn, const knot_dname_t *name, uint16_t type)
{
	uint8_t keybuf[KNOT_DNAME_MAXLEN + sizeof(uint16_t)];
	size_t key_len = cache_key(keybuf, name, type);

	/* Look up and return value */
	namedb_val_t key = { keybuf, key_len };
	namedb_val_t val = { NULL, 0 };
	int ret = db_api->find(txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	return (struct kr_cache_rrset *)val.data;
}

int kr_cache_query(namedb_txn_t *txn, knot_rrset_t *rr, uint32_t *timestamp)
{
	/* Check if the RRSet is in the cache. */
	struct kr_cache_rrset *found_rr = cache_rr(txn, rr->owner, rr->type);
	if (found_rr != NULL) {
#ifndef NDEBUG
		char name_str[KNOT_DNAME_MAXLEN];
		knot_dname_to_str(name_str, rr->owner, sizeof(name_str));
		char type_str[16];
		knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
		DEBUG_MSG("read '%s %s' => %u RRs\n", name_str, type_str, found_rr->count);
#endif
		/* Assign data and return success. */
		rr->rrs.rr_count = found_rr->count;
		rr->rrs.data = found_rr->data;

		/* No time constraint or current timestamp */
		if (timestamp == NULL || *timestamp <= found_rr->timestamp) {
			return KNOT_EOK;
		}

		/* Check if all RRs are still valid. */
		uint32_t drift = *timestamp - found_rr->timestamp;
		for (unsigned i = 0; i < rr->rrs.rr_count; ++i) {
			const knot_rdata_t *rd = knot_rdataset_at(&rr->rrs, i);
			if (drift >= knot_rdata_ttl(rd)) {
				return KNOT_ENOENT;
			}
		}

		*timestamp = drift;
		return KNOT_EOK;
	}

	/* Not found. */
	return KNOT_ENOENT;
}

int kr_cache_insert(namedb_txn_t *txn, const knot_rrset_t *rr, uint32_t timestamp)
{
	/* Ignore empty records. */
	if (knot_rrset_empty(rr)) {
		return KNOT_EOK;
	}

	uint8_t keybuf[KNOT_DNAME_MAXLEN + sizeof(uint16_t)];
	size_t key_len = cache_key(keybuf, rr->owner, rr->type);
	namedb_val_t key = { keybuf, key_len };
	namedb_val_t val = { NULL, sizeof(struct kr_cache_rrset) + knot_rdataset_size(&rr->rrs) };

#ifndef NDEBUG
	char name_str[KNOT_DNAME_MAXLEN];
	knot_dname_to_str(name_str, rr->owner, sizeof(name_str));
	char type_str[16];
	knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
	DEBUG_MSG("write '%s %s' => %u RRs (key=%zuB,data=%zuB)\n", name_str, type_str, rr->rrs.rr_count, key.len, val.len);
#endif

	int ret = db_api->insert(txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Write cached record. */
	struct kr_cache_rrset *cache_rr = val.data;
	cache_rr->timestamp = timestamp;
	cache_rr->count = rr->rrs.rr_count;
	memcpy(cache_rr->data, rr->rrs.data, knot_rdataset_size(&rr->rrs));

	return KNOT_EOK;
}

int kr_cache_remove(namedb_txn_t *txn, const knot_rrset_t *rr)
{
	uint8_t keybuf[KNOT_DNAME_MAXLEN + sizeof(uint16_t)];
	size_t key_len = cache_key(keybuf, rr->owner, rr->type);
	namedb_val_t key = { keybuf, key_len };

	/* TODO: selective deletion by RRSet subtraction */

	return db_api->del(txn, &key);
}

int kr_cache_clear(namedb_txn_t *txn)
{
	return db_api->clear(txn);
}

int kr_cache_prune(namedb_txn_t *txn, uint32_t timestamp)
{
	/* Whole cache sweep is not feasible as we don't have a list of items sorted
	 * by age nor any sort of LRU/MRU, completely random replace is not possible
	 * as well.
	 * - The LMDB also can't delete items when the MAPSIZE is reached.
	 * - So we're probably need to iteratively scan the LMDB and prune aged
	 *   items.
	 * - This is not ideal, because queries won't be able to write to cache
	 *   until at least some entry ages out.
	 * - Idea - make poor man's LRU with two databases doing following:
	 *   - Fill up 1, mark that it's unwritable
	 *   - Fill up 2, mark that it's unwritable
	 *   - Clear 1, all writes will now go in there
	 *   - This gives us LR(written) with resolution 2
	 */
	return KNOT_EOK;
}
