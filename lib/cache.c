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
#include <libknot/errcode.h>
#include <libknot/descriptor.h>

#include "lib/cache.h"
#include "lib/defines.h"

#define db_api namedb_lmdb_api()

namedb_t *kr_cache_open(const char *handle, mm_ctx_t *mm, size_t maxsize)
{
	if (handle == NULL || maxsize == 0) {
		return NULL;
	}

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
	if (cache != NULL) {
		db_api->deinit(cache);
	}
}

int kr_cache_txn_begin(namedb_t *cache, namedb_txn_t *txn, unsigned flags)
{
	if (cache == NULL || txn == NULL) {
		return KNOT_EINVAL;
	}

	return db_api->txn_begin(cache, txn, flags);
}

int kr_cache_txn_commit(namedb_txn_t *txn)
{
	if (txn == NULL) {
		return KNOT_EINVAL;
	}

	int ret = db_api->txn_commit(txn);
	if (ret != KNOT_EOK) {
		kr_cache_txn_abort(txn);
	}
	return ret;
}

void kr_cache_txn_abort(namedb_txn_t *txn)
{
	if (txn != NULL) {
		db_api->txn_abort(txn);
	}
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

int kr_cache_peek(namedb_txn_t *txn, knot_rrset_t *rr, uint32_t *timestamp)
{
	if (txn == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	/* Check if the RRSet is in the cache. */
	struct kr_cache_rrset *found_rr = cache_rr(txn, rr->owner, rr->type);
	if (found_rr != NULL) {

		/* Assign data and return success. */
		rr->rrs.rr_count = found_rr->count;
		rr->rrs.data = found_rr->data;

		/* No time constraint */
		if (timestamp == NULL) {
			return KNOT_EOK;
		}

		/* John Connor record cached from the future. */
		if (*timestamp < found_rr->timestamp) {
			*timestamp = 0;
			return KNOT_EOK;
		}

		/* Check if at least one RR is still valid. */
		uint32_t drift = *timestamp - found_rr->timestamp;
		for (unsigned i = 0; i < rr->rrs.rr_count; ++i) {
			const knot_rdata_t *rd = knot_rdataset_at(&rr->rrs, i);
			if (knot_rdata_ttl(rd) > drift) {
				*timestamp = drift;
				return KNOT_EOK;
			}
		}

		return KNOT_ENOENT;
	}

	/* Not found. */
	return KNOT_ENOENT;
}

knot_rrset_t kr_cache_materialize(const knot_rrset_t *src, uint32_t drift, mm_ctx_t *mm)
{
	assert(src);

	/* Make RRSet copy. */
	knot_rrset_t copy;
	knot_rrset_init(&copy, NULL, src->type, src->rclass);
	copy.owner = knot_dname_copy(src->owner, mm);
	if (copy.owner == NULL) {
		return copy;
	}
	
	for (uint16_t i = 0; i < src->rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&src->rrs, i);
		if (knot_rdata_ttl(rd) > drift) {
			if (knot_rdataset_add(&copy.rrs, rd, mm) != KNOT_EOK) {
				knot_rrset_clear(&copy, mm);
				return copy;
			}
		}
	}
	
	/* Update TTLs. */
	for (uint16_t i = 0; i < copy.rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&copy.rrs, i);
		knot_rdata_set_ttl(rd, knot_rdata_ttl(rd) - drift);
	}
	
	return copy;
}

int kr_cache_insert(namedb_txn_t *txn, const knot_rrset_t *rr, uint32_t timestamp)
{
	if (txn == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	/* Ignore empty records. */
	if (knot_rrset_empty(rr)) {
		return KNOT_EOK;
	}

	uint8_t keybuf[KNOT_DNAME_MAXLEN + sizeof(uint16_t)];
	size_t key_len = cache_key(keybuf, rr->owner, rr->type);
	namedb_val_t key = { keybuf, key_len };
	namedb_val_t val = { NULL, sizeof(struct kr_cache_rrset) + knot_rdataset_size(&rr->rrs) };

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
	if (txn == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t keybuf[KNOT_DNAME_MAXLEN + sizeof(uint16_t)];
	size_t key_len = cache_key(keybuf, rr->owner, rr->type);
	namedb_val_t key = { keybuf, key_len };

	return db_api->del(txn, &key);
}

int kr_cache_clear(namedb_txn_t *txn)
{
	if (txn == NULL) {
		return KNOT_EINVAL;
	}

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
