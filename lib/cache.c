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

/* Key size */
#define KEY_SIZE (sizeof(uint8_t) + KNOT_DNAME_MAXLEN + sizeof(uint16_t))

/** Used cache storage engine (default LMDB) */
const namedb_api_t *(*kr_cache_storage)(void) = namedb_lmdb_api;
#define db_api kr_cache_storage()

/** Generic storage options */
union storage_opts {
	struct namedb_lmdb_opts lmdb;
};

namedb_t *kr_cache_open(const char *handle, mm_ctx_t *mm, size_t maxsize)
{
	if (!handle || maxsize == 0) {
		return NULL;
	}

	union storage_opts opts;
	memset(&opts, 0, sizeof(opts));
	if (db_api == namedb_lmdb_api()) {
		opts.lmdb.mapsize = maxsize;
		opts.lmdb.path = handle;
	}

	namedb_t *db = NULL;
	int ret = db_api->init(&db, mm, &opts);
	if (ret != 0) {
		return NULL;
	}

	return db;
}

void kr_cache_close(namedb_t *cache)
{
	if (cache) {
		db_api->deinit(cache);
	}
}

int kr_cache_txn_begin(namedb_t *cache, namedb_txn_t *txn, unsigned flags)
{
	if (!cache || !txn) {
		return kr_error(EINVAL);
	}

	return db_api->txn_begin(cache, txn, flags);
}

int kr_cache_txn_commit(namedb_txn_t *txn)
{
	if (!txn) {
		return kr_error(EINVAL);
	}

	int ret = db_api->txn_commit(txn);
	if (ret != 0) {
		kr_cache_txn_abort(txn);
	}
	return ret;
}

void kr_cache_txn_abort(namedb_txn_t *txn)
{
	if (txn) {
		db_api->txn_abort(txn);
	}
}

/** @internal Composed key as { u8 tag, u8[1-255] name, u16 type } */
static size_t cache_key(uint8_t *buf, uint8_t tag, const knot_dname_t *name, uint16_t type)
{
	knot_dname_lf(buf, name, NULL);
	size_t len = buf[0] + 1;
	memcpy(buf + len, &type, sizeof(type));
	buf[0] = tag;
	return len + sizeof(type);
}

static struct kr_cache_entry *cache_entry(namedb_txn_t *txn, uint8_t tag, const knot_dname_t *name, uint16_t type)
{
	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, type);

	/* Look up and return value */
	namedb_val_t key = { keybuf, key_len };
	namedb_val_t val = { NULL, 0 };
	int ret = db_api->find(txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	return (struct kr_cache_entry *)val.data;
}

struct kr_cache_entry *kr_cache_peek(namedb_txn_t *txn, uint8_t tag, const knot_dname_t *name,
                                     uint16_t type, uint32_t *timestamp)
{
	if (!txn || !tag || !name) {
		return NULL;
	}

	struct kr_cache_entry *entry = cache_entry(txn, tag, name, type);
	if (!entry) {
		return NULL;
	}	

	/* No time constraint */
	if (!timestamp) {
		return entry;
	} else if (*timestamp <= entry->timestamp) {
		/* John Connor record cached in the future. */
		*timestamp = 0;
		return entry;
	} else {
		/* Check if the record is still valid. */
		uint32_t drift = *timestamp - entry->timestamp;
		if (drift < entry->ttl) {
			*timestamp = drift;
			return entry;
		}
	}

	return NULL;	
}

static void entry_write(struct kr_cache_entry *dst, struct kr_cache_entry *header, namedb_val_t data)
{
	assert(dst);
	memcpy(dst, header, sizeof(*header));
	memcpy(dst->data, data.data, data.len);
}

int kr_cache_insert(namedb_txn_t *txn, uint8_t tag, const knot_dname_t *name, uint16_t type,
                    struct kr_cache_entry *header, namedb_val_t data)
{
	if (!txn || !name || !tag || !header) {
		return kr_error(EINVAL);
	}

	/* Insert key */
	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, type);
	namedb_val_t key = { keybuf, key_len };
	namedb_val_t entry = { NULL, sizeof(*header) + data.len };

	/* LMDB can do late write and avoid copy */
	if (db_api == namedb_lmdb_api()) {
		int ret = db_api->insert(txn, &key, &entry, 0);
		if (ret != 0) {
			return ret;
		}
		entry_write(entry.data, header, data);
	} else {
		/* Other backends must prepare contiguous data first */
		entry.data = malloc(entry.len);
		if (!entry.data) {
			return kr_error(ENOMEM);
		}
		entry_write(entry.data, header, data);
		int ret = db_api->insert(txn, &key, &entry, 0);
		free(entry.data);
		if (ret != 0) {
			return ret;
		}
	}

	return kr_ok();
}

int kr_cache_remove(namedb_txn_t *txn, uint8_t tag, const knot_dname_t *name, uint16_t type)
{
	if (!txn || !tag || !name ) {
		return kr_error(EINVAL);
	}

	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, type);
	namedb_val_t key = { keybuf, key_len };
	return db_api->del(txn, &key);
}

int kr_cache_clear(namedb_txn_t *txn)
{
	if (!txn) {
		return kr_error(EINVAL);
	}

	return db_api->clear(txn);
}

int kr_cache_peek_rr(namedb_txn_t *txn, knot_rrset_t *rr, uint32_t *timestamp)
{
	if (!txn || !rr || !timestamp) {
		return kr_error(EINVAL);
	}

	/* Check if the RRSet is in the cache. */
	struct kr_cache_entry *entry = kr_cache_peek(txn, KR_CACHE_RR, rr->owner, rr->type, timestamp);
	if (entry) {
		rr->rrs.rr_count = entry->count;
		rr->rrs.data = entry->data;
		return kr_ok();
	}

	/* Not found. */
	return kr_error(ENOENT);
}

knot_rrset_t kr_cache_materialize(const knot_rrset_t *src, uint32_t drift, mm_ctx_t *mm)
{
	assert(src);

	/* Make RRSet copy. */
	knot_rrset_t copy;
	knot_rrset_init(&copy, NULL, src->type, src->rclass);
	copy.owner = knot_dname_copy(src->owner, mm);
	if (!copy.owner) {
		return copy;
	}

	for (uint16_t i = 0; i < src->rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&src->rrs, i);
		if (knot_rdata_ttl(rd) > drift) {
			if (knot_rdataset_add(&copy.rrs, rd, mm) != 0) {
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

int kr_cache_insert_rr(namedb_txn_t *txn, const knot_rrset_t *rr, uint32_t timestamp)
{
	if (!txn || !rr) {
		return kr_error(EINVAL);
	}

	/* Ignore empty records */
	if (knot_rrset_empty(rr)) {
		return kr_ok();
	}

	/* Prepare header to write */
	struct kr_cache_entry header = {
		.timestamp = timestamp,
		.ttl = 0,
		.count = rr->rrs.rr_count
	};
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&rr->rrs, i);
		if (knot_rdata_ttl(rd) > header.ttl) {
			header.ttl = knot_rdata_ttl(rd);
		}
	}

	namedb_val_t data = { rr->rrs.data, knot_rdataset_size(&rr->rrs) };
	return kr_cache_insert(txn, KR_CACHE_RR, rr->owner, rr->type, &header, data);
}
