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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <libknot/errcode.h>
#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/rrtype/rrsig.h>

#include "contrib/cleanup.h"
#include "contrib/ucw/lib.h"
#include "contrib/murmurhash3/murmurhash3.h"
#include "lib/cache.h"
#include "lib/client_subnet.h"
#include "lib/cdb_lmdb.h"
#include "lib/defines.h"
#include "lib/utils.h"

/** Cache version */
#define KEY_VERSION "V\x03"
/** An upper bound on the cache key length; see cache_key() */
#define KEY_SIZE (KNOT_DNAME_MAXLEN + 3 * sizeof(uint8_t) + 2 * sizeof(uint16_t))

/* Shorthand for operations on cache backend */
#define cache_isvalid(cache) ((cache) && (cache)->api && (cache)->db)
#define cache_op(cache, op, ...) (cache)->api->op((cache)->db, ## __VA_ARGS__)


/** @internal Memory-mapped cache entries; same field meanings as
 *  struct kr_cache_entry, except for type of data. */
typedef struct mmentry {
	uint32_t timestamp;
	uint32_t ttl;
	uint8_t  rank;
	uint8_t  flags;
	/** Short entry contains uint16_t hash instead. */
	uint8_t  data[];
} mmentry_t;


/** @internal Removes all records from cache. */
static inline int cache_purge(struct kr_cache *cache)
{
	cache->stats.delete += 1;
	return cache_op(cache, clear);
}

/** @internal Open cache db transaction and check internal data version. */
static int assert_right_version(struct kr_cache *cache)
{
	/* Check cache ABI version */
	knot_db_val_t key = { KEY_VERSION, 2 };
	knot_db_val_t val = { KEY_VERSION, 2 };
	int ret = cache_op(cache, read, &key, &val, 1);
	if (ret == 0) {
		ret = kr_error(EEXIST);
	} else {
		/* Version doesn't match. Recreate cache and write version key. */
		ret = cache_op(cache, count);
		if (ret != 0) { /* Non-empty cache, purge it. */
			kr_log_info("[cache] purging cache\n");
			ret = cache_purge(cache);
		}
		/* Either purged or empty. */
		if (ret == 0) {
			/* Key/Val is invalidated by cache purge, recreate it */
			key.data = KEY_VERSION;
			key.len = 2;
			val = key;
			ret = cache_op(cache, write, &key, &val, 1);
		}
	}
	kr_cache_sync(cache);
	return ret;
}

int kr_cache_open(struct kr_cache *cache, const struct kr_cdb_api *api, struct kr_cdb_opts *opts, knot_mm_t *mm)
{
	if (!cache) {
		return kr_error(EINVAL);
	}
	/* Open cache */
	if (!api) {
		api = kr_cdb_lmdb();
	}
	cache->api = api;
	int ret = cache->api->open(&cache->db, opts, mm);
	if (ret != 0) {
		return ret;
	}
	memset(&cache->stats, 0, sizeof(cache->stats));
	/* Check cache ABI version */
	(void) assert_right_version(cache);
	return 0;
}

void kr_cache_close(struct kr_cache *cache)
{
	if (cache_isvalid(cache)) {
		cache_op(cache, close);
		cache->db = NULL;
	}
}

void kr_cache_sync(struct kr_cache *cache)
{
	if (cache_isvalid(cache) && cache->api->sync) {
		cache_op(cache, sync);
	}
}

/**
 * @internal The key starts by { u8 tag, u8[1-255] name in LF, u16 type }.
 *
 * The name is lowercased and label order is reverted for easy prefix search.
 * e.g. '\x03nic\x02cz\x00' is saved as 'cz\x00nic\x00'
 *
 * In case of ECS the key is extended either by:
 *  - u8[1-2] location code, in case of location->hash entry; or by
 *  - u8 '\0' and u16 hash, in case of hash->data entry.
 */
static size_t cache_key(uint8_t *buf, uint8_t tag, const knot_dname_t *name,
			uint16_t rrtype, const kr_ecs_t *ecs, int32_t ecs_lkey)
{
	/* Convert name to lookup format */
	int ret = knot_dname_lf(buf, name, NULL);
	if (ret != 0) {
		assert(false);
		return 0;
	}
	/* Write tag + type */
	uint8_t name_len = buf[0];
	buf[0] = tag;
	uint8_t *buf_now = buf + sizeof(tag) + name_len;
	memcpy(buf_now, &rrtype, sizeof(rrtype));
	buf_now += sizeof(rrtype);

	/* ECS-specific handling now */
	if (ecs != NULL && ecs_lkey < 0) {
		memcpy(buf_now, ecs->loc, ecs->loc_len);
		buf_now += ecs->loc_len;
	}
	if (ecs_lkey >= 0) {
		uint16_t lkey = ecs_lkey;
		assert(lkey == ecs_lkey);
		*(buf_now++) = '\0';
		memcpy(buf_now, &lkey, sizeof(lkey));
		buf_now += sizeof(lkey);
	}
	assert(buf_now - buf <= (ptrdiff_t)KEY_SIZE);
	return buf_now - buf;
}


/** @internal Verify entry against a timestamp and replace timestamp by drift if OK;
	uint32_t time_now = *timestamp;
 *   return ESTALE otherwise. */
static int check_lifetime(mmentry_t *found, uint32_t *timestamp)
{
	if (!timestamp) {
		/* No time constraint. */
		return kr_ok();
	} else if (*timestamp < found->timestamp) {
		/* John Connor record cached in the future. */
		/* Even a sub-query can commonly make that happen with 1s difference,
		 * as we only use the timestamp of the original request. */
		*timestamp = 0;
		return kr_ok();
	} else {
		/* Check if the record is still valid. */
		uint32_t drift = *timestamp - found->timestamp;
		if (drift <= found->ttl) {
			*timestamp = drift;
			return kr_ok();
		}
	}
	return kr_error(ESTALE);
}

/** @internal Find a cache entry or eturn error code.
 *   It includes timestamp checking, ECS handling, etc.
 *   The current time entry->timestamp is replaced by drift on success. */
static int lookup(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name,
	uint16_t type, const kr_ecs_t *ecs, struct kr_cache_entry *entry)
{
	bool precond = name && cache && entry && (!ecs || ecs->loc_len > 0);
	if (!precond) {
		assert(false);
		return kr_error(EINVAL);
	}

	/* Prepare lookup and return value. */
	uint8_t keybuf[KEY_SIZE];
	knot_db_val_t key = {
		.data = keybuf,
		.len = cache_key(keybuf, tag, name, type, ecs, -1),
	};
	knot_db_val_t val = { NULL, 0 };

	int ret = key.len ? cache_op(cache, read, &key, &val, 1) : kr_error(EINVAL);

	bool require_scope0 = false;
	if (ecs == NULL) {
	retry_without_ecs:
		/* The non-ECS format is used. */
		if (ret != 0) {
			return ret == kr_error(EINVAL) ? ret : kr_error(ENOENT);
		}
		if (val.len < offsetof(mmentry_t, data) || (val.len >> 16)) {
			return kr_error(EILSEQ); /* bogus length */
		}
		mmentry_t *mme = val.data;
		
		if (require_scope0 && !(mme->flags & KR_CACHE_FLAG_ECS_SCOPE0)) {
			return kr_error(ENOENT);
		}

		/* Only time can stop us now. */
		ret = check_lifetime(mme, &entry->timestamp);
		if (ret) {
			return ret;
		}
		/* Deserialize *mme. */
		*entry = (struct kr_cache_entry){
			.timestamp	= entry->timestamp,
			.ttl		= mme->ttl,
			.rank		= mme->rank,
			.flags		= mme->flags,
			.data_len	= val.len - offsetof(mmentry_t, data),
			.data		= mme->data,
		};
		return kr_ok();
	}
	/* We want ECS from now on.
	 * The value should be a "short entry", with hash instead of data. */

	if (ret == 0 && val.len != offsetof(mmentry_t, data) + 2) {
		/* Bogus size found; continue as if not found, unless debugging. */
		assert(false);
		ret = kr_error(ENOENT);
	}
	mmentry_t *mmes = val.data;
	uint32_t timestamp_orig = entry->timestamp;
	if (!ret) {
		ret = check_lifetime(mmes, &entry->timestamp);
	}
	if (!ret) {
		/* We have an OK short entry and timestamp has been updated already.
		 * Let's try to find the rest of the entry. */
		uint16_t mmes_hash = mmes->data[0] + 256 * mmes->data[1];
		key.len = cache_key(keybuf, tag, name, type, ecs, mmes_hash);
		ret = key.len ? cache_op(cache, read, &key, &val, 1) : kr_error(EINVAL);
	}

	if (ret) {
		assert(ret);
		/* The search failed, at some point,
		 * but we may still use the scope0 entry, if it exists. */
		key.len = cache_key(keybuf, tag, name, type, NULL, -1);
		ret = key.len ? cache_op(cache, read, &key, &val, 1) : kr_error(EINVAL);
		require_scope0 = true;
		/* To be sure; maybe we haven't changed it. */
		entry->timestamp = timestamp_orig;
		goto retry_without_ecs;
	}
	
	/* The rest of entry is OK, so fill the output. */
	*entry = (struct kr_cache_entry){
		.timestamp	= entry->timestamp,
		.ttl		= mmes->ttl,
		.rank		= mmes->rank,
		.flags		= mmes->flags,
		.data_len	= val.len,
		.data		= val.data,
	};
	return kr_ok();
}

int kr_cache_peek(struct kr_cache *cache, const kr_ecs_t *ecs,
		  uint8_t tag, const knot_dname_t *name, uint16_t type,
		  struct kr_cache_entry *entry)
{
	bool precond = cache_isvalid(cache) && name && entry;
	if (!precond) {
		return kr_error(EINVAL);
	}

	int err = lookup(cache, tag, name, type, ecs, entry);
	if (!err) {
		cache->stats.hit += 1;
	}
       	if (err == kr_error(ENOENT) || err == kr_error(ESTALE)) {
		cache->stats.miss += 1;
	}
	return err;
}

/** Serialize data. If it's RRs (incl. sigs), clear their TTLs and return the minimum. */
static uint32_t serialize_data(const uint8_t *data, uint16_t len, uint8_t tag,
				uint8_t *dest)
{
	memcpy(dest, data, len);
	if (tag != KR_CACHE_RR && tag != KR_CACHE_SIG) {
		return 0;
	}
	knot_rdata_t *rd = dest;
	uint32_t ttl = -1;
	for (; rd < dest + len; rd = kr_rdataset_next(rd)) {
		ttl = MIN(ttl, knot_rdata_ttl(rd));
		knot_rdata_set_ttl(rd, 0);
	}
	assert(dest + len == rd && ttl != -1);
	return ttl;
}
static void entry2mm(const struct kr_cache_entry *src, uint32_t ttl, mmentry_t *dest)
{
	*dest = (mmentry_t){
		.timestamp	= src->timestamp,
		.ttl		= src->ttl ? src->ttl : ttl,
		.rank		= src->rank,
		.flags		= src->flags,
	};
}

int kr_cache_insert(struct kr_cache *cache, const kr_ecs_t *ecs, uint8_t tag,
		    const knot_dname_t *name, uint16_t type,
		    const struct kr_cache_entry *entry)
{
	bool precond = cache_isvalid(cache) && name && entry && entry->data;
	if (!precond) {
		assert(false);
		return kr_error(EINVAL);
	}

	/* Prepare key/value for insertion. */
	uint8_t keybuf[KEY_SIZE];
	knot_db_val_t key = {
		.data = keybuf,
		.len = cache_key(keybuf, tag, name, type, ecs, -1),
	};
	if (key.len == 0) {
		return kr_error(EINVAL);
	}

	int ret;
	if (!ecs || ecs->loc_len == 0) {
		/* The non-ECS format is used. */
		knot_db_val_t value = {
			.data = NULL,
			.len = offsetof(mmentry_t, data) + entry->data_len,
		};

		if (cache->api == kr_cdb_lmdb()) {
			/* LMDB can do late write and avoid copy */
			ret = cache_op(cache, write, &key, &value, 1);
			if (ret != 0) {
				return ret;
			}
			mmentry_t *mme = value.data;
			uint32_t ttl = serialize_data(entry->data, entry->data_len,
							tag, mme->data);
			entry2mm(entry, ttl, mme);
			ret = cache_op(cache, sync); /* Make sure the entry is committed. */
		} else {
			/* Other backends must prepare contiguous data first */
			char buf[value.len];
			value.data = buf;
			mmentry_t *mme = value.data;
			uint32_t ttl = serialize_data(entry->data, entry->data_len,
							tag, mme->data);
			entry2mm(entry, ttl, mme);
			ret = cache_op(cache, write, &key, &value, 1);
		}

		cache->stats.insert += (ret == 0);
		return ret;
	}

	/* The two-step ECS format is used.  Let's start with the "second step".
	 * We don't check for overwriting existing values, though it might be
	 * more efficient not to dirty the cache(s) in such cases. */

	/* Problem: we need to hash (and store) RRs with zeroed TTL,
	 * but the API does not guarantee that now, so we make a copy. */
	uint8_t data_ttl0[entry->data_len];
	uint32_t ttl = serialize_data(entry->data, entry->data_len, tag, data_ttl0);
	uint32_t hash_tmp = hash((const char *)/*sign-cast*/data_ttl0, entry->data_len);
	uint16_t hash = hash_tmp ^ (hash_tmp >> 16);

	uint8_t key2buf[KEY_SIZE];
	knot_db_val_t key2 = {
		.data = key2buf,
		.len = cache_key(key2buf, tag, name, type, ecs, hash),
	};
	if (key2.len == 0) {
		return kr_error(EINVAL);
	}
	knot_db_val_t value2 = {
		.data = data_ttl0,
		.len = entry->data_len,
	};

	ret = cache_op(cache, write, &key2, &value2, 1);
	if (ret) {
		return ret;
	}

	/* The second structure to write is small, so let's construct it. */
	mmentry_t *mm_val = (mmentry_t *)key2buf; /* reuse the large space */
	entry2mm(entry, ttl, mm_val);
	mm_val->data[0] = hash % 256;
	mm_val->data[1] = hash / 256;
	knot_db_val_t value = {
		.data = mm_val,
		.len = offsetof(mmentry_t, data) + 2,
	};

	ret = cache_op(cache, write, &key, &value, 1);
	cache->stats.insert += (ret == 0); /* let's only count it as one insertion */
	return ret;
}

int kr_cache_remove(struct kr_cache *cache, const kr_ecs_t *ecs,
		    uint8_t tag, const knot_dname_t *name, uint16_t type)
{
	if (!cache_isvalid(cache) || !name ) {
		return kr_error(EINVAL);
	}

	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, type, ecs, -1);
	if (key_len == 0) {
		return kr_error(EINVAL);
	}
	knot_db_val_t key = { keybuf, key_len };
	cache->stats.delete += 1;
	return cache_op(cache, remove, &key, 1);
	/* Note: even if ecs is requested, only the first (short) part is removed.
	 * We do no reference counting, so we can't know if the RRset is still alive. */
}

int kr_cache_clear(struct kr_cache *cache)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}
	int ret = cache_purge(cache);
	if (ret == 0) {
		ret = assert_right_version(cache);
	}
	return ret;
}

int kr_cache_match(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, knot_db_val_t *val, int maxcount)
{
	if (!cache_isvalid(cache) || !name ) {
		return kr_error(EINVAL);
	}
	if (!cache->api->match) {
		return kr_error(ENOSYS);
	}

	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, 0, NULL, 0);
	if (key_len == 0) {
		return kr_error(EILSEQ);
	}

	/* Trim type from the search key */ 
	knot_db_val_t key = { keybuf, key_len - 2 };
	return cache_op(cache, match, &key, val, maxcount);
}

/** @internal Count the number of RRs if the length of data is known,
 *  i.e. "inverse" of knot_rdataset_size. */
static int kr_rdataset_count(const knot_rdata_t *data, uint16_t len, uint16_t *count)
{
	const knot_rdata_t *rd = data;
	int cnt = 0;
	while (rd < data + len) {
		rd = kr_rdataset_next(/*const-cast*/(knot_rdata_t *)rd);
		++cnt;
	}
	if (rd != data + len) {
		kr_log_debug("[cach] ignored bogus rrset from cache.\n");
		return kr_error(EILSEQ);
	}
	*count = cnt;
	return kr_ok();
}
static int peek_rr(struct kr_cache *cache, const kr_ecs_t *ecs, knot_rrset_t *rr,
		   struct kr_cache_entry *entry, bool is_sig)
{
	if (!cache_isvalid(cache) || !rr || !entry || !entry->timestamp) {
		return kr_error(EINVAL);
	}

	/* Check if the RRSet is in the cache. */
	uint8_t tag = is_sig ? KR_CACHE_SIG : KR_CACHE_RR;
	int ret = kr_cache_peek(cache, ecs, tag, rr->owner, rr->type, entry);
	if (ret != 0) {
		return ret;
	}
	assert(entry->data);
	if (is_sig) {
		rr->type = KNOT_RRTYPE_RRSIG;
	}
	rr->rrs.data = entry->data;
	ret = kr_rdataset_count(rr->rrs.data, entry->data_len, &rr->rrs.rr_count);
	return ret;
}
int kr_cache_peek_rr(struct kr_cache *cache, const kr_ecs_t *ecs, knot_rrset_t *rr,
		     struct kr_cache_entry *entry)
{
	return peek_rr(cache, ecs, rr, entry, false);
}

int kr_cache_materialize(knot_rrset_t *rr, const struct kr_cache_entry *entry,
			 knot_mm_t *mm)
{
	if (!rr || !entry || entry->timestamp/*drift*/ > entry->ttl) {
		return kr_error(EINVAL);
	}

	/* Find valid records */
	knot_rdata_t **valid = malloc(sizeof(knot_rdata_t *) * rr->rrs.rr_count);
	uint16_t valid_count = 0;
	knot_rdata_t *rd = rr->rrs.data;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		uint32_t ttl = knot_rdata_ttl(rd);
		if (!ttl || ttl >= entry->timestamp/*drift*/) {
			valid[valid_count++] = rd;
		}
		rd = kr_rdataset_next(rd);
	}

	/* Reordering left up for now. */


	rr->rrs.data = NULL;
	int err = knot_rdataset_gather(&rr->rrs, valid, valid_count, mm);
	free(valid);
	if (err) {
		return kr_error(err);
	}

	/* Fixup TTL */
	rd = rr->rrs.data;
	uint32_t ttl_new = entry->ttl - entry->timestamp/*drift*/;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		uint32_t ttl = knot_rdata_ttl(rd);
		if (ttl) {
			/* count on possibility of having per-RR TTL */
			ttl -= - entry->timestamp/*drift*/;
		} else {
			ttl = ttl_new;
		}
		knot_rdata_set_ttl(rd, ttl);
		rd = kr_rdataset_next(rd);
	}

	return kr_ok();
}

static int insert_rr(struct kr_cache *cache, const kr_ecs_t *ecs, const knot_rrset_t *rr,
			uint8_t rank, uint8_t flags, uint32_t timestamp, bool is_sig)
{
	if (!cache_isvalid(cache) || !rr) {
		return kr_error(EINVAL);
	}

	/* Ignore empty records */
	if (knot_rrset_empty(rr)) {
		return kr_ok();
	}

	/* Prepare entry to write */
	struct kr_cache_entry entry = {
		.timestamp = timestamp,
		.ttl = 0, /* let it be computed from the RRs */
		.rank = rank,
		.flags = flags,
		.data_len = knot_rdataset_size(&rr->rrs),
		.data = rr->rrs.data,
	};

	uint8_t tag = is_sig ? KR_CACHE_SIG : KR_CACHE_RR;
	uint16_t type = is_sig ? knot_rrsig_type_covered(&rr->rrs, 0) : rr->type;
	return kr_cache_insert(cache, ecs, tag, rr->owner, type, &entry);
}
int kr_cache_insert_rr(struct kr_cache *cache, const kr_ecs_t *ecs, const knot_rrset_t *rr,
			uint8_t rank, uint8_t flags, uint32_t timestamp)
{
	return insert_rr(cache, ecs, rr, rank, flags, timestamp, false);
}

int kr_cache_peek_rrsig(struct kr_cache *cache, const kr_ecs_t *ecs, knot_rrset_t *rr,
			struct kr_cache_entry *entry)
{
	return peek_rr(cache, ecs, rr, entry, true);
}

int kr_cache_insert_rrsig(struct kr_cache *cache, const kr_ecs_t *ecs, const knot_rrset_t *rr,
			  uint8_t rank, uint8_t flags, uint32_t timestamp)
{
	return insert_rr(cache, ecs, rr, rank, flags, timestamp, true);
}
