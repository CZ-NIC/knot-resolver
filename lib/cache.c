#include <assert.h>
#include <time.h>

#include <lmdb.h>
#include <libknot/mempattern.h>
#include <libknot/descriptor.h>

#include "lib/cache.h"
#include "lib/defines.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[cache] " fmt, ## __VA_ARGS__)

struct kr_cache
{
	MDB_dbi dbi;
	MDB_env *env;
	mm_ctx_t *pool;
};

/*                       MDB access                                           */

static int dbase_open(struct kr_cache *cache, const char *handle)
{
	int ret = mdb_env_create(&cache->env);
	if (ret != 0) {
		return ret;
	}

	ret = mdb_env_open(cache->env, handle, 0, 0644);
	if (ret != 0) {
		mdb_env_close(cache->env);
		return ret;
	}

	MDB_txn *txn = NULL;
	ret = mdb_txn_begin(cache->env, NULL, 0, &txn);
	if (ret != 0) {
		mdb_env_close(cache->env);
		return ret;
	}

	ret = mdb_open(txn, NULL, MDB_DUPSORT, &cache->dbi);
	if (ret != 0) {
		mdb_txn_abort(txn);
		mdb_env_close(cache->env);
		return ret;
	}

	ret = mdb_txn_commit(txn);
	if (ret != 0) {
		mdb_env_close(cache->env);
		return ret;
	}

	DEBUG_MSG("opened '%s'\n", handle);

	return 0;
}

static void dbase_close(struct kr_cache *cache)
{
	mdb_close(cache->env, cache->dbi);
	mdb_env_close(cache->env);
}

/*                       data access                                          */

static MDB_cursor *cursor_acquire(struct kr_cache *cache, unsigned flags)
{
	MDB_txn *txn = NULL;
	MDB_cursor *cursor = NULL;
	int ret = mdb_txn_begin(cache->env, NULL, flags, &txn);
	if (ret != 0) {
		return NULL;
	}

	ret = mdb_cursor_open(txn, cache->dbi, &cursor);
	if (ret != 0) {
		mdb_txn_abort(txn);
		return NULL;
	}

	DEBUG_MSG("cursor acquire\n");

	return cursor;
}

static int cursor_release(MDB_cursor *cursor, bool commit)
{
	MDB_txn *txn = mdb_cursor_txn(cursor);
	mdb_cursor_close(cursor);

	int ret = 0;
	if (commit) {
		DEBUG_MSG("cursor release / commit\n");
		ret = mdb_txn_commit(txn);
	} else {
		DEBUG_MSG("cursor release\n");
		mdb_txn_abort(txn);
	}

	return ret;
}

/*                       data serialization                                   */

#define PACKED_RRTYPE(d) *((uint16_t *)(d))
#define PACKED_RDATA(d)  ((knot_rdata_t *)(d) + sizeof(uint16_t))

static MDB_val pack_key(const knot_dname_t *name)
{
	MDB_val key = { knot_dname_size(name), (void *)name };
	return key;
}

static int pack_entry(MDB_cursor *cur, const knot_dname_t *name, uint16_t type,
                      const knot_rdata_t *rdata, uint32_t expire)
{
	size_t rdlen = knot_rdata_array_size(knot_rdata_rdlen(rdata));
	size_t datalen = rdlen + sizeof(type);

	uint8_t buf[datalen];
	memcpy(buf, &type, sizeof(type));
	memcpy(buf + sizeof(type), rdata, rdlen);
	knot_rdata_set_ttl(buf + sizeof(type), expire);

	MDB_val key = pack_key(name);
	MDB_val data = { datalen, buf };

	return mdb_cursor_put(cur, &key, &data, 0);
}

static int pack_list(MDB_cursor *cur, const knot_rrset_t *rr)
{
	uint32_t expire = time(NULL) + knot_rrset_ttl(rr);

	int ret = 0;
	const knot_rdataset_t *rrs = &rr->rrs;
	for (uint16_t i = 0; i < rrs->rr_count; i++) {
		knot_rdata_t *rd = knot_rdataset_at(rrs, i);
		ret = pack_entry(cur, rr->owner, rr->type, rd, expire);
		if (ret != 0) {
			break;
		}
	}

#ifndef NDEBUG
	char *owner = knot_dname_to_str(rr->owner);
	DEBUG_MSG("packed RR '%s' TYPE %u, %u RDATA RC=%s\n", owner, rr->type, rr->rrs.rr_count, mdb_strerror(ret));
	free(owner);
#endif

	return ret;
}

static int unpack_entry(MDB_cursor *cur, knot_rrset_t *rr, MDB_val *data, uint32_t now, mm_ctx_t *mm)
{
	knot_rdata_t *rd = PACKED_RDATA(data->mv_data);
	uint16_t rr_type = PACKED_RRTYPE(data->mv_data);
	if (rr_type != rr->type) {
		return 0;
	}

	/* Check if TTL expired (with negative grace period). */
	if (knot_rdata_ttl(rd) <= now + KR_TTL_GRACE) {
		mdb_cursor_del(cur, 0);
		return 0;
	}

	return knot_rdataset_add(&rr->rrs, rd, mm);
}

static int unpack_list(MDB_cursor *cur, knot_rrset_t *rr, mm_ctx_t *mm)
{
	int ret = 0;
	uint32_t now = time(NULL);

	MDB_val key = pack_key(rr->owner);
	MDB_val data;

	while ((ret = mdb_cursor_get(cur, &key, &data, MDB_NEXT_DUP)) == 0) {
		ret = unpack_entry(cur, rr, &data, now, mm);
		if (ret != 0) {
			return ret;
		}
	}

#ifndef NDEBUG
	char *owner = knot_dname_to_str(rr->owner);
	DEBUG_MSG("unpacked RR '%s' TYPE %u, %u RDATA\n", owner, rr->type, rr->rrs.rr_count);
	free(owner);
#endif

	/* Update TTL for all records. */
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&rr->rrs, i);
		knot_rdata_set_ttl(rd, knot_rdata_ttl(rd) - now);
	}

	return 0;
}

struct kr_cache *kr_cache_open(const char *handle, unsigned flags, mm_ctx_t *mm)
{
	struct kr_cache *cache = mm_alloc(mm, sizeof(struct kr_cache));
	if (cache == NULL) {
		return NULL;
	}
	memset(cache, 0, sizeof(struct kr_cache));

	int ret = dbase_open(cache, handle);
	if (ret != 0) {
		mm_free(mm, cache);
		return NULL;
	}

	cache->pool = mm;
	return cache;
}

void kr_cache_close(struct kr_cache *cache)
{
	dbase_close(cache);
	mm_free(cache->pool, cache);
}

int kr_cache_query(struct kr_cache *cache, knot_rrset_t *rr, mm_ctx_t *mm)
{
	MDB_cursor *cursor = cursor_acquire(cache, MDB_RDONLY);
	if (cursor == NULL) {
		return -1;
	}

	int ret = unpack_list(cursor, rr, mm);
	if (knot_rrset_empty(rr)) {
		ret = -1;
	}

	cursor_release(cursor, false);
	return ret;
}

int kr_cache_insert(struct kr_cache *cache, const knot_rrset_t *rr, unsigned flags)
{
	MDB_cursor *cursor = cursor_acquire(cache, 0);
	if (cursor == NULL) {
	                return -1;
	}

	/* TODO: cache eviction if full */

	int ret = pack_list(cursor, rr);
	if (ret != 0) {
		cursor_release(cursor, false);
		return ret;
	}

	cursor_release(cursor, true);
	return ret;
}

int kr_cache_remove(struct kr_cache *cache, const knot_rrset_t *rr)
{
	MDB_cursor *cursor = cursor_acquire(cache, 0);
	if (cursor == NULL) {
	                return -1;
	}

	int ret = 0;
	MDB_val key = pack_key(rr->owner);
	MDB_val data;

	while ((ret = mdb_cursor_get(cursor, &key, &data, MDB_NEXT_DUP)) == 0) {
		if (PACKED_RRTYPE(data.mv_data) == rr->type &&
		    knot_rdataset_member(&rr->rrs, PACKED_RDATA(data.mv_data), false)) {
			mdb_cursor_del(cursor, 0);
#ifndef NDEBUG
			char *owner = knot_dname_to_str(rr->owner);
			DEBUG_MSG("removed RR '%s' TYPE %u (%p)\n", owner, rr->type, PACKED_RDATA(data.mv_data));
			free(owner);
#endif
		}
	}

	cursor_release(cursor, true);
	return ret;
}
