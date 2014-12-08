#include <assert.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <lmdb.h>
#include <libknot/internal/mempattern.h>
#include <libknot/errcode.h>
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

struct kr_txn
{
	MDB_dbi dbi;
	unsigned flags;
	MDB_txn *txn;
	MDB_txn *parent;
	mm_ctx_t *mm;
};

/*                       MDB access                                           */

static void create_env_dir(const char *path)
{
	(void) mkdir(path, 0770);
}

static int dbase_open(struct kr_cache *cache, const char *handle)
{
	int ret = mdb_env_create(&cache->env);
	if (ret != 0) {
		return ret;
	}

	create_env_dir(handle);

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

	DEBUG_MSG("OPEN '%s'\n", handle);
	return 0;
}

static void dbase_close(struct kr_cache *cache)
{
	mdb_close(cache->env, cache->dbi);
	mdb_env_close(cache->env);
	DEBUG_MSG("CLOSE\n");
}

/*                       data access                                          */

static MDB_cursor *cursor_acquire(struct kr_txn *txn)
{
	MDB_cursor *cursor = NULL;

	int ret = mdb_cursor_open(txn->txn, txn->dbi, &cursor);
	if (ret != 0) {
		return NULL;
	}

	return cursor;
}

static void cursor_release(MDB_cursor *cursor)
{
	mdb_cursor_close(cursor);
}

/*                       data serialization                                   */

#define PACKED_RRTYPE(d) *((uint16_t *)(d))
#define PACKED_RDATA(d)  ((knot_rdata_t *)(d) + sizeof(uint16_t))

static MDB_val pack_key(const knot_dname_t *name)
{
	MDB_val key = { knot_dname_size(name), (void *)name };
	return key;
}

static int del_entry(MDB_cursor *cur)
{
	/* Remember duplicate data count. */
	size_t rr_count = 0;
	mdb_cursor_count(cur, &rr_count);

	/* Remove key if last entry. */
	int ret = MDB_SUCCESS;
	if (rr_count == 1) {
		ret = mdb_cursor_del(cur, MDB_NODUPDATA);
	} else {
		ret = mdb_cursor_del(cur, 0);
	}

	if (ret == MDB_SUCCESS) {
		return KNOT_EOK;
	}

	return KNOT_ERROR;
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

	int ret = mdb_cursor_put(cur, &key, &data, 0);
	if (ret != MDB_SUCCESS) {
		DEBUG_MSG("cache insert failed => %s\n", mdb_strerror(ret));
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

static int pack_list(MDB_cursor *cur, const knot_rrset_t *rr)
{
	uint32_t expire = time(NULL) + knot_rrset_ttl(rr);

	int ret = KNOT_EOK;
	const knot_rdataset_t *rrs = &rr->rrs;
	for (uint16_t i = 0; i < rrs->rr_count; i++) {
		knot_rdata_t *rd = knot_rdataset_at(rrs, i);
		ret = pack_entry(cur, rr->owner, rr->type, rd, expire);
		if (ret != KNOT_EOK) {
			break;
		}
	}

#ifndef NDEBUG
	char owner[KNOT_DNAME_MAXLEN], type_str[16];
	knot_dname_to_str(owner, rr->owner, sizeof(owner));
	knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
	DEBUG_MSG("store '%s' type '%s' => %s\n", owner, type_str, knot_strerror(ret));
#endif

	return ret;
}

static int unpack_entry(MDB_cursor *cur, knot_rrset_t *rr, MDB_val *data, uint32_t now, mm_ctx_t *mm)
{
	knot_rdata_t *rd = PACKED_RDATA(data->mv_data);
	uint16_t rr_type = PACKED_RRTYPE(data->mv_data);
	if (rr_type != rr->type) {
		return KNOT_EOK;
	}

	/* Check if TTL expired (with negative grace period). */
	if (knot_rdata_ttl(rd) <= now + KR_TTL_GRACE) {
		return del_entry(cur);
	}

	return knot_rdataset_add(&rr->rrs, rd, mm);
}

static int unpack_list(MDB_cursor *cur, knot_rrset_t *rr, mm_ctx_t *mm)
{
	uint32_t now = time(NULL);

	MDB_val key = pack_key(rr->owner);
	MDB_val data = { 0, NULL };

	/* Fetch first entry. */
	int ret = mdb_cursor_get(cur, &key, &data, MDB_SET_KEY);

	/* Unpack, and find chained duplicates. */
	while (ret == MDB_SUCCESS) {
		ret = unpack_entry(cur, rr, &data, now, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = mdb_cursor_get(cur, &key, &data, MDB_NEXT_DUP);
	}

	/* No results. */
	if (knot_rrset_empty(rr)) {
		return KNOT_ENOENT;
	}

	/* Update TTL for all records. */
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&rr->rrs, i);
		knot_rdata_set_ttl(rd, knot_rdata_ttl(rd) - now);
	}

#ifndef NDEBUG
	char owner[KNOT_DNAME_MAXLEN], type_str[16];
	knot_dname_to_str(owner, rr->owner, sizeof(owner));
	knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
	DEBUG_MSG("load '%s' type '%s' => %u records\n", owner, type_str, rr->rrs.rr_count);
#endif

	return KNOT_EOK;
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

struct kr_txn *kr_cache_txn_begin(struct kr_cache *cache, struct kr_txn *parent, unsigned flags, mm_ctx_t *mm)
{
	assert(cache);
	
	struct kr_txn *txn = mm_alloc(mm, sizeof(struct kr_txn));
	if (txn == NULL) {
		return NULL;
	}
	memset(txn, 0, sizeof(struct kr_txn));

	txn->dbi = cache->dbi;
	txn->mm  = mm;
	if (parent) {
		txn->parent = parent->txn;
	}

	unsigned mdb_flags = 0;
	txn->flags = flags;
	if (flags & KR_CACHE_RDONLY) {
		mdb_flags |= MDB_RDONLY;
	}

	int ret = mdb_txn_begin(cache->env, txn->parent, mdb_flags, &txn->txn);
	if (ret != 0) {
		mm_free(mm, txn);
		return NULL;
	}

	return txn;
}

int kr_cache_txn_commit(struct kr_txn *txn)
{
	int ret = mdb_txn_commit(txn->txn);

#ifndef NDEBUG
	MDB_stat stat;
	mdb_stat(txn->txn, txn->dbi, &stat);
	DEBUG_MSG("commit, %zu entries\n", stat.ms_entries);
#endif

	mm_free(txn->mm, txn);
	return ret;
}

void kr_cache_txn_abort(struct kr_txn *txn)
{
	mdb_txn_abort(txn->txn);
	mm_free(txn->mm, txn);
}

int kr_cache_query(struct kr_txn *txn, knot_rrset_t *rr)
{
	MDB_cursor *cursor = cursor_acquire(txn);
	if (cursor == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = unpack_list(cursor, rr, txn->mm);

	cursor_release(cursor);
	return ret;
}

int kr_cache_insert(struct kr_txn *txn, const knot_rrset_t *rr, unsigned flags)
{
	MDB_cursor *cursor = cursor_acquire(txn);
	if (cursor == NULL) {
		return KNOT_ERROR;
	}

	/* TODO: cache eviction if full */
	int ret = pack_list(cursor, rr);

	cursor_release(cursor);
	return ret;
}

int kr_cache_remove(struct kr_txn *txn, const knot_rrset_t *rr)
{
	MDB_cursor *cursor = cursor_acquire(txn);
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

		}
	}

	cursor_release(cursor);
	return ret;
}
