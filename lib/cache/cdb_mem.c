/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "lib/cache/cdb_mem.h"
#include "lib/cache/cdb_api.h"
#include "lib/generic/trie.h"
#include "lib/utils.h"

/* Simple in-memory backend backed by QP-trie for ordered ops.
 * Notes:
 * - This backend is volatile (no persistence). It's meant for maximum speed.
 * - Values are stored as malloc'd blobs and owned by the backend.
 * - We implement enough of kr_cdb_api to be a drop-in for cache usage.
 */

struct mem_db {
	trie_t *kv; /* key -> value blob */
	struct kr_cdb_stats stats;
};

static int mem_open(kr_cdb_pt *db, struct kr_cdb_stats *st, struct kr_cdb_opts *opts, knot_mm_t *pool)
{
	(void)opts; (void)pool;
	if (!db || !st) return kr_error(EINVAL);
	struct mem_db *m = calloc(1, sizeof(*m));
	if (!m) return kr_error(ENOMEM);
	m->kv = trie_create(NULL);
	if (!m->kv) { free(m); return kr_error(ENOMEM); }
	*db = (kr_cdb_pt)m;
	st->open++;
	return kr_ok();
}

static void mem_close(kr_cdb_pt db, struct kr_cdb_stats *st)
{
	if (!db) return;
	struct mem_db *m = (struct mem_db*)db;
	/* Free all values */
	int free_val(trie_val_t *pv, void *_) {
		(void)_;
		free(*pv);
		*pv = NULL;
		return 0;
	}
	trie_apply(m->kv, free_val, NULL);
	trie_free(m->kv);
	free(m);
	if (st) st->close++;
}

static int mem_count(kr_cdb_pt db, struct kr_cdb_stats *st)
{
	(void)db;
	if (st) st->count++;
	/* We could return trie_weight, but LMDB count excludes metadata keys; mem has none. */
	struct mem_db *m = (struct mem_db*)db;
	return (int)trie_weight(m->kv);
}

static int mem_clear(kr_cdb_pt db, struct kr_cdb_stats *st)
{
	struct mem_db *m = (struct mem_db*)db;
	/* free all values and reset trie */
	int free_val(trie_val_t *pv, void *_) {
		(void)_;
		free(*pv);
		*pv = NULL;
		return 0;
	}
	trie_apply(m->kv, free_val, NULL);
	trie_clear(m->kv);
	if (st) st->clear++;
	return kr_ok();
}

static int mem_commit(kr_cdb_pt db, struct kr_cdb_stats *st, bool accept_rw, bool reset_ro)
{
	(void)db; (void)accept_rw; (void)reset_ro;
	if (st) st->commit++;
	return kr_ok();
}

static int mem_read(kr_cdb_pt db, struct kr_cdb_stats *st,
			const knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	struct mem_db *m = (struct mem_db*)db;
	for (int i = 0; i < maxcount; ++i) {
		if (st) st->read++;
		trie_val_t *pv = trie_get_try(m->kv, (const char*)key[i].data, key[i].len);
		if (!pv || !*pv) {
			if (st) st->read_miss++;
			return kr_error(ENOENT);
		}
		/* Stored value is a blob: [len|data] exact; copy pointer to caller */
		knot_db_val_t v = *(knot_db_val_t*)(*pv);
		val[i] = v;
	}
	return kr_ok();
}

static int mem_write(kr_cdb_pt db, struct kr_cdb_stats *st,
			const knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	struct mem_db *m = (struct mem_db*)db;
	for (int i = 0; i < maxcount; ++i) {
		if (st) st->write++;
		/* allocate blob holding knot_db_val_t header + bytes */
		size_t blob_sz = sizeof(knot_db_val_t) + val[i].len;
		knot_db_val_t *blob = malloc(blob_sz);
		if (!blob) return kr_error(ENOMEM);
		blob->len = val[i].len;
		blob->data = (uint8_t*)blob + sizeof(knot_db_val_t);
		if (val[i].len && val[i].data)
			memcpy(blob->data, val[i].data, val[i].len);
		trie_val_t *pv = trie_get_ins(m->kv, (const char*)key[i].data, key[i].len);
		if (!pv) { free(blob); return kr_error(ENOMEM); }
		/* replace existing */
		if (*pv) free(*pv);
		*pv = blob;
		/* return DB-owned pointer */
		val[i] = (knot_db_val_t){ .len = blob->len, .data = blob->data };
	}
	return kr_ok();
}

static int mem_remove(kr_cdb_pt db, struct kr_cdb_stats *st,
			knot_db_val_t keys[], int maxcount)
{
	struct mem_db *m = (struct mem_db*)db;
	int deleted = 0;
	for (int i = 0; i < maxcount; ++i) {
		if (st) st->remove++;
		trie_val_t v = NULL;
		int r = trie_del(m->kv, (const char*)keys[i].data, keys[i].len, &v);
		if (r == KNOT_EOK) {
			deleted++;
			free(v);
		} else if (r == KNOT_ENOENT) {
			if (st) st->remove_miss++;
		} else {
			return kr_error(EFAULT);
		}
	}
	return deleted;
}

static int mem_match(kr_cdb_pt db, struct kr_cdb_stats *st,
			knot_db_val_t *key, knot_db_val_t keyval[][2], int maxcount)
{
	struct mem_db *m = (struct mem_db*)db;
	/* Iterate from first >= key prefix, then collect until prefix mismatch */
	trie_val_t *pv = NULL;
	(void)pv; /* not needed directly */
	char *first_key = NULL; uint32_t first_len = 0;
	trie_get_first(m->kv, &first_key, &first_len);
	/* Fallback: naive linear scan; qp-trie lacks seek-by-prefix API */
	int results = 0;
	trie_it_t *it = trie_it_begin(m->kv);
	for (; !trie_it_finished(it); trie_it_next(it)) {
		size_t klen; const char *kstr = trie_it_key(it, &klen);
		if (klen < key->len) continue;
		if (memcmp(kstr, key->data, key->len) != 0) continue;
		if (results >= maxcount) break;
		knot_db_val_t *blob = (knot_db_val_t*)*trie_it_val(it);
		keyval[results][0] = (knot_db_val_t){ .data = (void*)kstr, .len = (int)klen };
		keyval[results][1] = (knot_db_val_t){ .data = blob->data, .len = blob->len };
		results++;
		if (st) st->match++;
	}
	trie_it_free(it);
	if (results == 0 && st) st->match_miss++;
	return results;
}

static int mem_read_leq(kr_cdb_pt db, struct kr_cdb_stats *st,
			knot_db_val_t *key, knot_db_val_t *val)
{
	struct mem_db *m = (struct mem_db*)db;
	trie_val_t *out = NULL;
	int r = trie_get_leq(m->kv, (const char*)key->data, key->len, &out);
	if (st) st->read_leq++;
	if (r < 0 || !out) {
		if (st) st->read_leq_miss++;
		return kr_error(ENOENT);
	}
	/* For exact match r==KNOT_EOK, for less r==1 */
	knot_db_val_t *blob = (knot_db_val_t*)(*out);
	/* Update key to DB-owned key */
	char *k2 = NULL; uint32_t k2len = 0;
	/* We need to fetch the exact key for the out node. There's no direct API,
	 * so do a second pass: iterate to find matching value pointer. */
	trie_it_t *it = trie_it_begin(m->kv);
	while (!trie_it_finished(it)) {
		if (*trie_it_val(it) == *out) {
			k2 = (char*)trie_it_key(it, (size_t*)&k2len);
			break;
		}
		trie_it_next(it);
	}
	trie_it_free(it);
	if (!k2) return kr_error(EFAULT);
	*key = (knot_db_val_t){ .data = k2, .len = (int)k2len };
	*val = (knot_db_val_t){ .data = blob->data, .len = blob->len };
	return (r == KNOT_EOK) ? 0 : 1;
}

static int mem_read_less(kr_cdb_pt db, struct kr_cdb_stats *st,
			knot_db_val_t *key, knot_db_val_t *val)
{
	/* Implement by scanning to strictly previous key. */
	struct mem_db *m = (struct mem_db*)db;
	trie_it_t *it = trie_it_begin(m->kv);
	trie_it_t *prev = NULL;
	for (; !trie_it_finished(it); trie_it_next(it)) {
		size_t klen; const char *kstr = trie_it_key(it, &klen);
		int cmp = key->len <= (int)klen ? memcmp(kstr, key->data, key->len)
					 : -memcmp(key->data, kstr, klen);
		if (cmp >= 0) break;
		prev = it; /* keep last strictly less */
	}
	if (!prev) { trie_it_free(it); if (st) st->read_less++; return kr_error(ENOENT); }
	/* Extract prev */
	size_t klen; const char *kstr = trie_it_key(prev, &klen);
	knot_db_val_t *blob = (knot_db_val_t*)(*trie_it_val(prev));
	*key = (knot_db_val_t){ .data = (void*)kstr, .len = (int)klen };
	*val = (knot_db_val_t){ .data = blob->data, .len = blob->len };
	if (st) st->read_less++;
	trie_it_free(it);
	return 1;
}

static double mem_usage_percent(kr_cdb_pt db)
{
	(void)db;
	return 0.0; /* not applicable; report 0 */
}

static size_t mem_get_maxsize(kr_cdb_pt db)
{
	(void)db;
	return SIZE_MAX;
}

static int mem_check_health(kr_cdb_pt db, struct kr_cdb_stats *st)
{
	(void)db; (void)st;
	return kr_ok();
}

static int mem_it_first(kr_cdb_pt db, struct kr_cdb_stats *st,
			const knot_db_val_t *key, knot_db_val_t *val)
{
	(void)db; (void)st; (void)key; (void)val;
	return kr_error(ENOSYS);
}

static int mem_it_next(kr_cdb_pt db, struct kr_cdb_stats *st, knot_db_val_t *val)
{
	(void)db; (void)st; (void)val;
	return kr_error(ENOSYS);
}

const struct kr_cdb_api *kr_cdb_mem(void)
{
	static const struct kr_cdb_api api = {
		"mem",
		mem_open, mem_close, mem_count, mem_clear, mem_commit,
		mem_read, mem_write, mem_remove,
		mem_match,
		mem_read_leq, mem_read_less,
		mem_usage_percent, mem_get_maxsize,
		mem_check_health,
		mem_it_first, mem_it_next,
	};
	return &api;
}
