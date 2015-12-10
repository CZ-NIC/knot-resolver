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

/** @file namedb_memcached.c
 *  @brief Implemented all the things that the resolver cache needs,
 *         it's not a general-purpose namedb implementation, and it can't
 *         be since it's *cache* by principle and it doesn't guarantee persistence anyway.
 *  @note The implemented functions are not thread-safe, see http://docs.libmemcached.org/libmemcachedutil.html
 *  @note Write transactions can't be aborted.
 *  @note No iteration support.
 */

#include <assert.h>
#include <string.h>
#include <libmemcached/memcached.h>
#include <libknot/internal/namedb/namedb.h>
#include <libknot/errcode.h>
#include <contrib/cleanup.h>

#include "lib/generic/array.h"
#include "lib/cache.h"
#include "lib/utils.h"

/* Oh, the irony... */
typedef array_t(char *) freelist_t;

static int init(namedb_t **db, mm_ctx_t *mm, void *arg)
{
	if (!db || !arg) {
		return KNOT_EINVAL;
	}

	/* Make sure we're running on binary protocol, as the
	 * textual protocol is broken for binary keys. */
	auto_free char *config_str = kr_strcatdup(2, arg, " --BINARY-PROTOCOL");
	memcached_st *handle = memcached(config_str, strlen(config_str));
	if (!handle) {
		return KNOT_ERROR;
	}

	*db = handle;
	return KNOT_EOK;
}

static void deinit(namedb_t *db)
{
	memcached_free((memcached_st *)db);
}

static int txn_begin(namedb_t *db, namedb_txn_t *txn, unsigned flags)
{
	freelist_t *freelist = malloc(sizeof(*freelist));
	if (!freelist) {
		return KNOT_ENOMEM;
	}
	txn->txn = freelist;
	txn->db  = db;
	array_init(*freelist);
	return KNOT_EOK;
}

static int txn_commit(namedb_txn_t *txn)
{
	freelist_t *freelist = txn->txn;
	if (freelist) {
		for (unsigned i = 0; i < freelist->len; ++i) {
			free(freelist->at[i]);
		}
		array_clear(*freelist);
		free(freelist);
		txn->txn = NULL;
	}
	return KNOT_EOK;
}

static void txn_abort(namedb_txn_t *txn)
{
	/** @warning No real transactions here,
	  *          all the reads/writes are done synchronously.
	  *          If it is needed, we would need to buffer writes in
	  *          the freelist first and put on commit.
	  */
	txn_commit(txn);
}

static int count(namedb_txn_t *txn)
{
	memcached_return_t error = 0;
	memcached_stat_st *stats = memcached_stat(txn->db, NULL, &error);
	if (error != 0) {
		return KNOT_ERROR;
	}
	size_t ret = stats->curr_items;
	free(stats);
	return ret;
}

static int clear(namedb_txn_t *txn)
{
	memcached_return_t ret = memcached_flush(txn->db, 0);
	if (ret != 0) {
		return KNOT_ERROR;
	}
	return KNOT_EOK;
}

static int find(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags)
{
	uint32_t mc_flags = 0;
	memcached_return_t error = 0;
	char *ret = memcached_get(txn->db, key->data, key->len, &val->len, &mc_flags, &error);
	if (error != 0) {
		return KNOT_ENOENT;
	}
	freelist_t *freelist = txn->txn;
	if (array_push(*freelist, ret) < 0) {
		free(ret); /* Can't track this, must free */
		return KNOT_ENOMEM;
	}
	val->data = ret;
	return KNOT_EOK;
}

static int insert(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags)
{
	if (!txn || !key || !val) {
		return KNOT_EINVAL;
	}
	/* @warning This expects usage only for recursor cache, if anyone
	 *          desires to port this somewhere else, TTL shouldn't be interpreted.
	 */
	struct kr_cache_entry *entry = val->data;
	memcached_return_t ret = memcached_set(txn->db, key->data, key->len, val->data, val->len, entry->ttl, 0);
	if (ret != 0) {
		return KNOT_ERROR;
	}
	return KNOT_EOK;
}

static int del(namedb_txn_t *txn, namedb_val_t *key)
{
	memcached_return_t ret = memcached_delete(txn->db, key->data, key->len, 0);
	if (ret != 0) {
		return KNOT_ERROR;
	}
	return KNOT_EOK;
}

static namedb_iter_t *iter_begin(namedb_txn_t *txn, unsigned flags)
{
	/* Iteration is not supported, pruning should be
	 * left on the memcached server */
	return NULL;
}

static namedb_iter_t *iter_seek(namedb_iter_t *iter, namedb_val_t *key, unsigned flags)
{
	assert(0);
	return NULL; /* ENOTSUP */
}

static namedb_iter_t *iter_next(namedb_iter_t *iter)
{
	assert(0);
	return NULL;
}

static int iter_key(namedb_iter_t *iter, namedb_val_t *val)
{
	return KNOT_ENOTSUP;
}

static int iter_val(namedb_iter_t *iter, namedb_val_t *val)
{
	return KNOT_ENOTSUP;
}

static void iter_finish(namedb_iter_t *iter)
{
	assert(0);
}

const namedb_api_t *namedb_memcached_api(void)
{
	static const namedb_api_t api = {
		"memcached",
		init, deinit,
		txn_begin, txn_commit, txn_abort,
		count, clear, find, insert, del,
		iter_begin, iter_seek, iter_next, iter_key, iter_val, iter_finish
	};

	return &api;
}
