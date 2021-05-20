/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/cache/cdb_compat.h"
#include "lib/cache/cdb_lmdb.h"

#if KR_USE_MDBX
	#include <libknot/error.h>
	#include <stdlib.h>
	#include <string.h>
#else
	#include <libknot/db/db_lmdb.h>
#endif

#if !KR_USE_MDBX
const knot_db_api_t *kr_cdb_pt2knot_db_api_t(kr_cdb_pt db)
{
	return knot_db_lmdb_api();
}
#endif

/* The following majority of this C file has only minor differences
 * from Knot's src/libknot/db/db_lmdb.c
 * Some mdbx differences get fully covered by cdb_compat.h defines, some don't.
 */
#if KR_USE_MDBX

/*! Beware: same name but different struct than in resolver's cdb_lmdb.c */
struct lmdb_env
{
	bool shared;
	MDB_dbi dbi;
	MDB_env *env;
	knot_mm_t *pool;
};

/*!
 * \brief Convert error code returned by LMDB to Knot DNS error code.
 *
 * LMDB defines own error codes but uses additional ones from libc:
 * - LMDB errors do not conflict with Knot DNS ones.
 * - Significant LMDB errors are mapped to Knot DNS ones.
 * - Standard errors are converted to negative value to match Knot DNS mapping.
 */
static int lmdb_error_to_knot(int error)
{
	if (error == MDB_SUCCESS) {
		return KNOT_EOK;
	}

	if (error == MDB_NOTFOUND) {
		return KNOT_ENOENT;
	}

	if (error == MDB_TXN_FULL) {
		return KNOT_ELIMIT;
	}

	if (error == MDB_MAP_FULL || error == ENOSPC) {
		return KNOT_ESPACE;
	}

	return -abs(error);
}

static
int knot_db_lmdb_txn_begin(knot_db_t *db, knot_db_txn_t *txn, knot_db_txn_t *parent,
                           unsigned flags)
{
	txn->db = db;
	txn->txn = NULL;

	unsigned txn_flags = 0;
	if (flags & KNOT_DB_RDONLY) {
		txn_flags |= MDB_RDONLY;
	} else {
		txn_flags |= MDB_RDWR;
	}

	MDB_txn *parent_txn = (parent != NULL) ? (MDB_txn *)parent->txn : NULL;

	struct lmdb_env *env = db;
	int ret = mdb_txn_begin(env->env, parent_txn, txn_flags, (MDB_txn **)&txn->txn);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	return KNOT_EOK;
}

static int txn_begin(knot_db_t *db, knot_db_txn_t *txn, unsigned flags)
{
	return knot_db_lmdb_txn_begin(db, txn, NULL, flags);
}

static int txn_commit(knot_db_txn_t *txn)
{
	int ret = mdb_txn_commit((MDB_txn *)txn->txn);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	return KNOT_EOK;
}

static void txn_abort(knot_db_txn_t *txn)
{
	mdb_txn_abort((MDB_txn *)txn->txn);
}

static knot_db_iter_t *iter_set(knot_db_iter_t *iter, knot_db_val_t *key, unsigned flags)
{
	MDB_cursor *cursor = iter;

	MDBX_cursor_op op = MDBX_SET;
	switch(flags) {
	case KNOT_DB_NOOP:  return cursor;
	case KNOT_DB_FIRST: op = MDBX_FIRST; break;
	case KNOT_DB_LAST:  op = MDBX_LAST;  break;
	case KNOT_DB_NEXT:  op = MDBX_NEXT; break;
	case KNOT_DB_PREV:  op = MDBX_PREV; break;
	case KNOT_DB_LEQ:
	case KNOT_DB_GEQ:   op = MDBX_SET_RANGE; break;
	default: break;
	}

	MDB_val db_key = { 0 };
	if (key) {
		db_key = val_knot2mdb(*key);
	}
	MDB_val unused_key = { 0 }, unused_val = { 0 };

	int ret = mdb_cursor_get(cursor, key ? &db_key : &unused_key, &unused_val, op);

	/* LEQ is not supported in LMDB, workaround using GEQ. */
	if (flags == KNOT_DB_LEQ && key) {
		/* Searched key is after the last key. */
		if (ret != MDB_SUCCESS) {
			return iter_set(iter, NULL, KNOT_DB_LAST);
		}
		/* If the searched key != matched, get previous. */
		if ((key->len != db_key.iov_len) ||
		    (memcmp(key->data, db_key.iov_base, key->len) != 0)) {
			return iter_set(iter, NULL, KNOT_DB_PREV);
		}
	}

	if (ret != MDB_SUCCESS) {
		mdb_cursor_close(cursor);
		return NULL;
	}

	return cursor;
}

static knot_db_iter_t *iter_begin(knot_db_txn_t *txn, unsigned flags)
{
	struct lmdb_env *env = txn->db;
	MDB_cursor *cursor = NULL;

	int ret = mdb_cursor_open(txn->txn, env->dbi, &cursor);
	if (ret != MDB_SUCCESS) {
		return NULL;
	}

	/* Clear sorted flag, as it's always sorted. */
	flags &= ~KNOT_DB_SORTED;

	return iter_set(cursor, NULL, (flags == 0) ? KNOT_DB_FIRST : flags);
}

static knot_db_iter_t *iter_next(knot_db_iter_t *iter)
{
	return iter_set(iter, NULL, KNOT_DB_NEXT);
}

static int iter_key(knot_db_iter_t *iter, knot_db_val_t *key)
{
	MDB_cursor *cursor = iter;

	MDB_val mdb_key, mdb_val;
	int ret = mdb_cursor_get(cursor, &mdb_key, &mdb_val, MDB_GET_CURRENT);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	*key = val_mdb2knot(mdb_key);
	return KNOT_EOK;
}

static int iter_val(knot_db_iter_t *iter, knot_db_val_t *val)
{
	MDB_cursor *cursor = iter;

	MDB_val mdb_key, mdb_val;
	int ret = mdb_cursor_get(cursor, &mdb_key, &mdb_val, MDB_GET_CURRENT);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	*val = val_mdb2knot(mdb_val);
	return KNOT_EOK;
}

static void iter_finish(knot_db_iter_t *iter)
{
	if (iter == NULL) {
		return;
	}

	MDB_cursor *cursor = iter;
	mdb_cursor_close(cursor);
}

static int find(knot_db_txn_t *txn, knot_db_val_t *key, knot_db_val_t *val, unsigned flags)
{
	knot_db_iter_t *iter = iter_begin(txn, KNOT_DB_NOOP);
	if (iter == NULL) {
		return KNOT_ERROR;
	}

	int ret = KNOT_EOK;
	if (iter_set(iter, key, flags) == NULL) {
		return KNOT_ENOENT;
	} else {
		ret = iter_val(iter, val);
	}

	iter_finish(iter);
	return ret;
}

static int insert(knot_db_txn_t *txn, knot_db_val_t *key, knot_db_val_t *val, unsigned flags)
{
	struct lmdb_env *env = txn->db;

	MDB_val db_key = val_knot2mdb(*key);
	MDB_val data = val_knot2mdb(*val);

	/* Reserve if only size is declared. */
	unsigned mdb_flags = 0;
	if (val->len > 0 && val->data == NULL) {
		mdb_flags |= MDB_RESERVE;
	}

	int ret = mdb_put(txn->txn, env->dbi, &db_key, &data, mdb_flags);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	/* Update the result. */
	*val = val_mdb2knot(data);
	return KNOT_EOK;
}

static int del(knot_db_txn_t *txn, knot_db_val_t *key)
{
	struct lmdb_env *env = txn->db;
	MDB_val db_key = val_knot2mdb(*key);

	int ret = mdb_del(txn->txn, env->dbi, &db_key, NULL);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	return KNOT_EOK;
}

const knot_db_api_t *kr_cdb_pt2knot_db_api_t(kr_cdb_pt db)
{
	static const knot_db_api_t api = {
		"mdbx",
		NULL, NULL, //init, deinit,
		txn_begin, txn_commit, txn_abort,
		NULL, NULL, //count, clear,
		find, insert, del,
		iter_begin, iter_set, iter_next, iter_key, iter_val, iter_finish
	};
	return &api;
}

#endif // KR_USE_MDBX

