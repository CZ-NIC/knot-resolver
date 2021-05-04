/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <libknot/db/db.h>

#if KR_USE_MDBX
	#include <mdbx.h>
	// FIXME: investigate mysterious constant-sized memleaks
#else
	#include <lmdb.h>
#endif

#if KR_USE_MDBX
	#define MDB_env MDBX_env
	#define mdb_env_create mdbx_env_create
	#define MDB_SUCCESS 0
	#define MDB_WRITEMAP MDBX_WRITEMAP
	#define MDB_MAPASYNC MDBX_UTTERLY_NOSYNC
	#define MDB_NOTLS MDBX_NOTLS
	#define mdb_env_open mdbx_env_open
	#define mdb_filehandle_t mdbx_filehandle_t
	#define mdb_env_get_fd mdbx_env_get_fd
	#define MDB_txn MDBX_txn
	#define mdb_txn_begin mdbx_txn_begin
	#define mdb_dbi_open mdbx_dbi_open
	#define MDB_dbi MDBX_dbi
	#define mdb_txn_commit mdbx_txn_commit
	#define mdb_env_close mdbx_env_close
	// Avoid mdbx_env_sync() as it uses some macro magic.
	#define mdb_env_sync(env, force) mdbx_env_sync_ex((env), (force), false)
	#define mdb_dbi_close mdbx_dbi_close
	#define MDB_cursor MDBX_cursor
	#define MDB_NOTFOUND MDBX_NOTFOUND
	#define MDB_MAP_FULL MDBX_MAP_FULL
	#define MDB_TXN_FULL MDBX_TXN_FULL
	#define mdb_strerror mdbx_strerror
	// Different field names as well; see val_mdb2knot().
	#define MDB_val MDBX_val
	// TODO: can be improved
	#define mdb_env_set_mapsize mdbx_env_set_mapsize
	#define MDB_RDONLY MDBX_TXN_RDONLY
	#define mdb_txn_renew mdbx_txn_renew
	#define MDB_READERS_FULL MDBX_READERS_FULL
	#define mdb_reader_check mdbx_reader_check
	#define mdb_txn_reset mdbx_txn_reset
	#define mdb_cursor_renew mdbx_cursor_renew
	#define mdb_cursor_open mdbx_cursor_open
	#define mdb_cursor_close mdbx_cursor_close
	#define mdb_cursor_get mdbx_cursor_get
	#define MDB_SET_RANGE MDBX_SET_RANGE
	#define mdb_txn_abort mdbx_txn_abort
	#define MDB_PREV MDBX_PREV
	#define MDB_NEXT MDBX_NEXT
	#define mdb_env_get_path mdbx_env_get_path
	#define mdb_del mdbx_del
	#define MDB_RESERVE MDBX_RESERVE
	#define mdb_put mdbx_put
	#define mdb_get mdbx_get
	#define mdb_drop mdbx_drop
	// just an extra field at the end
	#define MDB_stat MDBX_stat
	#define MDB_RDWR MDBX_TXN_READWRITE
	#define MDB_DATANAME MDBX_DATANAME
	#define mdb_env_info(env, info) \
		mdbx_env_info_ex((env), NULL, (info), sizeof(MDBX_envinfo))
	#define MDB_GET_CURRENT MDBX_GET_CURRENT
#else
	#define MDB_RDWR 0
	#define MDB_DATANAME "/data.mdb"
#endif

/** Conversion between knot and lmdb structs for values. */
static inline knot_db_val_t val_mdb2knot(MDB_val v)
{
	return (knot_db_val_t){
	#if KR_USE_MDBX
		.len = v.iov_len, .data = v.iov_base
	#else
		.len = v.mv_size, .data = v.mv_data
	#endif
	};
}
static inline MDB_val val_knot2mdb(knot_db_val_t v)
{
	return (MDB_val){
	#if KR_USE_MDBX
		.iov_len = v.len, .iov_base = v.data
	#else
		.mv_size = v.len, .mv_data = v.data
	#endif
	};
}

