/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <lmdb.h>

#include "contrib/cleanup.h"
#include "contrib/ucw/lib.h"
#include "lib/cache/cdb_lmdb.h"
#include "lib/cache/cdb_api.h"
#include "lib/cache/api.h"
#include "lib/utils.h"


/* Defines */
#define LMDB_DIR_MODE   0770
#define LMDB_FILE_MODE  0660

struct lmdb_env
{
	size_t mapsize;
	MDB_dbi dbi;
	MDB_env *env;

	/** Cached transactions
	 *
	 * - only one of (ro,rw) may be active at once
	 * - non-NULL .ro may be active or reset
	 * - non-NULL .rw is always active
	 */
	struct {
		bool ro_active, ro_curs_active;
		MDB_txn *ro, *rw;
		MDB_cursor *ro_curs;
	} txn;
};

/** @brief Convert LMDB error code. */
static int lmdb_error(int error)
{
	/* _BAD_TXN may happen with overfull DB,
	 * even during mdb_get with a single fork :-/ */
	if (error == MDB_BAD_TXN) {
		kr_log_info("[cache] MDB_BAD_TXN, probably overfull\n");
		error = ENOSPC;
	}
	switch (error) {
	case MDB_SUCCESS:
		return kr_ok();
	case MDB_NOTFOUND:
		return kr_error(ENOENT);
	case ENOSPC:
	case MDB_MAP_FULL:
	case MDB_TXN_FULL:
		return kr_error(ENOSPC);
	default:
		kr_log_error("[cache] LMDB error: %s\n", mdb_strerror(error));
		return kr_error(error);
	}
}

/** Conversion between knot and lmdb structs for values. */
static inline knot_db_val_t val_mdb2knot(MDB_val v)
{
	return (knot_db_val_t){ .len = v.mv_size, .data = v.mv_data };
}
static inline MDB_val val_knot2mdb(knot_db_val_t v)
{
	return (MDB_val){ .mv_size = v.len, .mv_data = v.data };
}


/*! \brief Set the environment map size.
 * \note This also sets the maximum database size, see \fn mdb_env_set_mapsize
 */
static int set_mapsize(MDB_env *env, size_t map_size)
{
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		return KNOT_ERROR;
	}

	/* Round to page size. */
	map_size = (map_size / page_size) * page_size;
	int ret = mdb_env_set_mapsize(env, map_size);
	if (ret != MDB_SUCCESS) {
		return lmdb_error(ret);
	}

	return 0;
}

#define FLAG_RENEW (2*MDB_RDONLY)
/** mdb_txn_begin or _renew + handle retries in some situations
 *
 * The retrying logic is so ugly that it has its own function.
 * \note this assumes no transactions are active
 * \return MDB_ errcode, not usual kr_error(...)
 */
static int txn_get_noresize(struct lmdb_env *env, unsigned int flag, MDB_txn **txn)
{
	assert(!env->txn.rw && (!env->txn.ro || !env->txn.ro_active));
	int attempts = 0;
	int ret;
retry:
	/* Do a few attempts in case we encounter multiple issues at once. */
	if (++attempts > 2) {
		return kr_error(1);
	}

	if (flag == FLAG_RENEW) {
		ret = mdb_txn_renew(*txn);
	} else {
		ret = mdb_txn_begin(env->env, NULL, flag, txn);
	}

	if (unlikely(ret == MDB_MAP_RESIZED)) {
		kr_log_info("[cache] detected size increased by another process\n");
		ret = mdb_env_set_mapsize(env->env, 0);
		if (ret == MDB_SUCCESS) {
			goto retry;
		}
	} else if (unlikely(ret == MDB_READERS_FULL)) {
		int cleared;
		ret = mdb_reader_check(env->env, &cleared);
		if (ret == MDB_SUCCESS)
			kr_log_info("[cache] cleared %d stale reader locks\n", cleared);
		else
			kr_log_error("[cache] failed to clear stale reader locks: "
					"LMDB error %d %s\n", ret, mdb_strerror(ret));
		goto retry;
	}
	return ret;
}

/** Obtain a transaction.  (they're cached in env->txn) */
static int txn_get(struct lmdb_env *env, MDB_txn **txn, bool rdonly)
{
	assert(env && txn);
	if (env->txn.rw) {
		/* Reuse the *open* RW txn even if only reading is requested.
		 * We leave the management of this to the cdb_commit command.
		 * The user may e.g. want to do some reads between the writes. */
		*txn = env->txn.rw;
		return kr_ok();
	}

	if (!rdonly) {
		/* avoid two active transactions */
		if (env->txn.ro && env->txn.ro_active) {
			mdb_txn_reset(env->txn.ro);
			env->txn.ro_active = false;
			env->txn.ro_curs_active = false;
		}
		int ret = txn_get_noresize(env, 0/*RW*/, &env->txn.rw);
		if (ret == MDB_SUCCESS) {
			*txn = env->txn.rw;
			assert(*txn);
		}
		return lmdb_error(ret);
	}

	/* Get an active RO txn and return it. */
	int ret = MDB_SUCCESS;
	if (!env->txn.ro) { //:unlikely
		ret = txn_get_noresize(env, MDB_RDONLY, &env->txn.ro);
	} else if (!env->txn.ro_active) {
		ret = txn_get_noresize(env, FLAG_RENEW, &env->txn.ro);
	}
	if (ret != MDB_SUCCESS) {
		return lmdb_error(ret);
	}
	env->txn.ro_active = true;
	*txn = env->txn.ro;
	assert(*txn);
	return kr_ok();
}

static int cdb_commit(knot_db_t *db, struct kr_cdb_stats *stats)
{
	struct lmdb_env *env = db;
	int ret = kr_ok();
	if (env->txn.rw) {
		stats->commit++;
		ret = lmdb_error(mdb_txn_commit(env->txn.rw));
		env->txn.rw = NULL; /* the transaction got freed even in case of errors */
	} else if (env->txn.ro && env->txn.ro_active) {
		mdb_txn_reset(env->txn.ro);
		env->txn.ro_active = false;
		env->txn.ro_curs_active = false;
	}
	return ret;
}

/** Obtain a read-only cursor (and a read-only transaction). */
static int txn_curs_get(struct lmdb_env *env, MDB_cursor **curs, struct kr_cdb_stats *stats)
{
	assert(env && curs);
	if (env->txn.ro_curs_active) {
		goto success;
	}
	/* Only in a read-only txn; TODO: it's a bit messy/coupled */
	if (env->txn.rw) {
		int ret = cdb_commit(env, stats);
		if (ret) return ret;
	}
	MDB_txn *txn = NULL;
	int ret = txn_get(env, &txn, true);
	if (ret) return ret;

	if (env->txn.ro_curs) {
		ret = mdb_cursor_renew(txn, env->txn.ro_curs);
	} else {
		ret = mdb_cursor_open(txn, env->dbi, &env->txn.ro_curs);
	}
	if (ret) return ret;
	env->txn.ro_curs_active = true;
success:
	assert(env->txn.ro_curs_active && env->txn.ro && env->txn.ro_active
		&& !env->txn.rw);
	*curs = env->txn.ro_curs;
	assert(*curs);
	return kr_ok();
}

static void free_txn_ro(struct lmdb_env *env)
{
	if (env->txn.ro) {
		mdb_txn_abort(env->txn.ro);
		env->txn.ro = NULL;
	}
	if (env->txn.ro_curs) {
		mdb_cursor_close(env->txn.ro_curs);
		env->txn.ro_curs = NULL;
	}
}

/*! \brief Close the database. */
static void cdb_close_env(struct lmdb_env *env, struct kr_cdb_stats *stats)
{
	assert(env && env->env);

	/* Get rid of any transactions. */
	cdb_commit(env, stats);
	free_txn_ro(env);

	mdb_env_sync(env->env, 1);
	stats->close++;
	mdb_dbi_close(env->env, env->dbi);
	mdb_env_close(env->env);
	memset(env, 0, sizeof(*env));
}

/*! \brief Open database environment. */
static int cdb_open_env(struct lmdb_env *env, unsigned flags, const char *path, size_t mapsize, struct kr_cdb_stats *stats)
{
	int ret = mkdir(path, LMDB_DIR_MODE);
	if (ret == -1 && errno != EEXIST) {
		return kr_error(errno);
	}

	MDB_env *mdb_env = NULL;
	stats->open++;
	ret = mdb_env_create(&mdb_env);
	if (ret != MDB_SUCCESS) {
		return lmdb_error(ret);
	}

	ret = set_mapsize(mdb_env, mapsize);
	if (ret != 0) {
		stats->close++;
		mdb_env_close(mdb_env);
		return ret;
	}

	ret = mdb_env_open(mdb_env, path, flags, LMDB_FILE_MODE);
	if (ret != MDB_SUCCESS) {
		stats->close++;
		mdb_env_close(mdb_env);
		return lmdb_error(ret);
	}

	/* Keep the environment pointer. */
	env->env = mdb_env;
	env->mapsize = mapsize;
	return 0;
}

static int cdb_open(struct lmdb_env *env, const char *path, size_t mapsize,
		struct kr_cdb_stats *stats)
{
	/* Cache doesn't require durability, we can be
	 * loose with the requirements as a tradeoff for speed. */
	const unsigned flags = MDB_WRITEMAP | MDB_MAPASYNC | MDB_NOTLS;
	int ret = cdb_open_env(env, flags, path, mapsize, stats);
	if (ret != 0) {
		return ret;
	}

	/* Open the database. */
	MDB_txn *txn = NULL;
	ret = mdb_txn_begin(env->env, NULL, 0, &txn);
	if (ret != MDB_SUCCESS) {
		stats->close++;
		mdb_env_close(env->env);
		return lmdb_error(ret);
	}

	ret = mdb_dbi_open(txn, NULL, 0, &env->dbi);
	if (ret != MDB_SUCCESS) {
		mdb_txn_abort(txn);
		stats->close++;
		mdb_env_close(env->env);
		return lmdb_error(ret);
	}

#if !defined(__MACOSX__) && !(defined(__APPLE__) && defined(__MACH__))
	auto_free char *mdb_datafile = kr_strcatdup(2, path, "/data.mdb");
	int fd = open(mdb_datafile, O_RDWR);
	if (fd == -1) {
		mdb_txn_abort(txn);
		stats->close++;
		mdb_env_close(env->env);
		return kr_error(errno);
	}

	ret = posix_fallocate(fd, 0, mapsize);
	if (ret == EINVAL) {
		/* POSIX says this can happen when the feature isn't supported by the FS.
		 * We haven't seen this happen on Linux+glibc but it was reported on FreeBSD.*/
		kr_log_info("[cache] space pre-allocation failed and ignored; "
				"your (file)system probably doesn't support it.\n");
	} else if (ret != 0) {
		mdb_txn_abort(txn);
		stats->close++;
		mdb_env_close(env->env);
		close(fd);
		return kr_error(ret);
	}
	close(fd);
#endif

	stats->commit++;
	ret = mdb_txn_commit(txn);
	if (ret != MDB_SUCCESS) {
		stats->close++;
		mdb_env_close(env->env);
		return lmdb_error(ret);
	}

	return 0;
}

static int cdb_init(knot_db_t **db, struct kr_cdb_stats *stats,
		struct kr_cdb_opts *opts, knot_mm_t *pool)
{
	if (!db || !stats || !opts) {
		return kr_error(EINVAL);
	}

	struct lmdb_env *env = malloc(sizeof(*env));
	if (!env) {
		return kr_error(ENOMEM);
	}
	memset(env, 0, sizeof(struct lmdb_env));

	/* Clear stale lockfiles. */
	auto_free char *lockfile = kr_strcatdup(2, opts->path, "/.cachelock");
	if (lockfile) {
		if (unlink(lockfile) == 0) {
			kr_log_info("[cache] cleared stale lockfile '%s'\n", lockfile);
		} else if (errno != ENOENT) {
			kr_log_info("[cache] failed to clear stale lockfile '%s': %s\n", lockfile,
				    strerror(errno));
		}
	}

	/* Open the database. */
	int ret = cdb_open(env, opts->path, opts->maxsize, stats);
	if (ret != 0) {
		free(env);
		return ret;
	}

	*db = env;
	return 0;
}

static void cdb_deinit(knot_db_t *db, struct kr_cdb_stats *stats)
{
	struct lmdb_env *env = db;
	cdb_close_env(env, stats);
	free(env);
}

static int cdb_count(knot_db_t *db, struct kr_cdb_stats *stats)
{
	struct lmdb_env *env = db;
	MDB_txn *txn = NULL;
	int ret = txn_get(env, &txn, true);
	if (ret != 0) {
		return ret;
	}

	MDB_stat stat;
	stats->count++;
	ret = mdb_stat(txn, env->dbi, &stat);

	return (ret == MDB_SUCCESS) ? stat.ms_entries : lmdb_error(ret);
}

static int cdb_clear(knot_db_t *db, struct kr_cdb_stats *stats)
{
	struct lmdb_env *env = db;
	stats->clear++;
	/* First try mdb_drop() to clear the DB; this may fail with ENOSPC. */
	/* If we didn't do this, explicit cache.clear() ran on an instance
	 * would lead to the instance detaching from the cache of others,
	 * until they reopened cache explicitly or cleared it for some reason.
	 */
	{
		MDB_txn *txn = NULL;
		int ret = txn_get(env, &txn, false);
		if (ret == kr_ok()) {
			ret = lmdb_error(mdb_drop(txn, env->dbi, 0));
			if (ret == kr_ok()) {
				ret = cdb_commit(db, stats);
			}
			if (ret == kr_ok()) {
				return ret;
			}
		}
		kr_log_info("[cache] clearing error, falling back\n");
	}

	/* We are about to switch to a different file, so end all txns, to be sure. */
	(void) cdb_commit(db, stats);
	free_txn_ro(db);

	/* Since there is no guarantee that there will be free
	 * pages to hold whole dirtied db for transaction-safe clear,
	 * we simply remove the database files and reopen.
	 * We can afford this since other readers will continue to read
	 * from removed file, but will reopen when encountering next
	 * error. */
	mdb_filehandle_t fd = -1;
	int ret = mdb_env_get_fd(env->env, &fd);
	if (ret != MDB_SUCCESS) {
		return lmdb_error(ret);
	}
	const char *path = NULL;
	ret = mdb_env_get_path(env->env, &path);
	if (ret != MDB_SUCCESS) {
		return lmdb_error(ret);
	}

	auto_free char *mdb_datafile = kr_strcatdup(2, path, "/data.mdb");
	auto_free char *mdb_lockfile = kr_strcatdup(2, path, "/lock.mdb");
	auto_free char *lockfile = kr_strcatdup(2, path, "/.cachelock");
	if (!mdb_datafile || !mdb_lockfile || !lockfile) {
		return kr_error(ENOMEM);
	}
	/* Find if we get a lock on lockfile. */
	ret = open(lockfile, O_CREAT|O_EXCL|O_RDONLY, S_IRUSR);
	if (ret == -1) {
		kr_log_error("[cache] clearing failed to get ./.cachelock; retry later\n");
		/* As we're out of space (almost certainly - mdb_drop didn't work),
		 * we will retry on the next failing write operation. */
		return kr_error(errno);
	}
	close(ret);
	/* We acquired lockfile.  Now find whether *.mdb are what we have open now. */
	struct stat old_stat, new_stat;
	if (fstat(fd, &new_stat) || stat(mdb_datafile, &old_stat)) {
		ret = errno;
		unlink(lockfile);
		return kr_error(ret);
	}
	/* Remove underlying files only if current open environment
	 * points to file on the disk. Otherwise just reopen as someone
	 * else has already removed the files.
	 */
	if (old_stat.st_dev == new_stat.st_dev && old_stat.st_ino == new_stat.st_ino) {
		kr_log_verbose("[cache] clear: identical files, unlinking\n");
		// coverity[toctou]
		unlink(mdb_datafile);
		unlink(mdb_lockfile);
	} else
		kr_log_verbose("[cache] clear: not identical files, reopening\n");
	/* Keep copy as it points to current handle internals. */
	auto_free char *path_copy = strdup(path);
	size_t mapsize = env->mapsize;
	cdb_close_env(env, stats);
	ret = cdb_open(env, path_copy, mapsize, stats);
	/* Environment updated, release lockfile. */
	unlink(lockfile);
	return ret;
}

static int cdb_readv(knot_db_t *db, struct kr_cdb_stats *stats,
		const knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	struct lmdb_env *env = db;
	MDB_txn *txn = NULL;
	int ret = txn_get(env, &txn, true);
	if (ret) {
		return ret;
	}

	for (int i = 0; i < maxcount; ++i) {
		/* Convert key structs */
		MDB_val _key = val_knot2mdb(key[i]);
		MDB_val _val = val_knot2mdb(val[i]);
		stats->read++;
		ret = mdb_get(txn, env->dbi, &_key, &_val);
		if (ret != MDB_SUCCESS) {
			if (ret == MDB_NOTFOUND)
				stats->read_miss++;
			ret = lmdb_error(ret);
			if (ret == kr_error(ENOSPC)) {
				/* we're likely to be forced to cache clear anyway */
				ret = kr_error(ENOENT);
			}
			return ret;
		}
		/* Update the result. */
		val[i] = val_mdb2knot(_val);
	}
	return kr_ok();
}

static int cdb_write(struct lmdb_env *env, MDB_txn **txn, const knot_db_val_t *key,
			knot_db_val_t *val, unsigned flags,
			struct kr_cdb_stats *stats)
{
	/* Convert key structs and write */
	MDB_val _key = val_knot2mdb(*key);
	MDB_val _val = val_knot2mdb(*val);
	stats->write++;
	int ret = mdb_put(*txn, env->dbi, &_key, &_val, flags);

	/* Try to recover from doing too much writing in a single transaction. */
	if (ret == MDB_TXN_FULL) {
		ret = cdb_commit(env, stats);
		if (ret) {
			ret = txn_get(env, txn, false);
		}
		if (ret) {
			stats->write++;
			ret = mdb_put(*txn, env->dbi, &_key, &_val, flags);
		}
	}
	if (ret != MDB_SUCCESS) {
		return lmdb_error(ret);
	}

	/* Update the result. */
	val->data = _val.mv_data;
	val->len = _val.mv_size;
	return kr_ok();
}

static int cdb_writev(knot_db_t *db, struct kr_cdb_stats *stats,
		const knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	struct lmdb_env *env = db;
	MDB_txn *txn = NULL;
	int ret = txn_get(env, &txn, false);

	for (int i = 0; ret == kr_ok() && i < maxcount; ++i) {
		/* This is LMDB specific optimisation,
		 * if caller specifies value with NULL data and non-zero length,
		 * LMDB will preallocate the entry for caller and leave write
		 * transaction open, caller is responsible for syncing thus committing transaction.
		 */
		unsigned mdb_flags = 0;
		if (val[i].len > 0 && val[i].data == NULL) {
			mdb_flags |= MDB_RESERVE;
		}
		ret = cdb_write(env, &txn, &key[i], &val[i], mdb_flags, stats);
	}

	return ret;
}

static int cdb_remove(knot_db_t *db, struct kr_cdb_stats *stats,
		knot_db_val_t keys[], int maxcount)
{
	struct lmdb_env *env = db;
	MDB_txn *txn = NULL;
	int ret = txn_get(env, &txn, false);
	int deleted = 0;

	for (int i = 0; ret == kr_ok() && i < maxcount; ++i) {
		MDB_val _key = val_knot2mdb(keys[i]);
		MDB_val val = { 0, NULL };
		stats->remove++;
		ret = lmdb_error(mdb_del(txn, env->dbi, &_key, &val));
		if (ret == kr_ok())
			deleted++;
		else if (ret == KNOT_ENOENT) {
			stats->remove_miss++;
			ret = kr_ok();  /* skip over non-existing entries */
		}
	}

	return ret < 0 ? ret : deleted;
}

static int cdb_match(knot_db_t *db, struct kr_cdb_stats *stats,
		knot_db_val_t *key, knot_db_val_t keyval[][2], int maxcount)
{
	struct lmdb_env *env = db;
	MDB_txn *txn = NULL;
	int ret = txn_get(env, &txn, true);
	if (ret != 0) {
		return ret;
	}

	/* LATER(optim.): use txn_curs_get() instead, to save resources. */
	MDB_cursor *cur = NULL;
	ret = mdb_cursor_open(txn, env->dbi, &cur);
	if (ret != 0) {
		return lmdb_error(ret);
	}

	MDB_val cur_key = val_knot2mdb(*key);
	MDB_val cur_val = { 0, NULL };
	stats->match++;
	ret = mdb_cursor_get(cur, &cur_key, &cur_val, MDB_SET_RANGE);
	if (ret != MDB_SUCCESS) {
		mdb_cursor_close(cur);
		return lmdb_error(ret);
	}

	int results = 0;
	while (ret == MDB_SUCCESS) {
		/* Retrieve current key and compare with prefix */
		if (cur_key.mv_size < key->len || memcmp(cur_key.mv_data, key->data, key->len) != 0) {
			break;
		}
		/* Add to result set */
		if (results < maxcount) {
			keyval[results][0] = val_mdb2knot(cur_key);
			keyval[results][1] = val_mdb2knot(cur_val);
			++results;
		} else {
			break;
		}
		stats->match++;
		ret = mdb_cursor_get(cur, &cur_key, &cur_val, MDB_NEXT);
	}
	if (results == 0)
		stats->match_miss++;


	mdb_cursor_close(cur);
	return results;
}


static int cdb_read_leq(knot_db_t *env, struct kr_cdb_stats *stats,
		knot_db_val_t *key, knot_db_val_t *val)
{
	assert(env && key && key->data && val);
	MDB_cursor *curs = NULL;
	int ret = txn_curs_get(env, &curs, stats);
	if (ret) return ret;

	MDB_val key2_m = val_knot2mdb(*key);
	MDB_val val2_m = { 0, NULL };
	stats->read_leq++;
	ret = mdb_cursor_get(curs, &key2_m, &val2_m, MDB_SET_RANGE);
	if (ret) {
		stats->read_leq_miss++;
		return lmdb_error(ret);
	}
	/* test for equality //:unlikely */
	if (key2_m.mv_size == key->len
	    && memcmp(key2_m.mv_data, key->data, key->len) == 0) {
		ret = 0; /* equality */
		goto success;
	}
	stats->read_leq_miss++;

	/* we must be greater than key; do one step to smaller */
	stats->read_leq++;
	ret = mdb_cursor_get(curs, &key2_m, &val2_m, MDB_PREV);
	if (ret) {
		stats->read_leq_miss++;
		return lmdb_error(ret);
	}
	ret = 1;
success:
	/* finalize the output */
	*key = val_mdb2knot(key2_m);
	*val = val_mdb2knot(val2_m);
	return ret;
}


const struct kr_cdb_api *kr_cdb_lmdb(void)
{
	static const struct kr_cdb_api api = {
		"lmdb",
		cdb_init, cdb_deinit, cdb_count, cdb_clear, cdb_commit,
		cdb_readv, cdb_writev, cdb_remove,
		cdb_match,
		cdb_read_leq
	};

	return &api;
}
