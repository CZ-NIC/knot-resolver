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
#include "lib/cache/impl.h"
#include "lib/utils.h"


/* Defines */
#define LMDB_DIR_MODE   0770
#define LMDB_FILE_MODE  0660

/* TODO: we rely on mirrors of these two structs not changing layout
 * in libknot and knot resolver! */
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

	/* Cached part of struct stat for data.mdb. */
	dev_t st_dev;
	ino_t st_ino;
	off_t st_size;
	const char *mdb_data_path; /**< path to data.mdb, for convenience */
};

struct libknot_lmdb_env {
	bool shared;
	unsigned dbi;
	void *env;
	knot_mm_t *pool;
};


static int cdb_commit(knot_db_t *db, struct kr_cdb_stats *stats);

/** @brief Convert LMDB error code. */
static int lmdb_error(int error)
{
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

/** Refresh mapsize value from file, including env->mapsize.
 * It's much lighter than reopen_env(). */
static int refresh_mapsize(struct lmdb_env *env)
{
	int ret = cdb_commit(env, NULL);
	if (!ret) ret = lmdb_error(mdb_env_set_mapsize(env->env, 0));
	if (ret) return ret;

	MDB_envinfo info;
	ret = lmdb_error(mdb_env_info(env->env, &info));
	if (ret) return ret;

	env->mapsize = info.me_mapsize;
	if (env->mapsize != env->st_size) {
		kr_log_info("[cache] suspicious size of cache file '%s'"
				": file size %zu != LMDB map size %zu\n",
				env->mdb_data_path, (size_t)env->st_size, env->mapsize);
	}
	return kr_ok();
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
		ret = refresh_mapsize(env);
		if (ret == 0)
			goto retry;
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
		if (stats) stats->commit++;
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
	if (ret) return lmdb_error(ret);
	env->txn.ro_curs_active = true;
success:
	assert(env->txn.ro_curs_active && env->txn.ro && env->txn.ro_active
		&& !env->txn.rw);
	*curs = env->txn.ro_curs;
	assert(*curs);
	return kr_ok();
}

static void txn_free_ro(struct lmdb_env *env)
{
	if (env->txn.ro_curs) {
		mdb_cursor_close(env->txn.ro_curs);
		env->txn.ro_curs = NULL;
	}
	if (env->txn.ro) {
		mdb_txn_abort(env->txn.ro);
		env->txn.ro = NULL;
	}
}

/** Abort all transactions.
 *
 * This is useful after an error happens, as those (always?) require abortion.
 * It's possible that _reset() would suffice and marking cursor inactive,
 * but these errors should be rare so let's close them completely. */
static void txn_abort(struct lmdb_env *env)
{
	txn_free_ro(env);
	if (env->txn.rw) {
		mdb_txn_abort(env->txn.rw);
		env->txn.rw = NULL; /* the transaction got freed even in case of errors */
	}
}

/*! \brief Close the database. */
static void cdb_close_env(struct lmdb_env *env, struct kr_cdb_stats *stats)
{
	assert(env && env->env);

	/* Get rid of any transactions. */
	txn_free_ro(env);
	cdb_commit(env, stats);

	mdb_env_sync(env->env, 1);
	stats->close++;
	mdb_dbi_close(env->env, env->dbi);
	mdb_env_close(env->env);
	free_const(env->mdb_data_path);
	memset(env, 0, sizeof(*env));
}

/** We assume that *env is zeroed and we return it zeroed on errors. */
static int cdb_open_env(struct lmdb_env *env, const char *path, const size_t mapsize,
		struct kr_cdb_stats *stats)
{
	int ret = mkdir(path, LMDB_DIR_MODE);
	if (ret && errno != EEXIST) return kr_error(errno);

	stats->open++;
	ret = mdb_env_create(&env->env);
	if (ret != MDB_SUCCESS) return lmdb_error(ret);

	env->mdb_data_path = kr_absolutize_path(path, "data.mdb");
	if (!env->mdb_data_path) {
		ret = ENOMEM;
		goto error_sys;
	}

	/* Set map size, rounded to page size. */
	errno = 0;
	const long pagesize = sysconf(_SC_PAGESIZE);
	if (errno) {
		ret = errno;
		goto error_sys;
	}

	const bool size_requested = mapsize;
	if (size_requested) {
		env->mapsize = (mapsize / pagesize) * pagesize;
		ret = mdb_env_set_mapsize(env->env, env->mapsize);
		if (ret != MDB_SUCCESS) goto error_mdb;
	}

	/* Cache doesn't require durability, we can be
	 * loose with the requirements as a tradeoff for speed. */
	const unsigned flags = MDB_WRITEMAP | MDB_MAPASYNC | MDB_NOTLS;
	ret = mdb_env_open(env->env, path, flags, LMDB_FILE_MODE);
	if (ret != MDB_SUCCESS) goto error_mdb;

	mdb_filehandle_t fd = -1;
	ret = mdb_env_get_fd(env->env, &fd);
	if (ret != MDB_SUCCESS) goto error_mdb;

	struct stat st;
	if (fstat(fd, &st)) {
		ret = errno;
		goto error_sys;
	}
	env->st_dev = st.st_dev;
	env->st_ino = st.st_ino;
	env->st_size = st.st_size;

	/* Get the real mapsize.  Shrinking can be restricted, etc.
	 * Unfortunately this is only reliable when not setting the size explicitly. */
	if (!size_requested) {
		ret = refresh_mapsize(env);
		if (ret) goto error_sys;
	}

	/* Open the database. */
	MDB_txn *txn = NULL;
	ret = mdb_txn_begin(env->env, NULL, 0, &txn);
	if (ret != MDB_SUCCESS) goto error_mdb;

	ret = mdb_dbi_open(txn, NULL, 0, &env->dbi);
	if (ret != MDB_SUCCESS) {
		mdb_txn_abort(txn);
		goto error_mdb;
	}

#if !defined(__MACOSX__) && !(defined(__APPLE__) && defined(__MACH__))
	if (size_requested) {
		ret = posix_fallocate(fd, 0, MAX(env->mapsize, env->st_size));
	} else {
		ret = 0;
	}
	if (ret == EINVAL) {
		/* POSIX says this can happen when the feature isn't supported by the FS.
		 * We haven't seen this happen on Linux+glibc but it was reported on FreeBSD.*/
		kr_log_info("[cache] space pre-allocation failed and ignored; "
				"your (file)system probably doesn't support it.\n");
	} else if (ret != 0) {
		mdb_txn_abort(txn);
		goto error_sys;
	}
#endif

	stats->commit++;
	ret = mdb_txn_commit(txn);
	if (ret != MDB_SUCCESS) goto error_mdb;

	return kr_ok();

error_mdb:
	ret = lmdb_error(ret);
error_sys:
	free_const(env->mdb_data_path);
	stats->close++;
	mdb_env_close(env->env);
	memset(env, 0, sizeof(*env));
	return kr_error(ret);
}

static int cdb_init(knot_db_t **db, struct kr_cdb_stats *stats,
		struct kr_cdb_opts *opts, knot_mm_t *pool)
{
	if (!db || !stats || !opts) {
		return kr_error(EINVAL);
	}

	/* Open the database. */
	struct lmdb_env *env = calloc(1, sizeof(*env));
	if (!env) {
		return kr_error(ENOMEM);
	}
	int ret = cdb_open_env(env, opts->path, opts->maxsize, stats);
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

	if (ret == MDB_SUCCESS) {
		return stat.ms_entries;
	} else {
		txn_abort(env);
		return lmdb_error(ret);
	}
}

static int reopen_env(struct lmdb_env *env, struct kr_cdb_stats *stats, const size_t mapsize)
{
	/* Keep copy as it points to current handle internals. */
	const char *path;
	int ret = mdb_env_get_path(env->env, &path);
	if (ret != MDB_SUCCESS) {
		return lmdb_error(ret);
	}
	auto_free char *path_copy = strdup(path);
	cdb_close_env(env, stats);
	return cdb_open_env(env, path_copy, mapsize, stats);
}

static int cdb_check_health(knot_db_t *db, struct kr_cdb_stats *stats)
{
	struct lmdb_env *env = db;

	struct stat st;
	if (stat(env->mdb_data_path, &st)) {
		int ret = errno;
		return kr_error(ret);
	}

	if (st.st_dev != env->st_dev || st.st_ino != env->st_ino) {
		kr_log_verbose("[cache] cache file has been replaced, reopening\n");
		int ret = reopen_env(env, stats, 0); // we accept mapsize from the new file
		return ret == 0 ? 1 : ret;
	}

	/* Cache check through file size works OK without reopening,
	 * contrary to methods based on mdb_env_info(). */
	if (st.st_size == env->st_size)
		return kr_ok();
	kr_log_info("[cache] detected size change (by another instance?) of file '%s'"
			": file size %zu -> file size %zu\n",
			env->mdb_data_path, (size_t)env->st_size, (size_t)st.st_size);
	env->st_size = st.st_size; // avoid retrying in cycle even if we fail
	return refresh_mapsize(env);
}

/** Obtain exclusive (advisory) lock by creating a file, returning FD or negative kr_error().
 * The lock is auto-released by OS in case the process finishes in any way (file remains). */
static int lockfile_get(const char *path)
{
	assert(path);
	const int fd = open(path, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if (fd < 0)
		return kr_error(errno);

	struct flock lock_info;
	memset(&lock_info, 0, sizeof(lock_info));
	lock_info.l_type = F_WRLCK;
	lock_info.l_whence = SEEK_SET;
	lock_info.l_start = 0;
	lock_info.l_len = 1; // it's OK for locks to extend beyond the end of the file
	int err;
	do {
		err = fcntl(fd, F_SETLK, &lock_info);
	} while (err == -1 && errno == EINTR);
	if (err) {
		close(fd);
		return kr_error(errno);
	}
	return fd;
}

/** Release and remove lockfile created by lockfile_get().  Return kr_error(). */
static int lockfile_release(const char *path, int fd)
{
	assert(path && fd > 0); // fd == 0 is surely a mistake, in our case at least
	int err = close(fd);
	return kr_error(errno);
}

static int cdb_clear(knot_db_t *db, struct kr_cdb_stats *stats)
{
	struct lmdb_env *env = db;
	stats->clear++;
	/* First try mdb_drop() to clear the DB; this may fail with ENOSPC. */
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
	/* Fallback: we'll remove the database files and reopen.
	 * Other instances can continue to use the removed lmdb,
	 * though it's best for them to reopen soon. */

	/* We are about to switch to a different file, so end all txns, to be sure. */
	txn_free_ro(db);
	(void) cdb_commit(db, stats);

	const char *path = NULL;
	int ret = mdb_env_get_path(env->env, &path);
	if (ret != MDB_SUCCESS) {
		return lmdb_error(ret);
	}
	auto_free char *mdb_lockfile = kr_strcatdup(2, path, "/lock.mdb");
	auto_free char *lockfile = kr_strcatdup(2, path, "/krcachelock");
	if (!mdb_lockfile || !lockfile) {
		return kr_error(ENOMEM);
	}

	/* Find if we get a lock on lockfile. */
	const int lockfile_fd = lockfile_get(lockfile);
	if (lockfile_fd < 0) {
		kr_log_error("[cache] clearing failed to get ./krcachelock (%s); retry later\n",
				kr_strerror(lockfile_fd));
		/* As we're out of space (almost certainly - mdb_drop didn't work),
		 * we will retry on the next failing write operation. */
		return kr_error(EAGAIN);
	}

	/* We acquired lockfile.  Now find whether *.mdb are what we have open now.
	 * If they are not we don't want to remove them; most likely they have been
	 * cleaned by another instance. */
	ret = cdb_check_health(db, stats);
	if (ret != 0) {
		if (ret == 1) // file changed and reopened successfuly
			ret = kr_ok();
		// else pass some other error
	} else {
		kr_log_verbose("[cache] clear: identical files, unlinking\n");
		// coverity[toctou]
		unlink(env->mdb_data_path);
		unlink(mdb_lockfile);
		ret = reopen_env(env, stats, env->mapsize);
	}

	/* Environment updated, release lockfile. */
	int lrerr = lockfile_release(lockfile, lockfile_fd);
	if (lrerr) {
		kr_log_error("[cache] failed to release ./krcachelock: %s\n",
				kr_strerror(lrerr));
	}
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
			if (ret == MDB_NOTFOUND) {
				stats->read_miss++;
			} else {
				txn_abort(env);
			}
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

	/* We don't try to recover from MDB_TXN_FULL. */
	if (ret != MDB_SUCCESS) {
		txn_abort(env);
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
		} else {
			txn_abort(env);
			break;
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
		txn_abort(env);
		return lmdb_error(ret);
	}

	MDB_val cur_key = val_knot2mdb(*key);
	MDB_val cur_val = { 0, NULL };
	stats->match++;
	ret = mdb_cursor_get(cur, &cur_key, &cur_val, MDB_SET_RANGE);
	if (ret != MDB_SUCCESS) {
		mdb_cursor_close(cur);
		if (ret != MDB_NOTFOUND) {
			txn_abort(env);
		}
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

	mdb_cursor_close(cur);
	if (ret != MDB_SUCCESS && ret != MDB_NOTFOUND) {
		txn_abort(env);
		return lmdb_error(ret);
	} else if (results == 0) {
		stats->match_miss++;
	}
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
	if (ret) goto failure;
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
	if (ret) goto failure;
	ret = 1;
success:
	/* finalize the output */
	*key = val_mdb2knot(key2_m);
	*val = val_mdb2knot(val2_m);
	return ret;
failure:
	if (ret == MDB_NOTFOUND) {
		stats->read_leq_miss++;
	} else {
		txn_abort(env);
	}
	return lmdb_error(ret);
}

static double cdb_usage(knot_db_t *db)
{
	const size_t db_size = knot_db_lmdb_get_mapsize(db);
	const size_t db_usage_abs = knot_db_lmdb_get_usage(db);
	const double db_usage = (double)db_usage_abs / db_size * 100.0;

	return db_usage;
}

static size_t cdb_get_maxsize(knot_db_t *db)
{
	struct lmdb_env *env = db;
	return env->mapsize;
}

/** Conversion between knot and lmdb structs. */
knot_db_t *knot_db_t_kres2libknot(const knot_db_t * db)
{
	/* this is struct lmdb_env as in resolver/cdb_lmdb.c */
	const struct lmdb_env *kres_db = db;
	struct libknot_lmdb_env *libknot_db = malloc(sizeof(*libknot_db));
	if (libknot_db != NULL) {
		libknot_db->shared = false;
		libknot_db->pool = NULL;
		libknot_db->env = kres_db->env;
		libknot_db->dbi = kres_db->dbi;
	}
	return libknot_db;
}

const struct kr_cdb_api *kr_cdb_lmdb(void)
{
	static const struct kr_cdb_api api = {
		"lmdb",
		cdb_init, cdb_deinit, cdb_count, cdb_clear, cdb_commit,
		cdb_readv, cdb_writev, cdb_remove,
		cdb_match,
		cdb_read_leq,
		cdb_usage,
		cdb_get_maxsize,
		cdb_check_health,
	};

	return &api;
}
