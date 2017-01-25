/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <lmdb.h>

#include "contrib/cleanup.h"
#include "lib/cdb_lmdb.h"
#include "lib/cache.h"
#include "lib/utils.h"


/* Defines */
#define LMDB_DIR_MODE   0770
#define LMDB_FILE_MODE  0660

struct lmdb_env
{
	size_t mapsize;
	MDB_dbi dbi;
	MDB_env *env;
	MDB_txn *rdtxn;
	MDB_txn *wrtxn;
};

/** @brief Convert LMDB error code. */
static int lmdb_error(int error)
{
	switch (error) {
	case MDB_SUCCESS:  return 0;
	case MDB_NOTFOUND: return kr_error(ENOENT);
	case MDB_MAP_FULL: /* Fallthrough */
	case MDB_TXN_FULL: /* Fallthrough */
	case ENOSPC:
		return kr_error(ENOSPC);
	default:
		return -abs(error);
	}
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

static int txn_begin(struct lmdb_env *env, MDB_txn **txn, bool rdonly)
{
	/* Always barrier for write transaction. */
	assert(env && txn);
	if (env->wrtxn) {
		mdb_txn_abort(env->wrtxn);
		env->wrtxn = NULL;
	}
	/* Renew pending read-only transaction 
	 * or abort it to clear reader slot before writing. */
	if (env->rdtxn) {
		if (rdonly) {
			*txn = env->rdtxn;
			env->rdtxn = NULL;
			return 0;
		} else {
			mdb_txn_abort(env->rdtxn);
			env->rdtxn = NULL;
		}
	}
	unsigned flags = rdonly ? MDB_RDONLY : 0;
	return lmdb_error(mdb_txn_begin(env->env, NULL, flags, txn));
}

static int txn_end(struct lmdb_env *env, MDB_txn *txn)
{
	assert(env && txn);
	/* Cache read transactions */
	if (!env->rdtxn) {
		env->rdtxn = txn;
	} else {
		mdb_txn_abort(txn);
	}
	return 0;
}

static int cdb_sync(knot_db_t *db)
{
	struct lmdb_env *env = db;
	int ret = 0;
	if (env->wrtxn) {
		ret = lmdb_error(mdb_txn_commit(env->wrtxn));
		env->wrtxn = NULL; /* In-flight transaction is committed. */
	}
	if (env->rdtxn) {
		mdb_txn_abort(env->rdtxn);
		env->rdtxn = NULL;
	}
	return ret;
}

/*! \brief Close the database. */
static void cdb_close_env(struct lmdb_env *env)
{
	assert(env && env->env);
	cdb_sync(env);
	mdb_env_sync(env->env, 1);
	mdb_dbi_close(env->env, env->dbi);
	mdb_env_close(env->env);
	memset(env, 0, sizeof(*env));
}

/*! \brief Open database environment. */
static int cdb_open_env(struct lmdb_env *env, unsigned flags, const char *path, size_t mapsize)
{
	int ret = mkdir(path, LMDB_DIR_MODE);
	if (ret == -1 && errno != EEXIST) {
		return kr_error(errno);
	}

	MDB_env *mdb_env = NULL;
	ret = mdb_env_create(&mdb_env);
	if (ret != MDB_SUCCESS) {
		return lmdb_error(ret);
	}

	ret = set_mapsize(mdb_env, mapsize);
	if (ret != 0) {
		mdb_env_close(mdb_env);
		return ret;
	}

	ret = mdb_env_open(mdb_env, path, flags, LMDB_FILE_MODE);
	if (ret != MDB_SUCCESS) {
		mdb_env_close(mdb_env);
		return lmdb_error(ret);
	}

	/* Keep the environment pointer. */
	env->env = mdb_env;
	env->mapsize = mapsize;
	return 0;
}

static int cdb_open(struct lmdb_env *env, const char *path, size_t mapsize)
{
	/* Cache doesn't require durability, we can be
	 * loose with the requirements as a tradeoff for speed. */
	const unsigned flags = MDB_WRITEMAP | MDB_MAPASYNC | MDB_NOTLS;
	int ret = cdb_open_env(env, flags, path, mapsize);
	if (ret != 0) {
		return ret;
	}

	/* Open the database. */
	MDB_txn *txn = NULL;
	ret = mdb_txn_begin(env->env, NULL, 0, &txn);
	if (ret != MDB_SUCCESS) {
		mdb_env_close(env->env);
		return lmdb_error(ret);
	}

	ret = mdb_dbi_open(txn, NULL, 0, &env->dbi);
	if (ret != MDB_SUCCESS) {
		mdb_txn_abort(txn);
		mdb_env_close(env->env);
		return lmdb_error(ret);
	}

	ret = mdb_txn_commit(txn);
	if (ret != MDB_SUCCESS) {
		mdb_env_close(env->env);
		return lmdb_error(ret);
	}

	return 0;
}

static int cdb_init(knot_db_t **db, struct kr_cdb_opts *opts, knot_mm_t *pool)
{
	if (!db || !opts) {
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
			kr_log_info("[system] cache: cleared stale lockfile '%s'\n", lockfile);
		} else if (errno != ENOENT) {
			kr_log_info("[system] cache: failed to clear stale lockfile '%s': %s\n", lockfile,
				    strerror(errno));
		}
	}

	/* Open the database. */
	int ret = cdb_open(env, opts->path, opts->maxsize);
	if (ret != 0) {
		free(env);
		return ret;
	}

	*db = env;
	return 0;
}

static void cdb_deinit(knot_db_t *db)
{
	struct lmdb_env *env = db;
	cdb_close_env(env);
	free(env);
}

static int cdb_count(knot_db_t *db)
{
	struct lmdb_env *env = db;
	MDB_txn *txn = NULL;
	int ret = txn_begin(env, &txn, true);
	if (ret != 0) {
		return ret;
	}

	MDB_stat stat;
	ret = mdb_stat(txn, env->dbi, &stat);

	/* Always abort, serves as a checkpoint for in-flight transaction. */
	mdb_txn_abort(txn);
	return (ret == MDB_SUCCESS) ? stat.ms_entries : lmdb_error(ret);
}

static int cdb_clear(knot_db_t *db)
{
	struct lmdb_env *env = db;
	/* Always attempt to commit write transactions in-flight. */
	(void) cdb_sync(db);

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

	/* Check if the fd is pointing to the same file.
	 * man open(2):
         * > Portable programs that want to perform atomic file
         * > locking using a lockfile, and need to avoid reliance on
         * > NFS support for O_EXCL, can create a unique file on the
         * > same filesystem (e.g., incorporating hostname and PID),
         * > and use link(2) to make a link to the lockfile.  If
         * > link(2) returns 0, the lock is successful.  Otherwise,
         * > use stat(2) on the unique file to check if its link count
         * > has increased to 2, in which case the lock is also
         * > successful.
	 */

	auto_free char *mdb_datafile = kr_strcatdup(2, path, "/data.mdb");
	auto_free char *mdb_lockfile = kr_strcatdup(2, path, "/lock.mdb");
	auto_free char *lockfile = kr_strcatdup(2, path, "/.cachelock");
	if (!mdb_datafile || !mdb_lockfile || !lockfile) {
		return kr_error(ENOMEM);
	}
	ret = link(mdb_lockfile, lockfile);
	if (ret != 0) {
		int lock_errno = errno;
		struct stat lock_stat;
		ret = stat(lockfile, &lock_stat);
		if (ret != 0) {
			return kr_error(errno);
		}
		if (lock_stat.st_nlink != 2) {
			return kr_error(lock_errno);
		}
	}
	struct stat old_stat, new_stat;
	ret = fstat(fd, &new_stat);
	if (ret != 0) {
		unlink(lockfile);
		return kr_error(errno);
	}
	ret = stat(mdb_datafile, &old_stat);
	if (ret != 0) {
		unlink(lockfile);
		return kr_error(errno);
	}
	/* Remove underlying files only if current open environment
	 * points to file on the disk. Otherwise just reopen as someone
	 * else has already removed the files.
	 */
	if (old_stat.st_dev == new_stat.st_dev && old_stat.st_ino == new_stat.st_ino) {
		// coverity[toctou]
		unlink(mdb_datafile);
		unlink(mdb_lockfile);
	}
	/* Keep copy as it points to current handle internals. */
	auto_free char *path_copy = strdup(path);
	size_t mapsize = env->mapsize;
	cdb_close_env(env);
	ret = cdb_open(env, path_copy, mapsize);
	/* Environment updated, release lockfile. */
	unlink(lockfile);
	return ret;
}

static int cdb_readv(knot_db_t *db, knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	struct lmdb_env *env = db;
	MDB_txn *txn = NULL;
	int ret = txn_begin(env, &txn, true);
	if (ret != 0) {
		return ret;
	}

	for (int i = 0; i < maxcount; ++i) {
		/* Convert key structs */
		MDB_val _key = { .mv_size = key[i].len, .mv_data = key[i].data };
		MDB_val _val = { .mv_size = val[i].len, .mv_data = val[i].data };
		ret = mdb_get(txn, env->dbi, &_key, &_val);
		/* Update the result. */
		val[i].data = _val.mv_data;
		val[i].len = _val.mv_size;
	}

	txn_end(env, txn);
	return lmdb_error(ret);
}

static int cdb_write(struct lmdb_env *env, MDB_txn *txn, knot_db_val_t *key, knot_db_val_t *val, unsigned flags)
{
	/* Convert key structs and write */
	MDB_val _key = { key->len, key->data };
	MDB_val _val = { val->len, val->data };
	int ret = mdb_put(txn, env->dbi, &_key, &_val, flags);
	if (ret != MDB_SUCCESS) {
		return lmdb_error(ret);
	}
	/* Update the result. */
	val->data = _val.mv_data;
	val->len = _val.mv_size;
	return 0;
}

static int cdb_writev(knot_db_t *db, knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	struct lmdb_env *env = db;
	MDB_txn *txn = NULL;
	int ret = txn_begin(env, &txn, false);
	if (ret != 0) {
		return ret;
	}

	bool reserved = false;
	for (int i = 0; i < maxcount; ++i) {
		/* This is LMDB specific optimisation,
		 * if caller specifies value with NULL data and non-zero length,
		 * LMDB will preallocate the entry for caller and leave write
		 * transaction open, caller is responsible for syncing thus comitting transaction.
		 */
		unsigned mdb_flags = 0;
		if (val[i].len > 0 && val[i].data == NULL) {
			mdb_flags |= MDB_RESERVE;
			reserved = true;
		}
		ret = cdb_write(env, txn, &key[i], &val[i], mdb_flags);
		if (ret != 0) {
			mdb_txn_abort(txn);
			return ret;
		}
	}

	/* Leave transaction open if reserved. */
	if (reserved) {
		assert(env->wrtxn == NULL);
		env->wrtxn = txn;
	} else {
		ret = lmdb_error(mdb_txn_commit(txn));
	}
	return ret;
}

static int cdb_remove(knot_db_t *db, knot_db_val_t *key, int maxcount)
{
	struct lmdb_env *env = db;
	MDB_txn *txn = NULL;
	int ret = txn_begin(env, &txn, false);
	if (ret != 0) {
		return ret;
	}

	for (int i = 0; i < maxcount; ++i) {
		MDB_val _key = { key[i].len, key[i].data };
		MDB_val val = { 0, NULL };
		ret = mdb_del(txn, env->dbi, &_key, &val);
		if (ret != 0) {
			mdb_txn_abort(txn);
			return lmdb_error(ret);
		}
	}

	return lmdb_error(mdb_txn_commit(txn));
}

static int cdb_match(knot_db_t *db, knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	struct lmdb_env *env = db;
	MDB_txn *txn = NULL;
	int ret = txn_begin(env, &txn, true);
	if (ret != 0) {
		return ret;
	}

	/* Turn wildcard into prefix scan. */
	const uint8_t *endp = (const uint8_t *)key->data + (key->len - 2);
	if (key->len > 2 && endp[0] == '*' && endp[1] == '\0') {
		key->len -= 2; /* Skip '*' label */
	}

	MDB_cursor *cur = NULL;
	ret = mdb_cursor_open(txn, env->dbi, &cur);
	if (ret != 0) {
		mdb_txn_abort(txn);
		return lmdb_error(ret);
	}

	MDB_val cur_key = { key->len, key->data }, cur_val = { 0, NULL };
	ret = mdb_cursor_get(cur, &cur_key, &cur_val, MDB_SET_RANGE);
	if (ret != 0) {
		mdb_cursor_close(cur);
		mdb_txn_abort(txn);
		return lmdb_error(ret);
	}

	int results = 0;
	while (ret == 0) {
		/* Retrieve current key and compare with prefix */
		if (cur_key.mv_size < key->len || memcmp(cur_key.mv_data, key->data, key->len) != 0) {
			break;
		}
		/* Add to result set */
		if (results < maxcount) {
			val[results].len = cur_key.mv_size;
			val[results].data = cur_key.mv_data;
			++results;
		} else {
			break;
		}
		ret = mdb_cursor_get(cur, &cur_key, &cur_val, MDB_NEXT);
	}

	mdb_cursor_close(cur);
	txn_end(env, txn);
	return results;
}


static int cdb_prune(knot_db_t *db, int limit)
{
	/* Sync in-flight transactions */
	cdb_sync(db);

	/* Prune old records */
	struct lmdb_env *env = db;
	MDB_txn *txn = NULL;
	int ret = txn_begin(env, &txn, false);
	if (ret != 0) {
		return ret;
	}

	MDB_cursor *cur = NULL;
	ret = mdb_cursor_open(txn, env->dbi, &cur);
	if (ret != 0) {
		mdb_txn_abort(txn);
		return lmdb_error(ret);
	}

	MDB_val cur_key, cur_val;
	ret = mdb_cursor_get(cur, &cur_key, &cur_val, MDB_FIRST);
	if (ret != 0) {
		mdb_cursor_close(cur);
		mdb_txn_abort(txn);
		return lmdb_error(ret);
	}

	int results = 0;
	struct timeval now;
	gettimeofday(&now, NULL);
	while (ret == 0 && results < limit) {
		/* Ignore special namespaces. */
		if (cur_key.mv_size < 2 || ((const char *)cur_key.mv_data)[0] == 'V') {
			ret = mdb_cursor_get(cur, &cur_key, &cur_val, MDB_NEXT);
			continue;
		}
		/* Check entry age. */
		struct kr_cache_entry *entry = cur_val.mv_data;
		if (entry->timestamp > now.tv_sec ||
			(now.tv_sec - entry->timestamp) < entry->ttl) {
			ret = mdb_cursor_get(cur, &cur_key, &cur_val, MDB_NEXT);
			continue;
		}
		/* Remove entry */
		mdb_cursor_del(cur, 0);
		++results;
		ret = mdb_cursor_get(cur, &cur_key, &cur_val, MDB_NEXT);
	}
	mdb_cursor_close(cur);
	ret = lmdb_error(mdb_txn_commit(txn));
	return ret < 0 ? ret : results;
}

const struct kr_cdb_api *kr_cdb_lmdb(void)
{
	static const struct kr_cdb_api api = {
		"lmdb",
		cdb_init, cdb_deinit, cdb_count, cdb_clear, cdb_sync,
		cdb_readv, cdb_writev, cdb_remove,
		cdb_match, cdb_prune
	};

	return &api;
}
