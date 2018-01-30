/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/** @file cdb_memcached.c
 *  @brief Implemented all the things that the resolver cache needs,
 *         it's not a general-purpose namedb implementation, and it can't
 *         be since it's *cache* by principle and it doesn't guarantee persistence anyway.
 */

#include <assert.h>
#include <string.h>
#include <limits.h>
#include <libmemcached/memcached.h>
#include "contrib/cleanup.h"

#include "lib/generic/array.h"
#include "lib/cache/cdb_api.h"
#include "lib/cache/api.h"
#include "lib/utils.h"

/* memcached client */
struct memcached_cli {
	memcached_st *handle;
	memcached_result_st res;
};

static int cdb_init(knot_db_t **db, struct kr_cdb_opts *opts, knot_mm_t *pool)
{
	if (!db || !opts) {
		return kr_error(EINVAL);
	}

	struct memcached_cli *cli = malloc(sizeof(*cli));
	if (!cli) {
		return kr_error(ENOMEM);
	}
	memset(cli, 0, sizeof(*cli));

	/* Make sure we're running on binary protocol, as the
	 * textual protocol is broken for binary keys. */
	auto_free char *config_str = kr_strcatdup(2, opts->path, " --BINARY-PROTOCOL");
	cli->handle = memcached(config_str, strlen(config_str));
	if (!cli->handle) {
		free(cli);
		return kr_error(EIO);
	}

	/* Create result set */
	memcached_result_st *res = memcached_result_create(cli->handle, &cli->res);
	if (!res) {
		memcached_free(cli->handle);
		free(cli);
		return kr_error(ENOMEM);
	}

	*db = cli;
	return 0;
}

static void cdb_deinit(knot_db_t *db)
{
	struct memcached_cli *cli = db;
	memcached_result_free(&cli->res);
	memcached_free(cli->handle);
	free(cli);
}

static int cdb_sync(knot_db_t *db)
{
	return 0;
}

static int cdb_count(knot_db_t *db)
{
	struct memcached_cli *cli = db;
	memcached_return_t error = 0;
	memcached_stat_st *stats = memcached_stat(cli->handle, NULL, &error);
	if (error != 0) {
		return kr_error(EIO);
	}
	size_t ret = stats->curr_items;
	free(stats);
	return (ret > INT_MAX) ? INT_MAX : ret;
}

static int cdb_clear(knot_db_t *db)
{
	struct memcached_cli *cli = db;
	memcached_return_t ret = memcached_flush(cli->handle, 0);
	if (ret != 0) {
		return kr_error(EIO);
	}
	return 0;
}

static int cdb_readv(knot_db_t *db, const knot_db_val_t *key, knot_db_val_t *val,
		     int maxcount)
{
	if (!db || !key || !val) {
		return kr_error(EINVAL);
	}

	struct memcached_cli *cli = db;

	/* Convert to libmemcached query format */
	assert(maxcount < 1000); /* Sane upper bound */
	const char *keys [maxcount];
	size_t lengths [maxcount];
	for (int i = 0; i < maxcount; ++i) {
		keys[i] = key[i].data;
		lengths[i] = key[i].len;
	}

	/* Execute multiple get and retrieve results */
	memcached_return_t status = memcached_mget(cli->handle, keys, lengths, maxcount);
	memcached_result_free(&cli->res);
	memcached_result_create(cli->handle, &cli->res);
	for (int i = 0; i < maxcount; ++i) {
		memcached_result_st *res = memcached_fetch_result(cli->handle, &cli->res, &status);
		if (!res) { /* Less results than expected */
			return kr_error(ENOENT);
		}
		val[i].len = memcached_result_length(res);
		val[i].data = (void *)memcached_result_value(res);
	}
	return 0;
}

static int cdb_writev(knot_db_t *db, const knot_db_val_t *key, knot_db_val_t *val,
			int maxcount)
{
	if (!db || !key || !val) {
		return kr_error(EINVAL);
	}

	struct memcached_cli *cli = db;
	/* @warning This expects usage only for recursor cache, if anyone
	 *          desires to port this somewhere else, TTL shouldn't be interpreted.
	 */
	memcached_return_t ret = 0;
	for (int i = 0; i < maxcount; ++i) {
		if (val->len < 2) {
			/* @note Special values/namespaces, not a RR entry with TTL. */
			ret = memcached_set(cli->handle, key[i].data, key[i].len, val[i].data, val[i].len, 0, 0);
		} else {
			struct kr_cache_entry *entry = val[i].data;
			ret = memcached_set(cli->handle, key[i].data, key[i].len, val[i].data, val[i].len, entry->ttl, 0);
		}
		if (ret != 0) {
			break;
		}
	}
	return ret;
}

static int cdb_remove(knot_db_t *db, knot_db_val_t *key, int maxcount)
{
	if (!db || !key) {
		return kr_error(EINVAL);
	}

	struct memcached_cli *cli = db;
	memcached_return_t ret = 0;
	for (int i = 0; i < maxcount; ++i) {
		memcached_return_t ret = memcached_delete(cli->handle, key[i].data, key[i].len, 0);
		if (ret != 0) {
			break;
		}
	}
	return ret;
}

static int cdb_match(knot_db_t *cache, knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	if (!cache || !key || !val) {
		return kr_error(EINVAL);
	}
	return kr_error(ENOSYS);
}

const struct kr_cdb_api *cdb_memcached(void)
{
	static const struct kr_cdb_api api = {
		"memcached",
		cdb_init, cdb_deinit, cdb_count, cdb_clear, cdb_sync,
		cdb_readv, cdb_writev, cdb_remove,
		cdb_match, NULL /* prune */
	};

	return &api;
}
