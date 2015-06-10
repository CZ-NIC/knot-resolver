/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/** @file namedb_redis.c
 *  @brief Implemented all the things that the resolver cache needs (get, set, expiration).
 *  @note No real transactions.
 *  @note No iteration support.
 */

#include <assert.h>
#include <string.h>
#include <libknot/internal/namedb/namedb.h>

#include "modules/redis/redis.h"

#include "lib/cache.h"
#include "lib/utils.h"
#include "lib/defines.h"

static int cli_connect(struct redis_cli *cli)
{
	/* Connect to either UNIX socket or TCP */
	if (cli->port == 0) {
		cli->handle = redisConnectUnix(cli->addr);
	} else {
		cli->handle = redisConnect(cli->addr, cli->port);
	}
	/* Catch errors */
	if (!cli->handle) {
		return kr_error(ENOMEM);
	} else if (cli->handle->err) {
		redisFree(cli->handle);
		cli->handle = NULL;
		return kr_error(ECONNREFUSED);
	}
	/* Set max bufsize */
	cli->handle->reader->maxbuf = REDIS_BUFSIZE;
	/* Select database */
	redisReply *reply = redisCommand(cli->handle, "SELECT %d", cli->database);
	if (!reply) {
		redisFree(cli->handle);
		cli->handle = NULL;
		return kr_error(ENOTDIR);
	}
	freeReplyObject(reply);
	return kr_ok();
}

static void cli_decommit(struct redis_cli *cli)
{
	redis_freelist_t *freelist = &cli->freelist;
	for (unsigned i = 0; i < freelist->len; ++i) {
		freeReplyObject(freelist->at[i]);
	}
	freelist->len = 0;
}

static void cli_free(struct redis_cli *cli)
{
	if (cli->handle) {
		redisFree(cli->handle);
	}
	cli_decommit(cli);
	array_clear(cli->freelist);
	free(cli->addr);
	free(cli);
}

static int init(namedb_t **db, mm_ctx_t *mm, void *arg)
{
	if (!db || !arg) {
		return kr_error(EINVAL);
	}
	/* Clone redis cli and connect */
	struct redis_cli *cli = malloc(sizeof(*cli));
	if (!cli) {
		return kr_error(ENOMEM);
	}
	memcpy(cli, arg, sizeof(*cli));
	int ret = cli_connect(cli);
	if (ret != 0) {
		cli_free(cli);
		return ret;
	}    
    	*db = cli;
	return ret;
}

static void deinit(namedb_t *db)
{
	struct redis_cli *cli = db;
	cli_free(cli);
}

static int txn_begin(namedb_t *db, namedb_txn_t *txn, unsigned flags)
{
	if (!db || !txn) {
		return kr_error(EINVAL);
	}
	txn->db = db;
	return kr_ok();
}

static int txn_commit(namedb_txn_t *txn)
{
	if (!txn || !txn->db) {
		return kr_error(EINVAL);
	}
	cli_decommit(txn->db);
	txn->db = NULL;
	return kr_ok();
}

static void txn_abort(namedb_txn_t *txn)
{
	/** @warning No real transactions here. */
	txn_commit(txn);
}

/* Disconnect client */
#define CLI_DISCONNECT(cli) \
	if ((cli)->handle->err != REDIS_ERR_OTHER) { \
		redisFree((cli)->handle); \
		(cli)->handle = NULL; \
	}
/* Attempt to reconnect */
#define CLI_KEEPALIVE(cli_) \
	if (!(cli_)->handle) { \
		int ret = cli_connect((cli_)); \
		if (ret != 0) { \
			return ret; \
		} \
	}

static int count(namedb_txn_t *txn)
{
	if (!txn || !txn->db) {
		return kr_error(EINVAL);
	}
	int ret = 0;
	struct redis_cli *cli = txn->db;
	CLI_KEEPALIVE(cli);
	redisReply *reply = redisCommand(cli->handle, "DBSIZE");
	if (!reply) {
		CLI_DISCONNECT(cli);
		return kr_error(EIO);
	}
	if (reply->type == REDIS_REPLY_INTEGER) {
		ret = reply->integer;
	}
	freeReplyObject(reply);
	return ret;
}

static int clear(namedb_txn_t *txn)
{
	if (!txn || !txn->db) {
		return kr_error(EINVAL);
	}
	struct redis_cli *cli = txn->db;
	CLI_KEEPALIVE(cli);
	redisReply *reply = redisCommand(cli->handle, "FLUSHDB");
	if (!reply) {
		CLI_DISCONNECT(cli);
		return kr_error(EIO);
	}
	freeReplyObject(reply);
	return kr_ok();
}

static int find(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags)
{
	if (!txn || !key || !val) {
		return kr_error(EINVAL);
	}
	struct redis_cli *cli = txn->db;
	CLI_KEEPALIVE(cli);
	redisReply *reply = redisCommand(cli->handle, "GET %b", key->data, key->len);
	if (!reply) {
		CLI_DISCONNECT(cli);
		return kr_error(EIO);
	}
	/* Track reply in a freelist for this transaction */ 
	if (array_push(cli->freelist, reply) < 0) {
		freeReplyObject(reply); /* Can't track this, must free */
		return kr_error(ENOMEM);
	}
	/* Return value */
	if (reply->type != REDIS_REPLY_STRING) {
		return kr_error(EPROTO);
	}
	val->data = reply->str;
	val->len = reply->len;
	return kr_ok();
}

static int insert(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags)
{
	if (!txn || !key || !val) {
		return kr_error(EINVAL);
	}
	/* @warning This expects usage only for recursor cache, if anyone
	 *          desires to port this somewhere else, TTL shouldn't be interpreted.
	 */
	struct redis_cli *cli = txn->db;
	CLI_KEEPALIVE(cli);
	struct kr_cache_entry *entry = val->data;
	redisReply *reply = redisCommand(cli->handle, "SETEX %b %d %b",
	                                 key->data, key->len, entry->ttl, val->data, val->len);
	if (!reply) {
		CLI_DISCONNECT(cli);
		return kr_error(EIO);
	}
	freeReplyObject(reply);
	return kr_ok();
}

static int del(namedb_txn_t *txn, namedb_val_t *key)
{
	return kr_error(ENOSYS);
}

static namedb_iter_t *iter_begin(namedb_txn_t *txn, unsigned flags)
{
	/* Iteration is not supported, pruning should be
	 * left on the Redis server setting */
	return NULL;
}

static namedb_iter_t *iter_seek(namedb_iter_t *iter, namedb_val_t *key, unsigned flags)
{
	assert(0);
	return NULL; /* ENOSYS */
}

static namedb_iter_t *iter_next(namedb_iter_t *iter)
{
	assert(0);
	return NULL;
}

static int iter_key(namedb_iter_t *iter, namedb_val_t *val)
{
	return kr_error(ENOSYS);
}

static int iter_val(namedb_iter_t *iter, namedb_val_t *val)
{
	return kr_error(ENOSYS);
}

static void iter_finish(namedb_iter_t *iter)
{
	assert(0);
}

const namedb_api_t *namedb_redis_api(void)
{
	static const namedb_api_t api = {
		"redis",
		init, deinit,
		txn_begin, txn_commit, txn_abort,
		count, clear, find, insert, del,
		iter_begin, iter_seek, iter_next, iter_key, iter_val, iter_finish
	};

	return &api;
}
