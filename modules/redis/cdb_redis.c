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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/** @file cdb_redis.c
 *  @brief Implemented all the things that the resolver cache needs (get, set, expiration).
 */

#include <assert.h>
#include <string.h>
#include <uv.h>

#include "modules/redis/redis.h"
#include "contrib/ccan/asprintf/asprintf.h"
#include "contrib/cleanup.h"
#include "contrib/ucw/lib.h"


#include "lib/cdb.h"
#include "lib/cache.h"
#include "lib/utils.h"
#include "lib/defines.h"

#define REDIS_BATCHSIZE 100

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

/** @internal Make redis options. */
static struct redis_cli *cli_make(const char *conf_)
{
	auto_free char *conf = strdup(conf_);
	struct redis_cli *cli = malloc(sizeof(*cli));
	if (!cli || !conf) {
		free(cli);
		return NULL;
	}
	/* Parse database */
	memset(cli, 0, sizeof(*cli));
	char *bp = conf;
	char *p = strchr(bp, '@');
	if (p) {
		*p = '\0';
		cli->database = atoi(conf);
		bp = (p + 1);
	}
	/* Parse host / ip / sock */
	if (access(bp, W_OK) == 0) { /* UNIX */
		cli->addr = strdup(bp);
		return cli;
	}
	struct sockaddr_in6 ip6;
	p = strchr(bp, ':');
	if (!p) { /* IPv4 */
		cli->addr = strdup(bp);
		cli->port = REDIS_PORT;
		return cli;
	}
	if (!strchr(p + 1, ':')) { /* IPv4 + port */
		*p = '\0';
		cli->addr = strdup(bp);
		cli->port = atoi(p + 1);
	} else { /* IPv6 */
		if (uv_ip6_addr(bp, 0, &ip6) == 0) {
			cli->addr = strdup(bp);
			cli->port = REDIS_PORT;
		} else { /* IPv6 + port */
			p = strrchr(bp, ':');
			*p = '\0';
			cli->addr = strdup(bp);
			cli->port = atoi(p + 1);
		}
	}
	return cli;
}

static int cdb_init(knot_db_t **cache, struct kr_cdb_opts *opts, knot_mm_t *pool)
{
	if (!cache || !opts) {
		return kr_error(EINVAL);
	}
	/* Clone redis cli and connect */
	struct redis_cli *cli = cli_make(opts->path);
	if (!cli) {
		return kr_error(ENOMEM);
	}
	int ret = cli_connect(cli);
	if (ret != 0) {
		cli_free(cli);
		return ret;
	}    
	*cache = cli;
	return ret;
}

static void cdb_deinit(knot_db_t *cache)
{
	struct redis_cli *cli = cache;
	cli_free(cli);
}

static int cdb_sync(knot_db_t *cache)
{
	if (!cache) {
		return kr_error(EINVAL);
	}
	struct redis_cli *cli = cache;
	cli_decommit(cli);
	return 0;
}

/* Disconnect client */
#define CLI_DISCONNECT(cli) \
	if ((cli)->handle->err != REDIS_ERR_OTHER) { \
		redisFree((cli)->handle); \
		(cli)->handle = NULL; \
	}
/* Attempt to reconnect */
#define CLI_KEEPALIVE(cli_) \
	if ((cli_)->freelist.len > REDIS_MAXFREELIST) { \
		cli_decommit(cli_); \
	} \
	if (!(cli_)->handle) { \
		int ret = cli_connect((cli_)); \
		if (ret != 0) { \
			return ret; \
		} \
	}

static int cdb_count(knot_db_t *cache)
{
	if (!cache) {
		return kr_error(EINVAL);
	}
	int ret = 0;
	struct redis_cli *cli = cache;
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

static int cdb_clear(knot_db_t *cache)
{
	if (!cache) {
		return kr_error(EINVAL);
	}
	struct redis_cli *cli = cache;
	CLI_KEEPALIVE(cli);
	redisReply *reply = redisCommand(cli->handle, "FLUSHDB");
	if (!reply) {
		CLI_DISCONNECT(cli);
		return kr_error(EIO);
	}
	freeReplyObject(reply);
	return kr_ok();
}

static int cdb_readv(knot_db_t *cache, knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	if (!cache || !key || !val) {
		return kr_error(EINVAL);
	}
	struct redis_cli *cli = cache;
	CLI_KEEPALIVE(cli);

	/* Build command pipeline */
	for (int i = 0; i < maxcount; ++i) {
		redisAppendCommand(cli->handle, "GET %b", key[i].data, key[i].len);
	}
	/* Gather replies */
	for (int i = 0; i < maxcount; ++i) {
		redisReply *reply = NULL;
		redisGetReply(cli->handle, (void **)&reply);
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
		val[i].data = reply->str;
		val[i].len = reply->len;
	}
	return kr_ok();
}

static int cdb_writev(knot_db_t *cache, knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	if (!cache || !key || !val) {
		return kr_error(EINVAL);
	}

	struct redis_cli *cli = cache;
	CLI_KEEPALIVE(cli);

	/* Build command pipeline */
	for (int i = 0; i < maxcount; ++i) {
		if (val->len < 2) {
			/* @note Special values/namespaces, not a RR entry with TTL. */
			redisAppendCommand(cli->handle, "SET %b %b", key[i].data, key[i].len, val[i].data, val[i].len);
		} else {
			/* @warning This expects usage only for recursor cache, if anyone
			 * desires to port this somewhere else, TTL shouldn't be interpreted. */
			struct kr_cache_entry *entry = val[i].data;
			redisAppendCommand(cli->handle, "SETEX %b %d %b", key[i].data, key[i].len, entry->ttl, val[i].data, val[i].len);
		}
	}
	/* Gather replies */
	for (int i = 0; i < maxcount; ++i) {
		redisReply *reply = NULL;
		redisGetReply(cli->handle, (void **)&reply);
		if (!reply) {
			CLI_DISCONNECT(cli);
			return kr_error(EIO);
		}
		freeReplyObject(reply);
	}
	return kr_ok();
}

static int cdb_remove(knot_db_t *cache, knot_db_val_t *key, int maxcount)
{
	if (!cache || !key) {
		return kr_error(EINVAL);
	}

	struct redis_cli *cli = cache;
	CLI_KEEPALIVE(cli);

	/* Build command pipeline */
	for (int i = 0; i < maxcount; ++i) {
		redisAppendCommand(cli->handle, "DEL %b", key[i].data, key[i].len);
	}
	/* Gather replies */
	for (int i = 0; i < maxcount; ++i) {
		redisReply *reply = NULL;
		redisGetReply(cli->handle, (void **)&reply);
		if (!reply) {
			CLI_DISCONNECT(cli);
			return kr_error(EIO);
		}
		freeReplyObject(reply);
	}
	return kr_ok();
}

static int cdb_match(knot_db_t *cache, knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	if (!cache || !key || !val) {
		return kr_error(EINVAL);
	}

	/* Turn wildcard into prefix scan. */
	const uint8_t *endp = (const uint8_t *)key->data + (key->len - 2);
	if (key->len > 2 && endp[0] == '*' && endp[1] == '\0') {
		--key->len; /* Trim terminal byte for right-side wildcard search */
	}

	struct redis_cli *cli = cache;
	CLI_KEEPALIVE(cli);
	redisReply *reply = redisCommand(cli->handle, "SCAN 0 MATCH %b COUNT 100", key->data, key->len);
	if (!reply) {
		CLI_DISCONNECT(cli);
		return kr_error(EIO);
	}
	/* Track reply in a freelist for this transaction */ 
	if (array_push(cli->freelist, reply) < 0) {
		freeReplyObject(reply); /* Can't track this, must free */
		return kr_error(ENOMEM);
	}
	/* SCAN returns array of 2 elements, first is iterator 'next' and second an array of results. */
	int results = 0;
	if (reply->type == REDIS_REPLY_ARRAY && reply->elements == 2) {
		redisReply *data = reply->element[1];
		results = MIN(data->elements, maxcount);
		assert(data->type == REDIS_REPLY_ARRAY);
		for (size_t i = 0; i < results; ++i) {
			redisReply *elem = data->element[i];
			assert(elem->type == REDIS_REPLY_STRING);
			val[i].data = elem->str;
			val[i].len = elem->len;
		}
	}
	return results;
}

const struct kr_cdb_api *cdb_redis(void)
{
	static const struct kr_cdb_api api = {
		"redis",
		cdb_init, cdb_deinit, cdb_count, cdb_clear, cdb_sync,
		cdb_readv, cdb_writev, cdb_remove,
		cdb_match, NULL /* prune */
	};

	return &api;
}
