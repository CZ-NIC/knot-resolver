/*  Copyright (C) 2015-2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/bindings/impl.h"

#include "daemon/zimport.h"

/** @internal return cache, or throw lua error if not open */
static struct kr_cache * cache_assert_open(lua_State *L)
{
	struct kr_cache *cache = &the_worker->engine->resolver.cache;
	assert(cache);
	if (!cache || !kr_cache_is_open(cache))
		lua_error_p(L, "no cache is open yet, use cache.open() or cache.size, etc.");
	return cache;
}

/** Return available cached backends. */
static int cache_backends(lua_State *L)
{
	struct engine *engine = the_worker->engine;

	lua_newtable(L);
	for (unsigned i = 0; i < engine->backends.len; ++i) {
		const struct kr_cdb_api *api = engine->backends.at[i];
		lua_pushboolean(L, api == engine->resolver.cache.api);
		lua_setfield(L, -2, api->name);
	}
	return 1;
}

/** Return number of cached records. */
static int cache_count(lua_State *L)
{
	struct kr_cache *cache = cache_assert_open(L);

	int count = cache->api->count(cache->db, &cache->stats);
	if (count >= 0) {
		/* First key is a version counter, omit it if nonempty. */
		lua_pushinteger(L, count ? count - 1 : 0);
		return 1;
	}
	return 0;
}

/** Return time of last checkpoint, or re-set it if passed `true`. */
static int cache_checkpoint(lua_State *L)
{
	struct kr_cache *cache = cache_assert_open(L);

	if (lua_gettop(L) == 0) { /* Return the current value. */
		lua_newtable(L);
		lua_pushnumber(L, cache->checkpoint_monotime);
		lua_setfield(L, -2, "monotime");
		lua_newtable(L);
		lua_pushnumber(L, cache->checkpoint_walltime.tv_sec);
		lua_setfield(L, -2, "sec");
		lua_pushnumber(L, cache->checkpoint_walltime.tv_usec);
		lua_setfield(L, -2, "usec");
		lua_setfield(L, -2, "walltime");
		return 1;
	}

	if (lua_gettop(L) != 1 || !lua_isboolean(L, 1) || !lua_toboolean(L, 1))
		lua_error_p(L, "cache.checkpoint() takes no parameters or a true value");

	kr_cache_make_checkpoint(cache);
	return 1;
}

/** Return cache statistics. */
static int cache_stats(lua_State *L)
{
	struct kr_cache *cache = cache_assert_open(L);
	lua_newtable(L);
#define add_stat(name) \
	lua_pushinteger(L, (cache->stats.name)); \
	lua_setfield(L, -2, #name)
	add_stat(open);
	add_stat(close);
	add_stat(count);
	cache->stats.count_entries = cache->api->count(cache->db, &cache->stats);
	add_stat(count_entries);
	add_stat(clear);
	add_stat(commit);
	add_stat(read);
	add_stat(read_miss);
	add_stat(write);
	add_stat(remove);
	add_stat(remove_miss);
	add_stat(match);
	add_stat(match_miss);
	add_stat(read_leq);
	add_stat(read_leq_miss);
	/* usage_percent statistics special case - double */
	cache->stats.usage_percent = cache->api->usage_percent(cache->db);
	lua_pushnumber(L, cache->stats.usage_percent);
	lua_setfield(L, -2, "usage_percent");
#undef add_stat

	return 1;
}

static const struct kr_cdb_api *cache_select(struct engine *engine, const char **conf)
{
	/* Return default backend */
	if (*conf == NULL || !strstr(*conf, "://")) {
		return engine->backends.at[0];
	}

	/* Find storage backend from config prefix */
	for (unsigned i = 0; i < engine->backends.len; ++i) {
		const struct kr_cdb_api *api = engine->backends.at[i];
		if (strncmp(*conf, api->name, strlen(api->name)) == 0) {
			*conf += strlen(api->name) + strlen("://");
			return api;
		}
	}

	return NULL;
}

static int cache_max_ttl(lua_State *L)
{
	struct kr_cache *cache = cache_assert_open(L);

	int n = lua_gettop(L);
	if (n > 0) {
		if (!lua_isnumber(L, 1) || n > 1)
			lua_error_p(L, "expected 'max_ttl(number ttl)'");
		uint32_t min = cache->ttl_min;
		int64_t ttl = lua_tointeger(L, 1);
		if (ttl < 1 || ttl < min || ttl > UINT32_MAX) {
			lua_error_p(L,
				"max_ttl must be larger than minimum TTL, and in range <1, "
				STR(UINT32_MAX) ">'");
		}
		cache->ttl_max = ttl;
	}
	lua_pushinteger(L, cache->ttl_max);
	return 1;
}


static int cache_min_ttl(lua_State *L)
{
	struct kr_cache *cache = cache_assert_open(L);

	int n = lua_gettop(L);
	if (n > 0) {
		if (!lua_isnumber(L, 1))
			lua_error_p(L, "expected 'min_ttl(number ttl)'");
		uint32_t max = cache->ttl_max;
		int64_t ttl = lua_tointeger(L, 1);
		if (ttl < 0 || ttl > max || ttl > UINT32_MAX) {
			lua_error_p(L,
				"min_ttl must be smaller than maximum TTL, and in range <0, "
				STR(UINT32_MAX) ">'");
		}
		cache->ttl_min = ttl;
	}
	lua_pushinteger(L, cache->ttl_min);
	return 1;
}

/** Open cache */
static int cache_open(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 1 || !lua_isnumber(L, 1))
		lua_error_p(L, "expected 'open(number max_size, string config = \"\")'");

	/* Select cache storage backend */
	struct engine *engine = the_worker->engine;

	lua_Integer csize_lua = lua_tointeger(L, 1);
	if (!(csize_lua >= 8192 && csize_lua < SIZE_MAX)) { /* min. is basically arbitrary */
		lua_error_p(L, "invalid cache size specified, it must be in range <8192, "
				STR(SIZE_MAX)  ">");
	}
	size_t cache_size = csize_lua;

	const char *conf = n > 1 ? lua_tostring(L, 2) : NULL;
	const char *uri = conf;
	const struct kr_cdb_api *api = cache_select(engine, &conf);
	if (!api)
		lua_error_p(L, "unsupported cache backend");

	/* Close if already open */
	kr_cache_close(&engine->resolver.cache);

	/* Reopen cache */
	struct kr_cdb_opts opts = {
		(conf && strlen(conf)) ? conf : ".",
		cache_size
	};
	int ret = kr_cache_open(&engine->resolver.cache, api, &opts, engine->pool);
	if (ret != 0) {
		char cwd[PATH_MAX];
		get_workdir(cwd, sizeof(cwd));
		return luaL_error(L, "can't open cache path '%s'; working directory '%s'; %s",
				  opts.path, cwd, kr_strerror(ret));
	}
	/* Let's check_health() every five seconds to avoid keeping old cache alive
	 * even in case of not having any work to do. */
	ret = kr_cache_check_health(&engine->resolver.cache, 5000);
	if (ret != 0) {
		kr_log_error("[cache] periodic health check failed (ignored): %s\n",
				kr_strerror(ret));
	}

	/* Store current configuration */
	lua_getglobal(L, "cache");
	lua_pushstring(L, "current_size");
	lua_pushnumber(L, cache_size);
	lua_rawset(L, -3);
	lua_pushstring(L, "current_storage");
	lua_pushstring(L, uri);
	lua_rawset(L, -3);
	lua_pop(L, 1);

	lua_pushboolean(L, 1);
	return 1;
}

static int cache_close(lua_State *L)
{
	struct kr_cache *cache = &the_worker->engine->resolver.cache;
	if (!kr_cache_is_open(cache)) {
		return 0;
	}

	kr_cache_close(cache);
	lua_getglobal(L, "cache");
	lua_pushstring(L, "current_size");
	lua_pushnumber(L, 0);
	lua_rawset(L, -3);
	lua_pop(L, 1);
	lua_pushboolean(L, 1);
	return 1;
}

#if 0
/** @internal Prefix walk. */
static int cache_prefixed(struct kr_cache *cache, const char *prefix, bool exact_name,
			  knot_db_val_t keyval[][2], int maxcount)
{
	/* Convert to domain name */
	uint8_t buf[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(buf, prefix, sizeof(buf))) {
		return kr_error(EINVAL);
	}
	/* Start prefix search */
	return kr_cache_match(cache, buf, exact_name, keyval, maxcount);
}
#endif

/** Clear everything. */
static int cache_clear_everything(lua_State *L)
{
	struct kr_cache *cache = cache_assert_open(L);

	/* Clear records and packets. */
	int ret = kr_cache_clear(cache);
	lua_error_maybe(L, ret);

	/* Clear reputation tables */
	struct kr_context *ctx = &the_worker->engine->resolver;
	lru_reset(ctx->cache_rtt);
	lru_reset(ctx->cache_rep);
	lru_reset(ctx->cache_cookie);
	lua_pushboolean(L, true);
	return 1;
}

#if 0
/** @internal Dump cache key into table on Lua stack. */
static void cache_dump(lua_State *L, knot_db_val_t keyval[])
{
	knot_dname_t dname[KNOT_DNAME_MAXLEN];
	char name[KNOT_DNAME_TXT_MAXLEN];
	uint16_t type;

	int ret = kr_unpack_cache_key(keyval[0], dname, &type);
	if (ret < 0) {
		return;
	}

	ret = !knot_dname_to_str(name, dname, sizeof(name));
	assert(!ret);
	if (ret) return;

	/* If name typemap doesn't exist yet, create it */
	lua_getfield(L, -1, name);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		lua_newtable(L);
	}
	/* Append to typemap */
	char type_buf[KR_RRTYPE_STR_MAXLEN] = { '\0' };
	knot_rrtype_to_string(type, type_buf, sizeof(type_buf));
	lua_pushboolean(L, true);
	lua_setfield(L, -2, type_buf);
	/* Set name typemap */
	lua_setfield(L, -2, name);
}

/** Query cached records.  TODO: fix caveats in ./README.rst documentation? */
static int cache_get(lua_State *L)
{
	//struct kr_cache *cache = cache_assert_open(L); // to be fixed soon

	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 1 || !lua_isstring(L, 1))
		lua_error_p(L, "expected 'cache.get(string key)'");

	/* Retrieve set of keys */
	const char *prefix = lua_tostring(L, 1);
	knot_db_val_t keyval[100][2];
	int ret = cache_prefixed(cache, prefix, false/*FIXME*/, keyval, 100);
	lua_error_maybe(L, ret);
	/* Format output */
	lua_newtable(L);
	for (int i = 0; i < ret; ++i) {
		cache_dump(L, keyval[i]);
	}
	return 1;
}
#endif
static int cache_get(lua_State *L)
{
	lua_error_maybe(L, ENOSYS);
	return kr_error(ENOSYS); /* doesn't happen */
}

/** Set time interval for cleaning rtt cache.
 * Servers with score >= KR_NS_TIMEOUT will be cleaned after
 * this interval ended up, so that they will be able to participate
 * in NS elections again. */
static int cache_ns_tout(lua_State *L)
{
	struct kr_context *ctx = &the_worker->engine->resolver;

	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 1) {
		lua_pushinteger(L, ctx->cache_rtt_tout_retry_interval);
		return 1;
	}

	if (!lua_isnumber(L, 1))
		lua_error_p(L, "expected 'cache.ns_tout(interval in ms)'");

	lua_Integer interval_lua = lua_tointeger(L, 1);
	if (!(interval_lua > 0 && interval_lua < UINT_MAX)) {
		lua_error_p(L, "invalid interval specified, it must be in range > 0, < "
				STR(UINT_MAX));
	}

	ctx->cache_rtt_tout_retry_interval = interval_lua;
	lua_pushinteger(L, ctx->cache_rtt_tout_retry_interval);
	return 1;
}

/** Zone import completion callback.
 * Deallocates zone import context. */
static void cache_zone_import_cb(int state, void *param)
{
	assert (param);
	(void)state;
	struct worker_ctx *worker = (struct worker_ctx *)param;
	assert (worker->z_import);
	zi_free(worker->z_import);
	worker->z_import = NULL;
}

/** Import zone from file. */
static int cache_zone_import(lua_State *L)
{
	int ret = -1;
	char msg[128];

	struct worker_ctx *worker = the_worker;
	if (!worker) {
		strncpy(msg, "internal error, empty worker pointer", sizeof(msg));
		goto finish;
	}

	if (worker->z_import && zi_import_started(worker->z_import)) {
		strncpy(msg, "import already started", sizeof(msg));
		goto finish;
	}

	(void)cache_assert_open(L); /* just check it in advance */

	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 1 || !lua_isstring(L, 1)) {
		strncpy(msg, "expected 'cache.zone_import(path to zone file)'", sizeof(msg));
		goto finish;
	}

	/* Parse zone file */
	const char *zone_file = lua_tostring(L, 1);

	const char *default_origin = NULL; /* TODO */
	uint16_t default_rclass = 1;
	uint32_t default_ttl = 0;

	if (worker->z_import == NULL) {
		worker->z_import = zi_allocate(worker, cache_zone_import_cb, worker);
		if (worker->z_import == NULL) {
			strncpy(msg, "can't allocate zone import context", sizeof(msg));
			goto finish;
		}
	}

	ret = zi_zone_import(worker->z_import, zone_file, default_origin,
			     default_rclass, default_ttl);

	lua_newtable(L);
	if (ret == 0) {
		strncpy(msg, "zone file successfully parsed, import started", sizeof(msg));
	} else if (ret == 1) {
		strncpy(msg, "TA not found", sizeof(msg));
	} else {
		strncpy(msg, "error parsing zone file", sizeof(msg));
	}

finish:
	msg[sizeof(msg) - 1] = 0;
	lua_newtable(L);
	lua_pushstring(L, msg);
	lua_setfield(L, -2, "msg");
	lua_pushnumber(L, ret);
	lua_setfield(L, -2, "code");

	return 1;
}

int kr_bindings_cache(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "backends", cache_backends },
		{ "count",  cache_count },
		{ "stats",  cache_stats },
		{ "checkpoint", cache_checkpoint },
		{ "open",   cache_open },
		{ "close",  cache_close },
		{ "clear_everything", cache_clear_everything },
		{ "get",     cache_get },
		{ "max_ttl", cache_max_ttl },
		{ "min_ttl", cache_min_ttl },
		{ "ns_tout", cache_ns_tout },
		{ "zone_import", cache_zone_import },
		{ NULL, NULL }
	};

	luaL_register(L, "cache", lib);
	return 1;
}

