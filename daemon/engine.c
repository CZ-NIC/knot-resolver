/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <contrib/cleanup.h>
#include <ccan/json/json.h>
#include <ccan/asprintf/asprintf.h>
#include <dlfcn.h>
#include <uv.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <sys/param.h>
#include <libzscanner/scanner.h>
#include <sys/un.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "daemon/bindings/impl.h"

#include "kresconfig.h"
#include "daemon/engine.h"
#include "daemon/ffimodule.h"
#include "lib/selection.h"
#include "lib/cache/api.h"
#include "lib/defines.h"
#include "lib/cache/cdb_lmdb.h"
#include "lib/dnssec/ta.h"

/* Magic defaults for the engine. */
#ifndef LRU_RTT_SIZE
#define LRU_RTT_SIZE 65536 /**< NS RTT cache size */
#endif
#ifndef LRU_REP_SIZE
#define LRU_REP_SIZE (LRU_RTT_SIZE / 4) /**< NS reputation cache size */
#endif
#ifndef LRU_COOKIES_SIZE
	#if ENABLE_COOKIES
	#define LRU_COOKIES_SIZE LRU_RTT_SIZE /**< DNS cookies cache size. */
	#else
	#define LRU_COOKIES_SIZE LRU_ASSOC /* simpler than guards everywhere */
	#endif
#endif

/**@internal Maximum number of incomplete TCP connections in queue.
* Default is from empirical testing - in our case, more isn't necessarily better.
* See https://gitlab.nic.cz/knot/knot-resolver/-/merge_requests/968
* */
#ifndef TCP_BACKLOG_DEFAULT
#define TCP_BACKLOG_DEFAULT 128
#endif

/* Cleanup engine state every 5 minutes */
const size_t CLEANUP_TIMER = 5*60*1000;

/* Execute byte code */
#define l_dobytecode(L, arr, len, name) \
	(luaL_loadbuffer((L), (arr), (len), (name)) || lua_pcall((L), 0, LUA_MULTRET, 0))

/*
 * Global bindings.
 */
struct args *the_args;


/** Print help and available commands. */
static int l_help(lua_State *L)
{
	static const char *help_str =
		"help()\n    show this help\n"
		"quit()\n    quit\n"
		"hostname()\n    hostname\n"
		"package_version()\n    return package version\n"
		"user(name[, group])\n    change process user (and group)\n"
		"verbose(true|false)\n    toggle verbose mode\n"
		"option(opt[, new_val])\n    get/set server option\n"
		"mode(strict|normal|permissive)\n    set resolver strictness level\n"
		"reorder_RR([true|false])\n    set/get reordering of RRs within RRsets\n"
		"resolve(name, type[, class, flags, callback])\n    resolve query, callback when it's finished\n"
		"todname(name)\n    convert name to wire format\n"
		"tojson(val)\n    convert value to JSON\n"
		"net\n    network configuration\n"
		"cache\n    network configuration\n"
		"modules\n    modules configuration\n"
		"kres\n    resolver services\n"
		"trust_anchors\n    configure trust anchors\n"
		"debugging\n    debugging configuration\n"
		;
	lua_pushstring(L, help_str);
	return 1;
}

static bool update_privileges(int uid, int gid)
{
	if ((gid_t)gid != getgid()) {
		if (setregid(gid, gid) < 0) {
			return false;
		}
	}
	if ((uid_t)uid != getuid()) {
		if (setreuid(uid, uid) < 0) {
			return false;
		}
	}
	return true;
}

/** Set process user/group. */
static int l_setuser(lua_State *L)
{
	int n = lua_gettop(L);
	if (n < 1 || !lua_isstring(L, 1))
		lua_error_p(L, "user(user[, group])");

	/* Fetch UID/GID based on string identifiers. */
	struct passwd *user_pw = getpwnam(lua_tostring(L, 1));
	if (!user_pw)
		lua_error_p(L, "invalid user name");
	int uid = user_pw->pw_uid;
	int gid = getgid();
	if (n > 1 && lua_isstring(L, 2)) {
		struct group *group_pw = getgrnam(lua_tostring(L, 2));
		if (!group_pw)
			lua_error_p(L, "invalid group name");
		gid = group_pw->gr_gid;
	}
	/* Drop privileges */
	bool ret = update_privileges(uid, gid);
	if (!ret) {
		lua_error_maybe(L, errno);
	}
	lua_pushboolean(L, ret);
	return 1;
}

/** Quit current executable. */
static int l_quit(lua_State *L)
{
	engine_stop(the_worker->engine);
	return 0;
}

/** Toggle verbose mode. */
static int l_verbose(lua_State *L)
{
	log_level_t level = LOG_DEFAULT_LEVEL;
	if ((lua_isboolean(L, 1) && lua_toboolean(L, 1) == true) ||
			lua_isnumber(L, 1)) {
		level = LOG_DEBUG;
	}

	lua_pushboolean(L, kr_log_level_set(level) == LOG_DEBUG);
	return 1;
}

static int l_set_log_level(lua_State *L)
{
	if(lua_gettop(L) == 0) {
		printf("levels: crit, err, warning, notice, info, debug\n");
		return 0;
	}

	if (lua_gettop(L) != 1 || !lua_isstring(L, 1))
		lua_error_p(L, "takes one parameter, type set_log_level() for help.");

	log_level_t lvl = kr_log_name2level(lua_tostring(L, 1));

	lua_pushinteger(L, kr_log_level_set(lvl));
	return 1;
}

static int l_get_log_level(lua_State *L)
{
	printf("%s\n", kr_log_level2name(kr_log_level_get()));

	return 0;
}

static int handle_log_groups(lua_State *L, void (*action)(log_groups_t grp))
{
	if(lua_gettop(L) == 0) {
		int grp_b = 1;
		char *grp_name = kr_log_grp2name(1 << grp_b);
		printf("groups: \n\t");
		while (grp_name) {
			printf("%s%s, ", group_is_set(1 << grp_b) ? "*":"", grp_name);
			if (grp_b%8 == 0)
				printf("\n\t");
			++grp_b;
			grp_name = kr_log_grp2name(1 << grp_b);
		}
		printf("\n* = groups logged in debug level\n");
		return 0;
	}

	if (lua_gettop(L) != 1 || (!lua_isstring(L, 1) && !lua_istable(L, 1)))
		lua_error_p(L, "takes string or table of strings, type add_log_group() for help.");

	if (lua_isstring(L, 1)) {
		log_groups_t grp = kr_log_name2grp(lua_tostring(L, 1));
		if (grp == 0)
			lua_error_p(L, "unknown group, type add_log_group() for help.");
		action(grp);
	}

	if (lua_istable(L, 1)) {
		int idx = 1;
		log_groups_t grp;
		lua_pushnil(L);
		while (lua_next(L, 1) != 0) {
			if (!lua_isstring(L, -1))
				lua_error_p(L, "wrong value at index %d, must be string", idx);
			grp = kr_log_name2grp(lua_tostring(L, -1));
			if (grp == 0)
				lua_error_p(L, "unknown group \"%s\", type add_log_group() for help.", lua_tostring(L, -1));

			action(grp);
			++idx;
			lua_pop(L, 1);
		}
	}

	return 0;
}

static int l_add_log_group(lua_State *L)
{
	return handle_log_groups(L, kr_log_add_group);
}

static int l_del_log_group(lua_State *L)
{
	return handle_log_groups(L, kr_log_del_group);
}

char *engine_get_hostname(struct engine *engine) {
	static char hostname_str[KNOT_DNAME_MAXLEN];
	if (!engine) {
		return NULL;
	}

	if (!engine->hostname) {
		if (gethostname(hostname_str, sizeof(hostname_str)) != 0)
			return NULL;
		return hostname_str;
	}
	return engine->hostname;
}

int engine_set_hostname(struct engine *engine, const char *hostname) {
	if (!engine || !hostname) {
		return kr_error(EINVAL);
	}

	char *new_hostname = strdup(hostname);
	if (!new_hostname) {
		return kr_error(ENOMEM);
	}
	if (engine->hostname) {
		free(engine->hostname);
	}
	engine->hostname = new_hostname;
	network_new_hostname(&engine->net, engine);

	return 0;
}

/** Return hostname. */
static int l_hostname(lua_State *L)
{
	struct engine *engine = the_worker->engine;
	if (lua_gettop(L) == 0) {
		lua_pushstring(L, engine_get_hostname(engine));
		return 1;
	}
	if ((lua_gettop(L) != 1) || !lua_isstring(L, 1))
		lua_error_p(L, "hostname takes at most one parameter: (\"fqdn\")");

	if (engine_set_hostname(engine, lua_tostring(L, 1)) != 0)
		lua_error_p(L, "setting hostname failed");

	lua_pushstring(L, engine_get_hostname(engine));
	return 1;
}

/** Return server package version. */
static int l_package_version(lua_State *L)
{
	lua_pushliteral(L, PACKAGE_VERSION);
	return 1;
}

/** Load root hints from zonefile. */
static int l_hint_root_file(lua_State *L)
{
	struct kr_context *ctx = &the_worker->engine->resolver;
	const char *file = lua_tostring(L, 1);

	const char *err = engine_hint_root_file(ctx, file);
	if (err) {
		if (!file) {
			file = ROOTHINTS;
		}
		lua_error_p(L, "error when opening '%s': %s", file, err);
	} else {
		lua_pushboolean(L, true);
		return 1;
	}
}

/** @internal for engine_hint_root_file */
static void roothints_add(zs_scanner_t *zs)
{
	struct kr_zonecut *hints = zs->process.data;
	if (!hints) {
		return;
	}
	if (zs->r_type == KNOT_RRTYPE_A || zs->r_type == KNOT_RRTYPE_AAAA) {
		kr_zonecut_add(hints, zs->r_owner, zs->r_data, zs->r_data_length);
	}
}
const char* engine_hint_root_file(struct kr_context *ctx, const char *file)
{
	if (!file) {
		file = ROOTHINTS;
	}
	if (strlen(file) == 0 || !ctx) {
		return "invalid parameters";
	}
	struct kr_zonecut *root_hints = &ctx->root_hints;

	zs_scanner_t zs;
	if (zs_init(&zs, ".", 1, 0) != 0) {
		return "not enough memory";
	}
	if (zs_set_input_file(&zs, file) != 0) {
		zs_deinit(&zs);
		return "failed to open root hints file";
	}

	kr_zonecut_set(root_hints, (const uint8_t *)"");
	zs_set_processing(&zs, roothints_add, NULL, root_hints);
	zs_parse_all(&zs);
	zs_deinit(&zs);
	return NULL;
}

/** Unpack JSON object to table */
static void l_unpack_json(lua_State *L, JsonNode *table)
{
	/* Unpack POD */
	switch(table->tag) {
		case JSON_STRING: lua_pushstring(L, table->string_); return;
		case JSON_NUMBER: lua_pushnumber(L, table->number_); return;
		case JSON_BOOL:   lua_pushboolean(L, table->bool_); return;
		default: break;
	}
	/* Unpack object or array into table */
	lua_newtable(L);
	JsonNode *node = NULL;
	json_foreach(node, table) {
		/* Push node value */
		switch(node->tag) {
		case JSON_OBJECT: /* as array */
		case JSON_ARRAY:  l_unpack_json(L, node); break;
		case JSON_STRING: lua_pushstring(L, node->string_); break;
		case JSON_NUMBER: lua_pushnumber(L, node->number_); break;
		case JSON_BOOL:   lua_pushboolean(L, node->bool_); break;
		default: continue;
		}
		/* Set table key */
		if (node->key) {
			lua_setfield(L, -2, node->key);
		} else {
			lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
		}
	}
}

/** @internal Recursive Lua/JSON serialization. */
static JsonNode *l_pack_elem(lua_State *L, int top)
{
	switch(lua_type(L, top)) {
	case LUA_TSTRING:  return json_mkstring(lua_tostring(L, top));
	case LUA_TNUMBER:  return json_mknumber(lua_tonumber(L, top));
	case LUA_TBOOLEAN: return json_mkbool(lua_toboolean(L, top));
	case LUA_TTABLE:   break; /* Table, iterate it. */
	default:           return json_mknull();
	}
	/* Use absolute indexes here, as the table may be nested. */
	JsonNode *node = NULL;
	lua_pushnil(L);
	while(lua_next(L, top) != 0) {
		bool is_array = false;
		if (!node) {
			is_array = (lua_type(L, top + 1) == LUA_TNUMBER);
			node = is_array ? json_mkarray() : json_mkobject();
			if (!node) {
				return NULL;
			}
		} else {
			is_array = node->tag == JSON_ARRAY;
		}

		/* Insert to array/table. */
		JsonNode *val = l_pack_elem(L, top + 2);
		if (is_array) {
			json_append_element(node, val);
		} else {
			const char *key = lua_tostring(L, top + 1);
			json_append_member(node, key, val);
		}
		lua_pop(L, 1);
	}
	/* Return empty object for empty tables. */
	return node ? node : json_mkobject();
}

/** @internal Serialize to string */
static char *l_pack_json(lua_State *L, int top)
{
	JsonNode *root = l_pack_elem(L, top);
	if (!root) {
		return NULL;
	}
	char *result = json_encode(root);
	json_delete(root);
	return result;
}

static int l_tojson(lua_State *L)
{
	auto_free char *json_str = l_pack_json(L, lua_gettop(L));
	if (!json_str) {
		return 0;
	}
	lua_pushstring(L, json_str);
	return 1;
}

static int l_fromjson(lua_State *L)
{
	if (lua_gettop(L) != 1 || !lua_isstring(L, 1))
		lua_error_p(L, "a JSON string is required");

	const char *json_str = lua_tostring(L, 1);
	JsonNode *root_node = json_decode(json_str);

	if (!root_node)
		lua_error_p(L, "invalid JSON string");
	l_unpack_json(L, root_node);
	json_delete(root_node);

	return 1;
}

/*
 * Engine API.
 */

static int init_resolver(struct engine *engine)
{
	/* Note: whole *engine had been zeroed by engine_init(). */
	struct kr_context * const ctx = &engine->resolver;
	/* Default options (request flags). */
	ctx->options.REORDER_RR = true;

	/* Open resolution context */
	ctx->trust_anchors = map_make(NULL);
	ctx->negative_anchors = map_make(NULL);
	ctx->pool = engine->pool;
	ctx->modules = &engine->modules;
	ctx->cache_rtt_tout_retry_interval = KR_NS_TIMEOUT_RETRY_INTERVAL;
	/* Create OPT RR */
	ctx->downstream_opt_rr = mm_alloc(engine->pool, sizeof(knot_rrset_t));
	ctx->upstream_opt_rr = mm_alloc(engine->pool, sizeof(knot_rrset_t));
	if (!ctx->downstream_opt_rr || !ctx->upstream_opt_rr) {
		return kr_error(ENOMEM);
	}
	knot_edns_init(ctx->downstream_opt_rr, KR_EDNS_PAYLOAD, 0, KR_EDNS_VERSION, engine->pool);
	knot_edns_init(ctx->upstream_opt_rr, KR_EDNS_PAYLOAD, 0, KR_EDNS_VERSION, engine->pool);
	/* Use default TLS padding */
	ctx->tls_padding = -1;
	/* Empty init; filled via ./lua/postconfig.lua */
	kr_zonecut_init(&ctx->root_hints, (const uint8_t *)"", engine->pool);
	lru_create(&ctx->cache_cookie, LRU_COOKIES_SIZE, NULL, NULL);

	/* Load basic modules */
	engine_register(engine, "iterate", NULL, NULL);
	engine_register(engine, "validate", NULL, NULL);
	engine_register(engine, "cache", NULL, NULL);

	return array_push(engine->backends, kr_cdb_lmdb());
}

static int init_state(struct engine *engine)
{
	/* Initialize Lua state */
	engine->L = luaL_newstate();
	if (engine->L == NULL) {
		return kr_error(ENOMEM);
	}
	/* Initialize used libraries. */
	luaL_openlibs(engine->L);
	/* Global functions */
	lua_pushcfunction(engine->L, l_help);
	lua_setglobal(engine->L, "help");
	lua_pushcfunction(engine->L, l_quit);
	lua_setglobal(engine->L, "quit");
	lua_pushcfunction(engine->L, l_hostname);
	lua_setglobal(engine->L, "hostname");
	lua_pushcfunction(engine->L, l_package_version);
	lua_setglobal(engine->L, "package_version");
	lua_pushcfunction(engine->L, l_verbose);
	lua_setglobal(engine->L, "verbose");
	lua_pushcfunction(engine->L, l_set_log_level);
	lua_setglobal(engine->L, "set_log_level");
	lua_pushcfunction(engine->L, l_get_log_level);
	lua_setglobal(engine->L, "get_log_level");
	lua_pushcfunction(engine->L, l_add_log_group);
	lua_setglobal(engine->L, "add_log_group");
	lua_pushcfunction(engine->L, l_del_log_group);
	lua_setglobal(engine->L, "del_log_group");
	lua_pushcfunction(engine->L, l_setuser);
	lua_setglobal(engine->L, "user");
	lua_pushcfunction(engine->L, l_hint_root_file);
	lua_setglobal(engine->L, "_hint_root_file");
	lua_pushliteral(engine->L, libknot_SONAME);
	lua_setglobal(engine->L, "libknot_SONAME");
	lua_pushliteral(engine->L, libzscanner_SONAME);
	lua_setglobal(engine->L, "libzscanner_SONAME");
	lua_pushcfunction(engine->L, l_tojson);
	lua_setglobal(engine->L, "tojson");
	lua_pushcfunction(engine->L, l_fromjson);
	lua_setglobal(engine->L, "fromjson");
	/* Random number generator */
	lua_getfield(engine->L, LUA_GLOBALSINDEX, "math");
	lua_getfield(engine->L, -1, "randomseed");
	lua_remove(engine->L, -2);
	lua_Number seed = kr_rand_bytes(sizeof(lua_Number));
	lua_pushnumber(engine->L, seed);
	lua_call(engine->L, 1, 0);
	return kr_ok();
}

/**
 * Start luacov measurement and store results to file specified by
 * KRESD_COVERAGE_STATS environment variable.
 * Do nothing if the variable is not set.
 */
static void init_measurement(struct engine *engine)
{
	const char * const statspath = getenv("KRESD_COVERAGE_STATS");
	if (!statspath)
		return;

	char * snippet = NULL;
	int ret = asprintf(&snippet,
		"_luacov_runner = require('luacov.runner')\n"
		"_luacov_runner.init({\n"
		"	statsfile = '%s',\n"
		"	exclude = {'test', 'tapered', 'lua/5.1'},\n"
		"})\n"
		"jit.off()\n", statspath
	);
	if (kr_fails_assert(ret > 0))
		return;

	ret = luaL_loadstring(engine->L, snippet);
	if (kr_fails_assert(ret == 0)) {
		free(snippet);
		return;
	}
	lua_call(engine->L, 0, 0);
	free(snippet);
}

int init_lua(struct engine *engine) {
	if (!engine) {
		return kr_error(EINVAL);
	}

	/* Use libdir path for including Lua scripts */
	char l_paths[MAXPATHLEN] = { 0 };
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wformat" /* %1$ is not in C standard */
	/* Save original package.path to package._path */
	snprintf(l_paths, MAXPATHLEN - 1,
		 "if package._path == nil then package._path = package.path end\n"
		 "package.path = '%1$s/?.lua;%1$s/?/init.lua;'..package._path\n"
		 "if package._cpath == nil then package._cpath = package.cpath end\n"
		 "package.cpath = '%1$s/?%2$s;'..package._cpath\n",
		 LIBDIR, LIBEXT);
	#pragma GCC diagnostic pop

	int ret = l_dobytecode(engine->L, l_paths, strlen(l_paths), "");
	if (ret != 0) {
		lua_pop(engine->L, 1);
		return ret;
	}
	return 0;
}


int engine_init(struct engine *engine, knot_mm_t *pool)
{
	if (engine == NULL) {
		return kr_error(EINVAL);
	}

	memset(engine, 0, sizeof(*engine));
	engine->pool = pool;

	/* Initialize state */
	int ret = init_state(engine);
	if (ret != 0) {
		engine_deinit(engine);
		return ret;
	}
	init_measurement(engine);
	/* Initialize resolver */
	ret = init_resolver(engine);
	if (ret != 0) {
		engine_deinit(engine);
		return ret;
	}
	/* Initialize network */
	network_init(&engine->net, uv_default_loop(), TCP_BACKLOG_DEFAULT);

	/* Initialize lua */
	ret = init_lua(engine);
	if (ret != 0) {
		engine_deinit(engine);
		return ret;
	}

	return ret;
}

/** Unregister a (found) module */
static void engine_unload(struct engine *engine, struct kr_module *module)
{
	auto_free char *name = module->name ? strdup(module->name) : NULL;
	kr_module_unload(module); /* beware: lua/C mix, could be confusing */
	/* Clear in Lua world, but not for embedded modules ('cache' in particular). */
	if (name && !kr_module_get_embedded(name)) {
		lua_pushnil(engine->L);
		lua_setglobal(engine->L, name);
	}
	free(module);
}

void engine_deinit(struct engine *engine)
{
	if (!engine || kr_fails_assert(engine->L))
		return;
	/* Only close sockets and services; no need to clean up mempool. */

	/* Network deinit is split up.  We first need to stop listening,
	 * then we can unload modules during which we still want
	 * e.g. the endpoint kind registry to work (inside ->net),
	 * and this registry deinitization uses the lua state. */
	network_close_force(&engine->net);
	for (size_t i = 0; i < engine->modules.len; ++i) {
		engine_unload(engine, engine->modules.at[i]);
	}
	kr_zonecut_deinit(&engine->resolver.root_hints);
	kr_cache_close(&engine->resolver.cache);

	/* The LRUs are currently malloc-ated and need to be freed. */
	lru_free(engine->resolver.cache_cookie);

	network_deinit(&engine->net);
	ffimodule_deinit(engine->L);
	lua_close(engine->L);

	/* Free data structures */
	array_clear(engine->modules);
	array_clear(engine->backends);
	kr_ta_clear(&engine->resolver.trust_anchors);
	kr_ta_clear(&engine->resolver.negative_anchors);
	free(engine->hostname);
}

int engine_pcall(lua_State *L, int argc)
{
	return lua_pcall(L, argc, LUA_MULTRET, 0);
}

int engine_cmd(lua_State *L, const char *str, bool raw)
{
	if (L == NULL) {
		return kr_error(ENOEXEC);
	}

	/* Evaluate results */
	lua_getglobal(L, "eval_cmd");
	lua_pushstring(L, str);
	lua_pushboolean(L, raw);

	/* Check result. */
	return engine_pcall(L, 2);
}

int engine_load_sandbox(struct engine *engine)
{
	/* Init environment */
	int ret = luaL_dofile(engine->L, LIBDIR "/sandbox.lua");
	if (ret != 0) {
		fprintf(stderr, "[system] error %s\n", lua_tostring(engine->L, -1));
		lua_pop(engine->L, 1);
		return kr_error(ENOEXEC);
	}
	ret = ffimodule_init(engine->L);
	return ret;
}

int engine_loadconf(struct engine *engine, const char *config_path)
{
	if (kr_fails_assert(config_path))
		return kr_error(EINVAL);

	char cwd[PATH_MAX];
	get_workdir(cwd, sizeof(cwd));
	kr_log_verbose("[system] loading config '%s' (workdir '%s')\n", config_path, cwd);

	int ret = luaL_dofile(engine->L, config_path);
	if (ret != 0) {
		fprintf(stderr, "[system] error while loading config: "
			"%s (workdir '%s')\n", lua_tostring(engine->L, -1), cwd);
		lua_pop(engine->L, 1);
	}
	return ret;
}

int engine_start(struct engine *engine)
{
	/* Clean up stack */
	lua_settop(engine->L, 0);

	return kr_ok();
}

void engine_stop(struct engine *engine)
{
	if (!engine) {
		return;
	}
	uv_stop(uv_default_loop());
}

/** @internal Find matching module */
static size_t module_find(module_array_t *mod_list, const char *name)
{
	size_t found = mod_list->len;
	for (size_t i = 0; i < mod_list->len; ++i) {
		struct kr_module *mod = mod_list->at[i];
		if (strcmp(mod->name, name) == 0) {
			found = i;
			break;
		}
	}
	return found;
}

int engine_register(struct engine *engine, const char *name, const char *precedence, const char* ref)
{
	if (kr_fails_assert(engine && name))
		return kr_error(EINVAL);
	/* Make sure module is unloaded */
	(void) engine_unregister(engine, name);
	/* Find the index of referenced module. */
	module_array_t *mod_list = &engine->modules;
	size_t ref_pos = mod_list->len;
	if (precedence && ref) {
		ref_pos = module_find(mod_list, ref);
		if (ref_pos >= mod_list->len) {
			return kr_error(EIDRM);
		}
	}
	/* Attempt to load binary module */
	struct kr_module *module = malloc(sizeof(*module));
	if (!module) {
		return kr_error(ENOMEM);
	}
	module->data = engine; /*< some outside modules may still use this value */

	int ret = kr_module_load(module, name, LIBDIR "/kres_modules");
	if (ret == 0) {
		/* We have a C module, loaded and init() was called.
		 * Now we need to prepare the lua side. */
		lua_State *L = engine->L;
		lua_getglobal(L, "modules_create_table_for_c");
		lua_pushpointer(L, module);
		if (lua_isnil(L, -2)) {
			/* When loading the three embedded modules, we don't
			 * have the "modules_*" lua function yet, but fortunately
			 * we don't need it there.  Let's just check they're embedded.
			 * TODO: solve this better *without* breaking stuff. */
			lua_pop(L, 2);
			if (module->lib != RTLD_DEFAULT) {
				ret = kr_error(1);
				lua_pushliteral(L, "missing modules_create_table_for_c()");
			}
		} else {
			ret = engine_pcall(L, 1);
		}
		if (kr_fails_assert(ret == 0)) {  /* probably not critical, but weird */
			kr_log_error(LOG_GRP_SYSTEM, "[system] internal error when loading C module %s: %s\n",
					module->name, lua_tostring(L, -1));
			lua_pop(L, 1);
		}

	} else if (ret == kr_error(ENOENT)) {
		/* No luck with C module, so try to load and .init() lua module. */
		ret = ffimodule_register_lua(engine, module, name);
		if (ret != 0) {
			kr_log_error(LOG_GRP_SYSTEM, "[system] failed to load module '%s'\n", name);
		}

	} else if (ret == kr_error(ENOTSUP)) {
		/* Print a more helpful message when module is linked against an old resolver ABI. */
		kr_log_error(LOG_GRP_SYSTEM, "[system] module '%s' links to unsupported ABI, please rebuild it\n", name);
	}

	if (ret != 0) {
		engine_unload(engine, module);
		return ret;
	}

	/* Push to the right place in engine->modules */
	if (array_push(engine->modules, module) < 0) {
		engine_unload(engine, module);
		return kr_error(ENOMEM);
	}
	if (precedence) {
		struct kr_module **arr = mod_list->at;
		size_t emplacement = mod_list->len;
		if (strcasecmp(precedence, ">") == 0) {
			if (ref_pos + 1 < mod_list->len)
				emplacement = ref_pos + 1; /* Insert after target */
		}
		if (strcasecmp(precedence, "<") == 0) {
			emplacement = ref_pos; /* Insert at target */
		}
		/* Move the tail if it has some elements. */
		if (emplacement + 1 < mod_list->len) {
			memmove(&arr[emplacement + 1], &arr[emplacement], sizeof(*arr) * (mod_list->len - (emplacement + 1)));
			arr[emplacement] = module;
		}
	}

	return kr_ok();
}

int engine_unregister(struct engine *engine, const char *name)
{
	module_array_t *mod_list = &engine->modules;
	size_t found = module_find(mod_list, name);
	if (found < mod_list->len) {
		engine_unload(engine, mod_list->at[found]);
		array_del(*mod_list, found);
		return kr_ok();
	}

	return kr_error(ENOENT);
}

