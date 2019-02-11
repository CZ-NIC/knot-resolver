/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <contrib/cleanup.h>
#include <ccan/json/json.h>
#include <ccan/asprintf/asprintf.h>
#include <uv.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <sys/param.h>
#include <libzscanner/scanner.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "daemon/bindings/impl.h"

#include "kresconfig.h"
#include "daemon/engine.h"
#include "daemon/ffimodule.h"
#include "lib/nsrep.h"
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
	#ifdef ENABLE_COOKIES
	#define LRU_COOKIES_SIZE LRU_RTT_SIZE /**< DNS cookies cache size. */
	#else
	#define LRU_COOKIES_SIZE LRU_ASSOC /* simpler than guards everywhere */
	#endif
#endif

/** @internal Compatibility wrapper for Lua < 5.2 */
#if LUA_VERSION_NUM < 502
#define lua_rawlen(L, obj) lua_objlen((L), (obj))
#endif

/**@internal Maximum number of incomplete TCP connections in queue.
* Default is from Redis and Apache. */
#ifndef TCP_BACKLOG_DEFAULT
#define TCP_BACKLOG_DEFAULT 511
#endif

/* Cleanup engine state every 5 minutes */
const size_t CLEANUP_TIMER = 5*60*1000;

/* Execute byte code */
#define l_dobytecode(L, arr, len, name) \
	(luaL_loadbuffer((L), (arr), (len), (name)) || lua_pcall((L), 0, LUA_MULTRET, 0))
/** Load file in a sandbox environment. */
#define l_dosandboxfile(L, filename) \
	(luaL_loadfile((L), (filename)) || engine_pcall((L), 0))

/*
 * Global bindings.
 */

/** Register module callback into Lua world. */
#define REGISTER_MODULE_CALL(L, module, cb, name) do { \
	lua_pushlightuserdata((L), (module)); \
	lua_pushlightuserdata((L), (cb)); \
	lua_pushcclosure((L), l_trampoline, 2); \
	lua_setfield((L), -2, (name)); \
	} while (0)

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
		"map(expr)\n    run expression on all workers\n"
		"net\n    network configuration\n"
		"cache\n    network configuration\n"
		"modules\n    modules configuration\n"
		"kres\n    resolver services\n"
		"trust_anchors\n    configure trust anchors\n"
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
	engine_stop(engine_luaget(L));
	return 0;
}

/** Toggle verbose mode. */
static int l_verbose(lua_State *L)
{
	if (lua_isboolean(L, 1) || lua_isnumber(L, 1)) {
		kr_verbose_set(lua_toboolean(L, 1));
	}
	lua_pushboolean(L, kr_verbose_status);
	return 1;
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
	struct engine *engine = engine_luaget(L);
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

char *engine_get_moduledir(struct engine *engine) {
	return engine->moduledir;
}

int engine_set_moduledir(struct engine *engine, const char *moduledir) {
	if (!engine || !moduledir) {
		return kr_error(EINVAL);
	}

	char *new_moduledir = strdup(moduledir);
	if (!new_moduledir) {
		return kr_error(ENOMEM);
	}
	if (engine->moduledir) {
		free(engine->moduledir);
	}
	engine->moduledir = new_moduledir;

	/* Use module path for including Lua scripts */
	char l_paths[MAXPATHLEN] = { 0 };
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wformat" /* %1$ is not in C standard */
	/* Save original package.path to package._path */
	snprintf(l_paths, MAXPATHLEN - 1,
		 "if package._path == nil then package._path = package.path end\n"
		 "package.path = '%1$s/?.lua;%1$s/?/init.lua;'..package._path\n"
		 "if package._cpath == nil then package._cpath = package.cpath end\n"
		 "package.cpath = '%1$s/?%2$s;'..package._cpath\n",
		 new_moduledir, LIBEXT);
	#pragma GCC diagnostic pop

	int ret = l_dobytecode(engine->L, l_paths, strlen(l_paths), "");
	if (ret != 0) {
		lua_pop(engine->L, 1);
		return ret;
	}
	return 0;
}

/** Return hostname. */
static int l_moduledir(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	if (lua_gettop(L) == 0) {
		lua_pushstring(L, engine_get_moduledir(engine));
		return 1;
	}
	if ((lua_gettop(L) != 1) || !lua_isstring(L, 1))
		lua_error_p(L, "moduledir takes at most one parameter: (\"directory\")");

	if (engine_set_moduledir(engine, lua_tostring(L, 1)) != 0)
		lua_error_p(L, "setting moduledir failed");

	lua_pushstring(L, engine_get_moduledir(engine));
	return 1;
}

/** Load root hints from zonefile. */
static int l_hint_root_file(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	struct kr_context *ctx = &engine->resolver;
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
			lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
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

/** @internal Throw Lua error if expr is false */
#define expr_checked(expr) \
	if (!(expr)) { lua_pushboolean(L, false); lua_rawseti(L, -2, lua_rawlen(L, -2) + 1); continue; }

static int l_map(lua_State *L)
{
	if (lua_gettop(L) != 1 || !lua_isstring(L, 1))
		lua_error_p(L, "map('string with a lua expression')");

	struct engine *engine = engine_luaget(L);
	const char *cmd = lua_tostring(L, 1);
	uint32_t len = strlen(cmd);
	lua_newtable(L);

	/* Execute on leader instance */
	int ntop = lua_gettop(L);
	engine_cmd(L, cmd, true);
	lua_settop(L, ntop + 1); /* Push only one return value to table */
	lua_rawseti(L, -2, 1);

	for (size_t i = 0; i < engine->ipc_set.len; ++i) {
		int fd = engine->ipc_set.at[i];
		/* Send command */
		expr_checked(write(fd, &len, sizeof(len)) == sizeof(len));
		expr_checked(write(fd, cmd, len) == len);
		/* Read response */
		uint32_t rlen = 0;
		if (read(fd, &rlen, sizeof(rlen)) == sizeof(rlen)) {
			expr_checked(rlen < UINT32_MAX);
			auto_free char *rbuf = malloc(rlen + 1);
			expr_checked(rbuf != NULL);
			expr_checked(read(fd, rbuf, rlen) == rlen);
			rbuf[rlen] = '\0';
			/* Unpack from JSON */
			JsonNode *root_node = json_decode(rbuf);
			if (root_node) {
				l_unpack_json(L, root_node);
			} else {
				lua_pushlstring(L, rbuf, rlen);
			}
			json_delete(root_node);
			lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
			continue;
		}
		/* Didn't respond */
		lua_pushboolean(L, false);
		lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
	}
	return 1;
}

#undef expr_checked


/** Trampoline function for module properties. */
static int l_trampoline(lua_State *L)
{
	struct kr_module *module = lua_touserdata(L, lua_upvalueindex(1));
	void* callback = lua_touserdata(L, lua_upvalueindex(2));
	struct engine *engine = engine_luaget(L);
	if (!module)
		lua_error_p(L, "module closure missing upvalue");

	/* Now we only have property callback or config,
	 * if we expand the callables, we might need a callback_type.
	 */
	const char *args = NULL;
	auto_free char *cleanup_args = NULL;
	if (lua_gettop(L) > 0) {
		if (lua_istable(L, 1) || lua_isboolean(L, 1)) {
			cleanup_args = l_pack_json(L, 1);
			args = cleanup_args;
		} else {
			args = lua_tostring(L, 1);
		}
	}
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wpedantic" /* void* vs. function pointer */
	if (callback == module->config) {
		module->config(module, args);
	} else {
		kr_prop_cb *prop = (kr_prop_cb *)callback;
		auto_free char *ret = prop(engine, module, args);
		if (!ret) { /* No results */
			return 0;
		}
		JsonNode *root_node = json_decode(ret);
		if (root_node) {
			l_unpack_json(L, root_node);
		} else {
			lua_pushstring(L, ret);
		}
		json_delete(root_node);
		return 1;
	}
	#pragma GCC diagnostic pop

	/* No results */
	return 0;
}

/*
 * Engine API.
 */

static int init_resolver(struct engine *engine)
{
	/* Note: it had been zored by engine_init(). */
	/* Open resolution context */
	engine->resolver.trust_anchors = map_make(NULL);
	engine->resolver.negative_anchors = map_make(NULL);
	engine->resolver.pool = engine->pool;
	engine->resolver.modules = &engine->modules;
	engine->resolver.cache_rtt_tout_retry_interval = KR_NS_TIMEOUT_RETRY_INTERVAL;
	/* Create OPT RR */
	engine->resolver.opt_rr = mm_alloc(engine->pool, sizeof(knot_rrset_t));
	if (!engine->resolver.opt_rr) {
		return kr_error(ENOMEM);
	}
	knot_edns_init(engine->resolver.opt_rr, KR_EDNS_PAYLOAD, 0, KR_EDNS_VERSION, engine->pool);
	/* Use default TLS padding */
	engine->resolver.tls_padding = -1;
	/* Empty init; filled via ./lua/config.lua */
	kr_zonecut_init(&engine->resolver.root_hints, (const uint8_t *)"", engine->pool);
	/* Open NS rtt + reputation cache */
	lru_create(&engine->resolver.cache_rtt, LRU_RTT_SIZE, engine->pool, NULL);
	lru_create(&engine->resolver.cache_rep, LRU_REP_SIZE, engine->pool, NULL);
	lru_create(&engine->resolver.cache_cookie, LRU_COOKIES_SIZE, engine->pool, NULL);

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
	lua_gc(engine->L, LUA_GCSTOP, 0);
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
	lua_pushcfunction(engine->L, l_moduledir);
	lua_setglobal(engine->L, "moduledir");
	lua_pushcfunction(engine->L, l_verbose);
	lua_setglobal(engine->L, "verbose");
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
	lua_pushcfunction(engine->L, l_map);
	lua_setglobal(engine->L, "map");
	lua_pushlightuserdata(engine->L, engine);
	lua_setglobal(engine->L, "__engine");
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
	assert(ret > 0);

	ret = luaL_loadstring(engine->L, snippet);
	assert(ret == 0);
	lua_call(engine->L, 0, 0);
	free(snippet);
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

	return ret;
}

static void engine_unload(struct engine *engine, struct kr_module *module)
{
	/* Unregister module */
	auto_free char *name = strdup(module->name);
	kr_module_unload(module);
	/* Clear in Lua world, but not for embedded modules ('cache' in particular). */
	if (name && !kr_module_embedded(name)) {
		lua_pushnil(engine->L);
		lua_setglobal(engine->L, name);
	}
	free(module);
}

void engine_deinit(struct engine *engine)
{
	if (engine == NULL) {
		return;
	}

	/* Only close sockets and services,
	 * no need to clean up mempool. */
	network_deinit(&engine->net);
	kr_zonecut_deinit(&engine->resolver.root_hints);
	kr_cache_close(&engine->resolver.cache);

	/* The lru keys are currently malloc-ated and need to be freed. */
	lru_free(engine->resolver.cache_rtt);
	lru_free(engine->resolver.cache_rep);
	lru_free(engine->resolver.cache_cookie);

	/* Clear IPC pipes */
	for (size_t i = 0; i < engine->ipc_set.len; ++i) {
		close(engine->ipc_set.at[i]);
	}

	/* Unload modules and engine. */
	for (size_t i = 0; i < engine->modules.len; ++i) {
		engine_unload(engine, engine->modules.at[i]);
	}
	if (engine->L) {
		lua_close(engine->L);
	}

	/* Free data structures */
	array_clear(engine->modules);
	array_clear(engine->backends);
	array_clear(engine->ipc_set);
	kr_ta_clear(&engine->resolver.trust_anchors);
	kr_ta_clear(&engine->resolver.negative_anchors);
	free(engine->hostname);
	free(engine->moduledir);
}

int engine_pcall(lua_State *L, int argc)
{
#if LUA_VERSION_NUM >= 502
	lua_getglobal(L, "_SANDBOX");
	lua_setupvalue(L, -(2 + argc), 1);
#endif
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

int engine_ipc(struct engine *engine, const char *expr)
{
	if (engine == NULL || engine->L == NULL) {
		return kr_error(ENOEXEC);
	}

	/* Run expression and serialize response. */
	engine_cmd(engine->L, expr, true);
	if (lua_gettop(engine->L) > 0) {
		l_tojson(engine->L);
		return 1;
	} else {
		return 0;
	}
}

int engine_load_sandbox(struct engine *engine)
{
	/* Init environment */
    int ret = l_dosandboxfile(engine->L, LIBDIR "/sandbox.lua");
	if (ret != 0) {
		fprintf(stderr, "[system] error %s\n", lua_tostring(engine->L, -1));
		lua_pop(engine->L, 1);
		return kr_error(ENOEXEC);
	}
	return kr_ok();
}

int engine_loadconf(struct engine *engine, const char *config_path)
{
	assert(config_path != NULL);
	int ret = l_dosandboxfile(engine->L, config_path);
	if (ret != 0) {
		fprintf(stderr, "%s\n", lua_tostring(engine->L, -1));
		lua_pop(engine->L, 1);
	}
	return ret;
}

int engine_load_defaults(struct engine *engine)
{
	/* Load defaults */
	int ret = l_dosandboxfile(engine->L, LIBDIR "/config.lua");
	if (ret != 0) {
		fprintf(stderr, "%s\n", lua_tostring(engine->L, -1));
		lua_pop(engine->L, 1);
	}
	return ret;
}

int engine_start(struct engine *engine)
{
	/* Clean up stack and restart GC */
	lua_settop(engine->L, 0);
	lua_gc(engine->L, LUA_GCCOLLECT, 0);
	lua_gc(engine->L, LUA_GCSETSTEPMUL, 50);
	lua_gc(engine->L, LUA_GCSETPAUSE, 400);
	lua_gc(engine->L, LUA_GCRESTART, 0);

	return kr_ok();
}

void engine_stop(struct engine *engine)
{
	if (!engine) {
		return;
	}
	uv_stop(uv_default_loop());
}

/** Register module properties in Lua environment, if any. */
static int register_properties(struct engine *engine, struct kr_module *module)
{
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wpedantic" /* casts in lua_pushlightuserdata() */
	if (!module->config && !module->props) {
		return kr_ok();
	}
	lua_newtable(engine->L);
	if (module->config != NULL) {
		REGISTER_MODULE_CALL(engine->L, module, module->config, "config");
	}

	const struct kr_prop *p = module->props == NULL ? NULL : module->props();
	for (; p && p->name; ++p) {
		if (p->cb != NULL) {
			REGISTER_MODULE_CALL(engine->L, module, p->cb, p->name);
		}
	}
	lua_setglobal(engine->L, module->name);
	#pragma GCC diagnostic pop

	/* Register module in Lua env */
	lua_getglobal(engine->L, "modules_register");
	lua_getglobal(engine->L, module->name);
	if (engine_pcall(engine->L, 1) != 0) {
		lua_pop(engine->L, 1);
	}

	return kr_ok();
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
	if (engine == NULL || name == NULL) {
		return kr_error(EINVAL);
	}
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
	module->data = engine;
	int ret = kr_module_load(module, name, engine->moduledir);
	/* Load Lua module if not a binary */
	if (ret == kr_error(ENOENT)) {
		ret = ffimodule_register_lua(engine, module, name);
	} else if (ret == kr_error(ENOTSUP)) {
		/* Print a more helpful message when module is linked against an old resolver ABI. */
		fprintf(stderr, "[system] module '%s' links to unsupported ABI, please rebuild it\n", name);
	}
	if (ret != 0) {
		free(module);
		return ret;
	}
	if (array_push(engine->modules, module) < 0) {
		engine_unload(engine, module);
		return kr_error(ENOMEM);
	}
	/* Evaluate precedence operator */
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

	return register_properties(engine, module);
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

struct engine *engine_luaget(lua_State *L)
{
	lua_getglobal(L, "__engine");
	struct engine *engine = lua_touserdata(L, -1);
	if (!engine) luaL_error(L, "internal error, empty engine pointer");
	lua_pop(L, 1);
	return engine;
}
