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

#include <ccan/json/json.h>
#include <uv.h>
#include <unistd.h>
#include <libknot/internal/mempattern.h>
/* #include <libknot/internal/namedb/namedb_trie.h> @todo Not supported (doesn't keep value copy) */
#include <libknot/internal/namedb/namedb_lmdb.h>

#include "daemon/engine.h"
#include "daemon/bindings.h"
#include "daemon/ffimodule.h"
#include "lib/cache.h"
#include "lib/defines.h"

/** @internal Compatibility wrapper for Lua < 5.2 */
#if LUA_VERSION_NUM < 502
#define lua_rawlen(L, obj) lua_objlen((L), (obj))
#endif

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
		;
	lua_pushstring(L, help_str);
	return 1;
}

/** Quit current executable. */
static int l_quit(lua_State *L)
{
	/* Stop engine */
	engine_stop(engine_luaget(L));
	/* No results */
	return 0;
}

/** Return hostname. */
static int l_hostname(lua_State *L)
{
	char host_str[KNOT_DNAME_MAXLEN];
	gethostname(host_str, sizeof(host_str));
	lua_pushstring(L, host_str);
	return 1;
}

/** Unpack JSON object to table */
static void l_unpack_json(lua_State *L, JsonNode *table)
{
	lua_newtable(L);
	JsonNode *node = NULL;
	json_foreach(node, table) {
		/* Push node value */
		switch(node->tag) {
		case JSON_OBJECT: /* as array */
		case JSON_ARRAY:  l_unpack_json(L, node); break;
		case JSON_STRING: lua_pushstring(L, node->string_); break;
		case JSON_NUMBER: lua_pushnumber(L, node->number_); break;
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

/** Trampoline function for module properties. */
static int l_trampoline(lua_State *L)
{
	struct kr_module *module = lua_touserdata(L, lua_upvalueindex(1));
	void* callback = lua_touserdata(L, lua_upvalueindex(2));
	struct engine *engine = engine_luaget(L);
	if (!module) {
		lua_pushstring(L, "module closure missing upvalue");
		lua_error(L);
	}

	/* Now we only have property callback or config,
	 * if we expand the callables, we might need a callback_type.
	 */
	const char *args = NULL;
	if (lua_gettop(L) > 0) {
		args = lua_tostring(L, 1);
	}
	if (callback == module->config) {
		module->config(module, args);
	} else {
		kr_prop_cb *prop = (kr_prop_cb *)callback;
		auto_free char *ret = prop(engine, module, args);
		if (!ret) { /* No results */
			return 0;
		}
		JsonNode *root_node = json_decode(ret);
		if (root_node->tag == JSON_OBJECT || root_node->tag == JSON_ARRAY) {
			l_unpack_json(L, root_node);
		} else {
			lua_pushstring(L, ret);
		}
		json_delete(root_node);
		return 1;
	}

	/* No results */
	return 0;
}

/*
 * Engine API.
 */

/** @internal Make lmdb options. */
void *namedb_lmdb_mkopts(const char *conf, size_t maxsize)
{
	struct namedb_lmdb_opts *opts = malloc(sizeof(*opts));
	if (opts) {
		memset(opts, 0, sizeof(*opts));
		opts->path = (conf && strlen(conf)) ? conf : ".";
		opts->mapsize = maxsize;
	}
	return opts;
}

static int init_resolver(struct engine *engine)
{
	/* Open resolution context */
	engine->resolver.modules = &engine->modules;

	/* Load basic modules */
	engine_register(engine, "iterate");
	engine_register(engine, "rrcache");
	engine_register(engine, "pktcache");

	/* Initialize storage backends */
	struct storage_api lmdb = {
		"lmdb://", namedb_lmdb_api, namedb_lmdb_mkopts
	};

	return array_push(engine->storage_registry, lmdb);
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
	lua_pushlightuserdata(engine->L, engine);
	lua_setglobal(engine->L, "__engine");
	return kr_ok();
}

int engine_init(struct engine *engine, mm_ctx_t *pool)
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
	}
	/* Initialize resolver */
	ret = init_resolver(engine);
	if (ret != 0) {
		return ret;
	}
	/* Initialize network */
	network_init(&engine->net, uv_default_loop());

	return ret;
}

static void engine_unload(struct engine *engine, struct kr_module *module)
{
	/* Unregister module */
	auto_free char *name = strdup(module->name);
	kr_module_unload(module);
	/* Clear in Lua world */
	if (name) {
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

	network_deinit(&engine->net);
	kr_cache_close(engine->resolver.cache);
	engine->resolver.cache = NULL;

	/* Unload modules. */
	for (size_t i = 0; i < engine->modules.len; ++i) {
		engine_unload(engine, engine->modules.at[i]);
	}
	array_clear(engine->modules);
	array_clear(engine->storage_registry);

	if (engine->L) {
		lua_close(engine->L);
	}

}

int engine_pcall(lua_State *L, int argc)
{
#if LUA_VERSION_NUM >= 502
	lua_getglobal(L, "_SANDBOX");
	lua_setupvalue(L, -(2 + argc), 1);
#endif
	return lua_pcall(L, argc, LUA_MULTRET, 0);
}

int engine_cmd(struct engine *engine, const char *str)
{
	if (engine == NULL || engine->L == NULL) {
		return kr_error(ENOEXEC);
	}

	/* Evaluate results */
	lua_getglobal(engine->L, "eval_cmd");
	lua_pushstring(engine->L, str);

	/* Check result. */
	if (engine_pcall(engine->L, 1) != 0) {
		fprintf(stderr, "%s\n", lua_tostring(engine->L, -1));
		lua_pop(engine->L, 1);
		return kr_error(EINVAL);
	}

	return kr_ok();
}

/* Execute byte code */
#define l_dobytecode(L, arr, len, name) \
	(luaL_loadbuffer((L), (arr), (len), (name)) || lua_pcall((L), 0, LUA_MULTRET, 0))
/** Load file in a sandbox environment. */
#define l_dosandboxfile(L, filename) \
	(luaL_loadfile((L), (filename)) || engine_pcall((L), 0))

static int engine_loadconf(struct engine *engine)
{
	/* Init environment */
	static const char sandbox_bytecode[] = {
		#include "daemon/lua/sandbox.inc"
	};
	if (l_dobytecode(engine->L, sandbox_bytecode, sizeof(sandbox_bytecode), "init") != 0) {
		fprintf(stderr, "[system] error %s\n", lua_tostring(engine->L, -1));
		lua_pop(engine->L, 1);
		return kr_error(ENOEXEC);
	}
	/* Use module path for including Lua scripts */
	engine_cmd(engine, "package.path = package.path..';" PREFIX MODULEDIR "/?.lua'");

	/* Load config file */
	int ret = 0;
	if(access("config", F_OK ) != -1 ) {
		ret = l_dosandboxfile(engine->L, "config");
	} else {
		/* Load defaults */
		static const char config_bytecode[] = {
			#include "daemon/lua/config.inc"
		};
		ret = l_dobytecode(engine->L, config_bytecode, sizeof(config_bytecode), "config");
	}

	/* Evaluate */
	if (ret != 0) {
		fprintf(stderr, "%s\n", lua_tostring(engine->L, -1));
		lua_pop(engine->L, 1);
	}
	return ret;
}

int engine_start(struct engine *engine)
{
	/* Load configuration. */
	int ret = engine_loadconf(engine);
	if (ret != 0) {
		return ret;
	}

	return kr_ok();
}

void engine_stop(struct engine *engine)
{
	uv_stop(uv_default_loop());
}

/** Register module properties in Lua environment */
static int register_properties(struct engine *engine, struct kr_module *module)
{
	lua_newtable(engine->L);
	if (module->config != NULL) {
		REGISTER_MODULE_CALL(engine->L, module, module->config, "config");
	}
	for (struct kr_prop *p = module->props; p->name; ++p) {
		if (p->cb != NULL && p->name != NULL) {
			REGISTER_MODULE_CALL(engine->L, module, p->cb, p->name);
		}
	}
	lua_setglobal(engine->L, module->name);

	/* Register module in Lua env */
	lua_getglobal(engine->L, "modules_register");
	lua_getglobal(engine->L, module->name);
	if (engine_pcall(engine->L, 1) != 0) {
		lua_pop(engine->L, 1);
	}

	return kr_ok();
}

int engine_register(struct engine *engine, const char *name)
{
	if (engine == NULL || name == NULL) {
		return kr_error(EINVAL);
	}

	/* Make sure module is unloaded */
	(void) engine_unregister(engine, name);
	/* Attempt to load binary module */
	struct kr_module *module = malloc(sizeof(*module));
	if (!module) {
		return kr_error(ENOMEM);
	}
	module->data = engine;
	int ret = kr_module_load(module, name, NULL);
	/* Load Lua module if not a binary */
	if (ret == kr_error(ENOENT)) {
		ret = ffimodule_register_lua(engine, module, name);
	}
	if (ret != 0) {
		free(module);
		return ret;
	}

	if (array_push(engine->modules, module) < 0) {
		engine_unload(engine, module);
		return kr_error(ENOMEM);
	}

	/* Register properties */
	if (module->props) {
		return register_properties(engine, module);
	}

	return kr_ok();
}

int engine_unregister(struct engine *engine, const char *name)
{
	/* Find matching module. */
	module_array_t *mod_list = &engine->modules;
	size_t found = mod_list->len;
	for (size_t i = 0; i < mod_list->len; ++i) {
		struct kr_module *mod = mod_list->at[i];
		if (strcmp(mod->name, name) == 0) {
			found = i;
			break;
		}
	}
	if (found < mod_list->len) {
		engine_unload(engine, mod_list->at[found]);
		array_del(*mod_list, found);
		return kr_ok();
	}

	return kr_error(ENOENT);
}

void engine_lualib(struct engine *engine, const char *name, lua_CFunction lib_cb)
{
	if (engine != NULL) {
#if LUA_VERSION_NUM >= 502
		luaL_requiref(engine->L, name, lib_cb, 1);
		lua_pop(engine->L, 1);
#else
		lib_cb(engine->L);
#endif
	}
}

struct engine *engine_luaget(lua_State *L)
{
	lua_getglobal(L, "__engine");
	struct engine *engine = lua_touserdata(L, -1);
	lua_pop(engine->L, 1);
	return engine;
}
