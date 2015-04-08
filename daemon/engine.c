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

#include <uv.h>
#include <unistd.h>
#include <libknot/internal/mem.h>

#include "daemon/engine.h"
#include "daemon/bindings.h"
#include "lib/cache.h"
#include "lib/defines.h"

/*
 * Global bindings.
 */

/** Register module callback into Lua world. */
#define REGISTER_MODULE_CALL(L, module, cb, name) \
	lua_pushlightuserdata((L), (module)); \
	lua_pushlightuserdata((L), (cb)); \
	lua_pushcclosure((L), l_trampoline, 2); \
	lua_setfield((L), -2, (name))

/** Print help and available commands. */
static int l_help(lua_State *L)
{
	static const char *help_str = 
		"help()\n    show this help\n"
		"quit()\n    quit\n"
		"modules.list()\n    list modules\n"
		"modules.load()\n    load module\n"
		"modules.unload()\n    unload module\n"
		"cache.open(path, max_size)\n    open cache\n"
		"cache.close()\n    close cache\n"
		;
	puts(help_str);
	/* No results */
	return 0;
}

/** Quit current executable. */
static int l_quit(lua_State *L)
{
	/* Stop engine */
	engine_stop(engine_luaget(L));
	/* No results */
	return 0;
}

/** Trampoline function for module properties. */
static int l_trampoline(lua_State *L)
{
	struct kr_module *module = lua_touserdata(L, lua_upvalueindex(1));
	void* callback = lua_touserdata(L, lua_upvalueindex(2));
	struct engine *engine = engine_luaget(L);

	/* Now we only have property callback or config,
	 * if we expand the callables, we might need a callback_type.
	 */
	if (callback == module->config) {
		const char *param = lua_tostring(L, 1);
		module->config(module, param);
	} else {
		kr_prop_cb *prop = (kr_prop_cb *)callback;
		auto_free char *ret = prop(engine, module, lua_tostring(L, 1));
		lua_pushstring(L, ret);
		return 1;
	}

	/* No results */
	return 0;
}

/*
 * Engine API.
 */

static int init_resolver(struct engine *engine)
{
	/* Open resolution context */
	engine->resolver.modules = &engine->modules;

	/* Load basic modules */
	engine_register(engine, "iterate");
	engine_register(engine, "itercache");

	return kr_ok();
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

void engine_deinit(struct engine *engine)
{
	if (engine == NULL) {
		return;
	}

	network_deinit(&engine->net);

	/* Unload modules. */
	for (size_t i = 0; i < engine->modules.len; ++i) {
		kr_module_unload(&engine->modules.at[i]);
	}
	array_clear(engine->modules);

	if (engine->L) {
		lua_close(engine->L);
	}

	kr_cache_close(engine->resolver.cache);
}

/** Execute current chunk in the sandbox */
static int l_sandboxcall(lua_State *L)
{
#if LUA_VERSION_NUM >= 502
	lua_getglobal(L, "_SANDBOX");
	lua_setupvalue(L, -2, 1);
#endif
	return lua_pcall(L, 0, LUA_MULTRET, 0);
}

int engine_cmd(struct engine *engine, const char *str)
{
	if (engine == NULL || engine->L == NULL) {
		return kr_error(ENOEXEC);
	}

	/* Evaluate results */
	int ret = luaL_loadstring(engine->L, str);
	if (ret == 0) {
		ret = l_sandboxcall(engine->L);
	}

	/* Print results. */
	int nres = lua_gettop(engine->L);
	for (int i = 0; i < nres; ++i) {
		const char *out = lua_tostring(engine->L, -1);
		if (out != NULL) {
			printf("%s\n", out);
		}
		lua_pop(engine->L, 1);
	}

	/* Check result. */
	if (ret != 0) {
		return kr_error(EINVAL);
	}

	return kr_ok();
}

/* Execute byte code */
#define l_dobytecode(L, arr, len, name) \
	(luaL_loadbuffer((L), (arr), (len), (name)) || lua_pcall((L), 0, LUA_MULTRET, 0))
/** Load file in a sandbox environment. */
#define l_dosandboxfile(L, filename) \
	(luaL_loadfile((L), (filename)) || l_sandboxcall((L)))

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
		fprintf(stderr, "[system] error %s\n", lua_tostring(engine->L, -1));
		lua_pop(engine->L, 1);
		return kr_error(EINVAL);
	}

	return kr_ok();
}

int engine_start(struct engine *engine)
{
	/* Load configuration. */
	int ret = engine_loadconf(engine);
	if (ret != 0) {
		return ret;
	}

	return uv_run(uv_default_loop(), UV_RUN_DEFAULT);	
}

void engine_stop(struct engine *engine)
{
	uv_stop(uv_default_loop());
}

int engine_register(struct engine *engine, const char *name)
{
	if (engine == NULL || name == NULL) {
		return kr_error(EINVAL);
	}

	/* Load module */
	size_t next = engine->modules.len;
	array_reserve(engine->modules, next + 1);
	struct kr_module *module = &engine->modules.at[next];
	int ret = kr_module_load(module, name, NULL);
	if (ret != 0) {
		return ret;
	} else {
		engine->modules.len += 1;
	}

	/* Register properties */
	if (module->props) {
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
	}

	return kr_ok();
}

int engine_unregister(struct engine *engine, const char *name)
{
	/* Find matching module. */
	module_array_t *mod_list = &engine->modules;
	size_t found = mod_list->len;
	for (size_t i = 0; i < mod_list->len; ++i) {
		if (strcmp(mod_list->at[i].name, name) == 0) {
			found = i;
			break;
		}
	}

	/* Unregister module */
	if (found < mod_list->len) {
		kr_module_unload(&mod_list->at[found]);
		array_del(*mod_list, found);
		return kr_ok();
	}

	return kr_error(ENOENT);
}

void engine_lualib(struct engine *engine, const char *name, lua_CFunction lib_cb)
{
	if (engine != NULL) {
#if LUA_VERSION_NUM < 502
		lib_cb(engine->L);
#else
		luaL_requiref(engine->L, name, lib_cb, 1);
		lua_pop(engine->L, 1);
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