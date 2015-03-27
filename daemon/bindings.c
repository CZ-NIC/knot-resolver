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

#include "lib/cache.h"
#include "daemon/bindings.h"

/** @internal Compatibility wrapper for Lua 5.0 - 5.2 */
#if LUA_VERSION_NUM < 502
#define register_lib(L, name, lib) \
	luaL_openlib((L), (name), (lib), 0)
#else
#define register_lib(L, name, lib) \
	luaL_newlib((L), (lib))
#endif

/** List loaded modules */
static int mod_list(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	for (unsigned i = 0; i < engine->modules.len; ++i) {
		struct kr_module *module = &engine->modules.at[i];
		lua_pushstring(L, module->name);
	}
	return engine->modules.len;
}

/** Load module. */
static int mod_load(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n != 1 || !lua_isstring(L, 1)) {
		lua_pushstring(L, "expected module name");
		lua_error(L);
	}
	/* Load engine module */
	struct engine *engine = engine_luaget(L);
	int ret = engine_register(engine, lua_tostring(L, 1));
	if (ret != 0) {
		lua_pushstring(L, kr_strerror(ret));
		lua_error(L);
	}
	return 0;
}

/** Unload module. */
static int mod_unload(lua_State *L)
{
	lua_pushstring(L, "not implemented");
	lua_error(L);
	return 0;
}

int lib_modules(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "list",   mod_list },
		{ "load",   mod_load },
		{ "unload", mod_unload },
		{ NULL, NULL }
	};

	register_lib(L, "modules", lib);
	return 1;
}

int lib_config(lua_State *L)
{
	return 0;
}

/** Open cache */
static int cache_open(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 2) {
		lua_pushstring(L, "expected (string path, int size)");
		lua_error(L);
	}

	/* Open resolution context cache */
	struct engine *engine = engine_luaget(L);
	engine->resolver.cache = kr_cache_open(lua_tostring(L, 1), engine->pool, lua_tointeger(L, 2));
	if (engine->resolver.cache == NULL) {
		lua_pushstring(L, "invalid cache directory: ");
		lua_pushstring(L, lua_tostring(L, 1));
		lua_concat(L, 2);
		lua_error(L);
	}

	lua_pushboolean(L, 1);
	return 1;
}

static int cache_close(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	if (engine->resolver.cache != NULL) {
		kr_cache_close(engine->resolver.cache);
		engine->resolver.cache = NULL;
	}

	return 0;
}

int lib_cache(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "open",   cache_open },
		{ "close",  cache_close },
		{ NULL, NULL }
	};

	register_lib(L, "cache", lib);
	return 0;
}