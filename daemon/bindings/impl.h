/*  Copyright (C) 2015-2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "daemon/engine.h"

#include <lua.h>
#include <lauxlib.h>


/** @internal Compatibility wrapper for Lua 5.0 - 5.2
    https://www.lua.org/manual/5.2/manual.html#luaL_newlib
 */
#if LUA_VERSION_NUM >= 502
#define register_lib(L, name, lib) \
	luaL_newlib((L), (lib))
#else
#define lua_rawlen(L, obj) \
	lua_objlen((L), (obj))
#define register_lib(L, name, lib) \
	luaL_openlib((L), (name), (lib), 0)
#endif

/** Useful to stringify #defines into error strings. */
#define STR(s) STRINGIFY_INT(s)
#define STRINGIFY_INT(s) #s

/** @internal Prefix error with file:line
 * Implementation in ./impl.c */
int KR_COLD format_error(lua_State* L, const char *err);

static inline struct worker_ctx *wrk_luaget(lua_State *L) {
	lua_getglobal(L, "__worker");
	struct worker_ctx *worker = lua_touserdata(L, -1);
	lua_pop(L, 1);
	return worker;
}

static inline int execute_callback(lua_State *L, int argc)
{
	int ret = engine_pcall(L, argc);
	if (ret != 0) {
		fprintf(stderr, "error: %s\n", lua_tostring(L, -1));
	}
	/* Clear the stack, there may be event a/o enything returned */
	lua_settop(L, 0);
	return ret;
}

