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

/**
 * Bindings to engine services, see \a http://www.lua.org/manual/5.2/manual.html#luaL_newlib for the reference.
 */
#pragma once

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "daemon/engine.h"

 /** @internal Compatibility wrapper for Lua 5.0 - 5.2 */
 #if LUA_VERSION_NUM >= 502
 #define register_lib(L, name, lib) \
 	luaL_newlib((L), (lib))
 #else
 #define lua_rawlen(L, obj) \
 	lua_objlen((L), (obj))
 #define register_lib(L, name, lib) \
 	luaL_openlib((L), (name), (lib), 0)
 #endif

/**
 * Load 'modules' package.
 * @param  L scriptable
 * @return   number of packages to load
 */
int lib_modules(lua_State *L);

/**
 * Load 'net' package.
 * @param  L scriptable
 * @return   number of packages to load
 */
int lib_net(lua_State *L);

/**
 * Load 'cache' package.
 * @param  L scriptable
 * @return   number of packages to load
 */
int lib_cache(lua_State *L);

/**
 * Load 'event' package.
 * @param  L scriptable
 * @return   number of packages to load
 */
int lib_event(lua_State *L);