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

#include "engine.h"

#include <lua.h>
#include <lauxlib.h>

/** Useful to stringify #defines into error strings. */
#define STR(s) STRINGIFY_TOKEN(s)
#define STRINGIFY_TOKEN(s) #s


/** Check lua table at the top of the stack for allowed keys.
 * \param keys NULL-terminated array of 0-terminated strings
 * \return NULL if passed or the offending string (pushed on top of lua stack)
 * \note Future work: if non-NULL is returned, there's extra stuff on the lua stack.
 * \note Brute-force complexity: table length * summed length of keys.
 */
const char * lua_table_checkindices(lua_State *L, const char *keys[]);

/** If the value at the top of the stack isn't a table, make it a single-element list. */
static inline void lua_listify(lua_State *L)
{
	if (lua_istable(L, -1))
		return;
	lua_createtable(L, 1, 0);
	lua_insert(L, lua_gettop(L) - 1); /* swap the top two stack elements */
	lua_pushinteger(L, 1);
	lua_insert(L, lua_gettop(L) - 1); /* swap the top two stack elements */
	lua_settable(L, -3);
}


/** Throw a formatted lua error.
 *
 * The message will get prefixed by "ERROR: " and supplemented by stack trace.
 * \return never!  It calls lua_error().
 *
 * Example:
	ERROR: not a valid pin_sha256: 'a1Z/3ek=', raw length 5 instead of 32
	stack traceback:
		[C]: in function 'tls_client'
		/PathToPREFIX/lib/kdns_modules/policy.lua:175: in function 'TLS_FORWARD'
		/PathToConfig.lua:46: in main chunk
 */
KR_PRINTF(2) KR_NORETURN KR_COLD
void lua_error_p(lua_State *L, const char *fmt, ...);
/** @internal Annotate for static checkers. */
KR_NORETURN int lua_error(lua_State *L);

/** Shortcut for common case. */
static inline void lua_error_maybe(lua_State *L, int err)
{
	if (err) lua_error_p(L, "%s", kr_strerror(err));
}

static inline int execute_callback(lua_State *L, int argc)
{
	int ret = engine_pcall(L, argc);
	if (ret != 0) {
		kr_log_error("error: %s\n", lua_tostring(L, -1));
	}
	/* Clear the stack, there may be event a/o enything returned */
	lua_settop(L, 0);
	return ret;
}

/** Push a pointer as heavy/full userdata.
 *
 * It's useful as a replacement of lua_pushlightuserdata(),
 * but note that it behaves differently in lua (converts to pointer-to-pointer).
 */
static inline void lua_pushpointer(lua_State *L, void *p)
{
       void *addr = lua_newuserdata(L, sizeof(void *));
       assert(addr);
       memcpy(addr, &p, sizeof(void *));
}

