/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <lua.h>
#include <lauxlib.h>
#include <string.h>


const char * lua_table_checkindices(lua_State *L, const char *keys[])
{
	/* Iterate over table at the top of the stack.
	 * http://www.lua.org/manual/5.1/manual.html#lua_next */
	for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
		lua_pop(L, 1); /* we don't need the value */
		/* We need to copy the key, as _tostring() confuses _next().
		 * https://www.lua.org/manual/5.1/manual.html#lua_tolstring */
		lua_pushvalue(L, -1);
		const char *key = lua_tostring(L, -1);
		if (!key)
			return "<NON-STRING_INDEX>";
		for (const char **k = keys; ; ++k) {
			if (*k == NULL)
				return key;
			if (strcmp(*k, key) == 0)
				break;
		}
	}
	return NULL;
}


/* Each of these just creates the correspondingly named lua table of functions. */
int kr_bindings_cache   (lua_State *L); /* ./cache.c   */
int kr_bindings_event   (lua_State *L); /* ./event.c   */
int kr_bindings_modules (lua_State *L); /* ./modules.c */
int kr_bindings_net     (lua_State *L); /* ./net.c     */
int kr_bindings_worker  (lua_State *L); /* ./worker.c  */

void kr_bindings_register(lua_State *L)
{
	kr_bindings_cache(L);
	kr_bindings_event(L);
	kr_bindings_modules(L);
	kr_bindings_net(L);
	kr_bindings_worker(L);
}

void lua_error_p(lua_State *L, const char *fmt, ...)
{
	/* Add a stack trace and throw the result as a lua error. */
	luaL_traceback(L, L, "error occured here (config filename:lineno is at the bottom, if config is involved):", 0);
	/* Push formatted custom message, prepended with "ERROR: ". */
	lua_pushliteral(L, "\nERROR: ");
	{
		va_list args;
		va_start(args, fmt);
		lua_pushvfstring(L, fmt, args);
		va_end(args);
	}
	lua_concat(L, 3);
	lua_error(L);
	/* TODO: we might construct a little more friendly trace by using luaL_where().
	 * In particular, in case the error happens in a function that was called
	 * directly from a config file (the most common case), there isn't much need
	 * to format the trace in this heavy way. */
}

