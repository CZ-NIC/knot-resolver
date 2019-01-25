/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <lua.h>
#include <string.h>

/* Each of these just creates the correspondingly named lua table of functions. */
int kr_bindings_cache   (lua_State *L); /* ./cache.c   */
int kr_bindings_event   (lua_State *L); /* ./event.c   */
int kr_bindings_modules (lua_State *L); /* ./modules.c */
int kr_bindings_net     (lua_State *L); /* ./net.c     */
int kr_bindings_worker  (lua_State *L); /* ./worker.c  */


static void lualib(lua_State *L, const char *name, lua_CFunction lib_cb)
{
#if LUA_VERSION_NUM >= 502
	luaL_requiref(L, name, lib_cb, 1);
	lua_pop(L, 1);
#else
	lib_cb(L);
#endif
}

void kr_bindings_register(lua_State *L)
{
	lualib(L, "modules", kr_bindings_modules);
	lualib(L, "net",     kr_bindings_net);
	lualib(L, "cache",   kr_bindings_cache);
	lualib(L, "event",   kr_bindings_event);
	lualib(L, "worker",  kr_bindings_worker);
}

void lua_error_p(lua_State *L, const char *fmt, ...)
{
	/* Push a string describing location in the "parent" lua function. */
	lua_Debug d;
	lua_getstack(L, 1, &d);
	lua_getinfo(L, "Sln", &d);
	if (strncmp(d.short_src, "[", 1) != 0) {
		lua_pushstring(L, d.short_src);
		lua_pushstring(L, ":");
		lua_pushnumber(L, d.currentline);
		lua_pushstring(L, ": error: ");
		lua_concat(L, 4);
	} else {
		lua_pushstring(L, "error: ");
	}
	/* Push formatted custom message. */
	va_list args;
	va_start(args, fmt);
	lua_pushvfstring(L, fmt, args);
	va_end(args);
	/* Concatenate the two and throw a lua error. */
	lua_concat(L,  2);
	lua_error(L);
}

