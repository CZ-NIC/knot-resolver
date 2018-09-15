/*
 * Copyright 2010-2015, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "contrib/lua_utils.h"

#include <assert.h>
#include <errno.h>

int luaL_ctypeof(struct lua_State *L, const char *ctypename)
{
	int idx = lua_gettop(L);
	/* This function calls ffi.typeof to determine CDataType */

	/* Get ffi.typeof function */
	luaL_loadstring(L, "return require('ffi').typeof");
	lua_call(L, 0, 1);
	/* FFI must exist */
	assert(lua_gettop(L) == idx + 1 && lua_isfunction(L, idx + 1));
	/* Push the first argument to ffi.typeof */
	lua_pushstring(L, ctypename);
	/* Call ffi.typeof() */
	lua_call(L, 1, 1);
	/* Return the reference */
	return luaL_ref(L, LUA_REGISTRYINDEX);
}

int luaL_cdef(struct lua_State *L, const char *what)
{
	int idx = lua_gettop(L);
	/* This function calls ffi.cdef  */

	/* Get ffi.typeof function */
	luaL_loadstring(L, "return require('ffi').cdef");
	lua_call(L, 0, 1);
	/* FFI must exist */
	assert(lua_gettop(L) == idx + 1 && lua_isfunction(L, idx + 1));
	/* Push the argument to ffi.cdef */
	lua_pushstring(L, what);
	/* Call ffi.cdef() */
	return lua_pcall(L, 1, 0, 0);
}

void luaL_pushcpointer(lua_State *L, void *p, int ctype_ref)
{
#ifdef LUA_CTID_INTERNED
	lua_rawgeti(L, LUA_REGISTRYINDEX, ctype_ref);
    /* Pointer does not fit in light userdata, it must be interned into a full userdata. */
    void **ud = lua_newuserdata(L, sizeof(p));
    *ud = p;
    /* Convert to given CType pointer */
    lua_call(L, 1, 1);
    /* Dereference pointer to pointer. */
    lua_pushinteger(L, 0);
    lua_gettable(L, -2);
    lua_remove(L, -2);
#else
    /* Cache ffi.cast() function */
    static int ffi_cast_ref = LUA_NOREF;
    if (ffi_cast_ref == LUA_NOREF) {
    	luaL_loadstring(L, "return require('ffi').cast");
    	lua_call(L, 0, 1);
    	ffi_cast_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    /* Call ffi.cast(ct, value) */
    lua_rawgeti(L, LUA_REGISTRYINDEX, ffi_cast_ref);
    lua_rawgeti(L, LUA_REGISTRYINDEX, ctype_ref);
    lua_pushlightuserdata(L, p);
    /* Convert to given CType */
    lua_call(L, 2, 1);
#endif
}

void *luaL_tocpointer(lua_State *L, int index)
{
	void **p = (void **)lua_topointer(L, index);
	if (p) {
		return *p;
	}
	return NULL;
}

void luaL_pushvoidpointer(lua_State *L, void *p)
{
	LUA_CTID_DECLARE(CTID_VOIDP);
	LUA_CTID_DEFINE(L, CTID_VOIDP, "void *");
	luaL_pushcpointer(L, p, CTID_VOIDP);
}