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

#pragma once

#include <stdint.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h> /* luaL_error */

/**
 * @brief Push CTypeID (FFI) of given СDATA type on stack
 * @param L Lua State
 * @param ctypename С type name as string (e.g. "struct request" or "uint32_t")
 * @return reference to CType value (or LUA_NOREF)
 */
int luaL_ctypeof(struct lua_State *L, const char *ctypename);

/**
 * @brief Declare symbols for FFI
 * @param L Lua State
 * @param ctypename C definitions, e.g "struct stat"
 * @sa ffi.cdef(def)
 * @retval 0 on success
 * @retval LUA_ERRRUN, LUA_ERRMEM, LUA_ERRERR otherwise
 */
int luaL_cdef(struct lua_State *L, const char *ctypename);

/**
 * @brief Push C pointer to Lua stack.
 * @param L Lua State
 * @param p C pointer
 * @param ctype_ref Reference to corresponding Lua C type (see luaL_ctypeof) 
 */
void luaL_pushcpointer(lua_State *L, void *p, int ctype_ref);

/**
 * @brief Convert value on Lua stack to C pointer.
 * @param L Lua State
 * @param index Lua stack index
 * @return C pointer
 */
void *luaL_tocpointer(lua_State *L, int index);

/**
 * @brief Push an opaque void pointer to Lua stack.
 * @param L Lua State
 * @param p C pointer
 */
void luaL_pushvoidpointer(lua_State *L, void *p);

/* Use full userdata to store pointers on some architectures. */
#ifdef __aarch64__
#define LUA_CTID_INTERNED
#endif

/** Helper macro to declare a static CType reference variable. */
#define LUA_CTID_DECLARE(name) \
	static int name = LUA_NOREF

/** Convert type to it's pointer name */
#ifdef LUA_CTID_INTERNED
#define LUA_CTID_PTRNAME(name) name "*"
#else
#define LUA_CTID_PTRNAME(name) name ""
#endif

/** Helper macro to define a static CType reference variable.
  * Example use:
  *   LUA_CTID_DECLARE(MY_TYPE);
  *   void myfunc(lua_State *L, struct my_type *x) {
  *     LUA_CTID_DEFINE(MY_TYPE, "struct my_type *");
  *     luaL_pushcpointer(L, x, CTID_MY_TYPE);
  *   }
  */
#define LUA_CTID_DEFINE(L, ctype_ref, ctypename) do { \
	if (ctype_ref == LUA_NOREF) { \
		ctype_ref = luaL_ctypeof(L, LUA_CTID_PTRNAME(ctypename)); \
	} \
} while(0)