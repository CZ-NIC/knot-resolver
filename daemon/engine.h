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

#pragma once

/* Magic defaults */
#ifndef LRU_RTT_SIZE
#define LRU_RTT_SIZE 4096 /**< NS RTT cache size */
#endif
#ifndef LRU_REP_SIZE
#define LRU_REP_SIZE (LRU_RTT_SIZE / 2) /**< NS reputation cache size */
#endif
#ifndef MP_FREELIST_SIZE
#define MP_FREELIST_SIZE 32 /**< Maximum length of the worker mempool freelist */
#endif

/*
 * @internal These are forward decls to allow building modules with engine but without Lua.
 */
struct lua_State;

#include "lib/resolve.h"
#include "daemon/network.h"

/** Cache storage backend. */
struct storage_api {
	const char *prefix; /**< Storage prefix, e.g. 'lmdb://' */
	const namedb_api_t *(*api)(void); /**< Storage API implementation */
	void *(*opts_create)(const char *, size_t); /**< Storage options factory */
};

/** @internal Array of cache backend options. */
typedef array_t(struct storage_api) storage_registry_t;

struct engine {
    struct kr_context resolver;
    struct network net;
    module_array_t modules;
    storage_registry_t storage_registry;
    mm_ctx_t *pool;
    struct lua_State *L;
};

int engine_init(struct engine *engine, mm_ctx_t *pool);
void engine_deinit(struct engine *engine);
int engine_cmd(struct engine *engine, const char *str);
int engine_start(struct engine *engine);
void engine_stop(struct engine *engine);
int engine_register(struct engine *engine, const char *module);
int engine_unregister(struct engine *engine, const char *module);
void engine_lualib(struct engine *engine, const char *name, int (*lib_cb) (struct lua_State *));

/** Execute current chunk in the sandbox */
int engine_pcall(struct lua_State *L, int argc);

/** Return engine light userdata. */
struct engine *engine_luaget(struct lua_State *L);
