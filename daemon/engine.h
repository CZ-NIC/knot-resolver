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
#define LRU_RTT_SIZE 65536 /**< NS RTT cache size */
#endif
#ifndef LRU_REP_SIZE
#define LRU_REP_SIZE (LRU_RTT_SIZE / 4) /**< NS reputation cache size */
#endif
#ifndef MP_FREELIST_SIZE
#define MP_FREELIST_SIZE 64 /**< Maximum length of the worker mempool freelist */
#endif
#ifndef RECVMMSG_BATCH
#define RECVMMSG_BATCH 4
#endif
#ifndef QUERY_RATE_THRESHOLD
#define QUERY_RATE_THRESHOLD (2 * MP_FREELIST_SIZE) /**< Nr of parallel queries considered as high rate */
#endif

/*
 * @internal These are forward decls to allow building modules with engine but without Lua.
 */
struct lua_State;

#include "lib/utils.h"
#include "lib/resolve.h"
#include "daemon/network.h"

/** Cache storage backend. */
struct storage_api {
	const char *prefix; /**< Storage prefix, e.g. 'lmdb://' */
	const knot_db_api_t *(*api)(void); /**< Storage API implementation */
	void *(*opts_create)(const char *, size_t); /**< Storage options factory */
};

/** @cond internal Array of cache backend options. */
typedef array_t(struct storage_api) storage_registry_t;
/* @endcond */

struct engine {
    struct kr_context resolver;
    struct network net;
    module_array_t modules;
    storage_registry_t storage_registry;
    knot_mm_t *pool;
    uv_timer_t *updater;
    struct lua_State *L;
};

int engine_init(struct engine *engine, knot_mm_t *pool);
void engine_deinit(struct engine *engine);
/** @warning This function leaves 1 string result on stack. */
int engine_cmd(struct engine *engine, const char *str);
int engine_start(struct engine *engine, const char *config_path);
void engine_stop(struct engine *engine);
int engine_register(struct engine *engine, const char *module, const char *precedence, const char* ref);
int engine_unregister(struct engine *engine, const char *module);
void engine_lualib(struct engine *engine, const char *name, int (*lib_cb) (struct lua_State *));

/** Execute current chunk in the sandbox */
int engine_pcall(struct lua_State *L, int argc);

/** Return engine light userdata. */
struct engine *engine_luaget(struct lua_State *L);
