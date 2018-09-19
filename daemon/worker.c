/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "daemon/worker.h"

#include "daemon/bindings.h"
#include "daemon/session.h"
#include "daemon/zimport.h"

#include <contrib/ucw/mempool.h>

#include <sys/types.h>
#include <unistd.h>

#if 0
#include <contrib/ucw/lib.h>
#include <contrib/wire.h>
#include <uv.h>
#include <lua.h>
#include <libknot/packet/pkt.h>
#include <libknot/descriptor.h>
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
#include <malloc.h>
#endif
#include <assert.h>
#include <gnutls/gnutls.h>
#include "lib/utils.h"
#include "lib/layer.h"
#include "daemon/engine.h"
#include "daemon/io.h"
#include "daemon/tls.h"
#include "daemon/session.h"
#endif

#define VERBOSE_MSG(qry, fmt...) QRVERBOSE(qry, "wrkr", fmt)

/** Client request state. */
struct request_ctx
{
	struct kr_request req;
	struct {
		union inaddr addr;
		union inaddr dst_addr;
		/* uv_handle_t *handle; */

		/** NULL if the request didn't come over network. */
		struct session *session;
	} source;
	struct worker_ctx *worker;
	qr_tasklist_t tasks;
};


struct session *worker_request_get_source_session(struct request_ctx *ctx)
{
	return ctx->source.session;
}

void worker_request_set_source_session(struct request_ctx *ctx, struct session *session)
{
	ctx->source.session = session;
}

/** Reserve worker buffers */
static int worker_reserve(struct worker_ctx *worker, size_t ring_maxlen)
{
	array_init(worker->pool_mp);
	array_init(worker->pool_ioreqs);
	array_init(worker->pool_iohandles);
	array_init(worker->pool_sessions);
	if (array_reserve(worker->pool_mp, ring_maxlen) ||
		array_reserve(worker->pool_ioreqs, ring_maxlen) ||
		array_reserve(worker->pool_iohandles, ring_maxlen) ||
		array_reserve(worker->pool_sessions, ring_maxlen)) {
		return kr_error(ENOMEM);
	}
	memset(&worker->pkt_pool, 0, sizeof(worker->pkt_pool));
	worker->pkt_pool.ctx = mp_new (4 * sizeof(knot_pkt_t));
	worker->pkt_pool.alloc = (knot_mm_alloc_t) mp_alloc;
	worker->subreq_out = trie_create(NULL);
	worker->tcp_connected = map_make(NULL);
	worker->tcp_waiting = map_make(NULL);
	worker->tcp_pipeline_max = MAX_PIPELINED;
	memset(&worker->stats, 0, sizeof(worker->stats));
	return kr_ok();
}

#define reclaim_freelist(list, type, cb) \
	for (unsigned i = 0; i < list.len; ++i) { \
		void *elm = list.at[i]; \
		kr_asan_unpoison(elm, sizeof(type)); \
		cb(elm); \
	} \
	array_clear(list)

#define reclaim_freelist_custom(list, type, cb) \
	for (unsigned i = 0; i < list.len; ++i) { \
		void *elm = list.at[i]; \
		kr_asan_custom_unpoison(type, elm); \
		cb(elm); \
	} \
	array_clear(list)

void worker_reclaim(struct worker_ctx *worker)
{
	reclaim_freelist(worker->pool_mp, struct mempool, mp_delete);
	reclaim_freelist(worker->pool_ioreqs, uv_reqs_t, free);
	reclaim_freelist(worker->pool_iohandles, uv_handles_t, free);
	reclaim_freelist_custom(worker->pool_sessions, session, session_free);
	mp_delete(worker->pkt_pool.ctx);
	worker->pkt_pool.ctx = NULL;
	trie_free(worker->subreq_out);
	worker->subreq_out = NULL;
	map_clear(&worker->tcp_connected);
	map_clear(&worker->tcp_waiting);
	if (worker->z_import != NULL) {
		zi_free(worker->z_import);
		worker->z_import = NULL;
	}
}

struct worker_ctx *worker_create(struct engine *engine, knot_mm_t *pool,
		int worker_id, int worker_count)
{
	/* Load bindings */
	engine_lualib(engine, "modules", lib_modules);
	engine_lualib(engine, "net",     lib_net);
	engine_lualib(engine, "cache",   lib_cache);
	engine_lualib(engine, "event",   lib_event);
	engine_lualib(engine, "worker",  lib_worker);

	/* Create main worker. */
	struct worker_ctx *worker = mm_alloc(pool, sizeof(*worker));
	if (!worker) {
		return NULL;
	}
	memset(worker, 0, sizeof(*worker));
	worker->id = worker_id;
	worker->count = worker_count;
	worker->engine = engine;
	worker_reserve(worker, MP_FREELIST_SIZE);
	worker->out_addr4.sin_family = AF_UNSPEC;
	worker->out_addr6.sin6_family = AF_UNSPEC;
	/* Register worker in Lua thread */
	lua_pushlightuserdata(engine->L, worker);
	lua_setglobal(engine->L, "__worker");
	lua_getglobal(engine->L, "worker");
	lua_pushnumber(engine->L, worker_id);
	lua_setfield(engine->L, -2, "id");
	lua_pushnumber(engine->L, getpid());
	lua_setfield(engine->L, -2, "pid");
	lua_pushnumber(engine->L, worker_count);
	lua_setfield(engine->L, -2, "count");
	/* Register table for worker per-request variables */
	lua_newtable(engine->L);
	lua_setfield(engine->L, -2, "vars");
	lua_getfield(engine->L, -1, "vars");
	worker->vars_table_ref = luaL_ref(engine->L, LUA_REGISTRYINDEX);
	lua_pop(engine->L, 1);
	return worker;
}

#undef VERBOSE_MSG
