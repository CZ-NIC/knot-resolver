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
#include "daemon/io.h"
#include "daemon/qr_task.h"
#include "daemon/session.h"
#include "daemon/zimport.h"

#include <contrib/ucw/mempool.h>

#include <sys/types.h>
#include <unistd.h>
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
	#include <malloc.h>
#endif

#if 0
#include <contrib/ucw/lib.h>
#include <contrib/wire.h>
#include <uv.h>
#include <lua.h>
#include <libknot/packet/pkt.h>
#include <libknot/descriptor.h>
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

static inline void *iohandle_borrow(struct worker_ctx *worker)
{
	void *h = NULL;

	const size_t size = sizeof(uv_handles_t);
	if (worker->pool_iohandles.len > 0) {
		h = array_tail(worker->pool_iohandles);
		array_pop(worker->pool_iohandles);
		kr_asan_unpoison(h, size);
	} else {
		h = malloc(size);
	}

	return h;
}

static inline void iohandle_release(struct worker_ctx *worker, void *h)
{
	assert(h);

	if (worker->pool_iohandles.len < MP_FREELIST_SIZE) {
		array_push(worker->pool_iohandles, h);
		kr_asan_poison(h, sizeof(uv_handles_t));
	} else {
		free(h);
	}
}

void *worker_iohandle_borrow(struct worker_ctx *worker)
{
	return iohandle_borrow(worker);
}

void worker_iohandle_release(struct worker_ctx *worker, void *h)
{
	iohandle_release(worker, h);
}

static inline void *iorequest_borrow(struct worker_ctx *worker)
{
	void *r = NULL;

	const size_t size = sizeof(uv_reqs_t);
	if (worker->pool_ioreqs.len > 0) {
		r = array_tail(worker->pool_ioreqs);
		array_pop(worker->pool_ioreqs);
		kr_asan_unpoison(r, size);
	} else {
		r = malloc(size);
	}

	return r;
}

static inline void iorequest_release(struct worker_ctx *worker, void *r)
{
	assert(r);

	if (worker->pool_ioreqs.len < MP_FREELIST_SIZE) {
		array_push(worker->pool_ioreqs, r);
		kr_asan_poison(r, sizeof(uv_reqs_t));
	} else {
		free(r);
	}
}

/*! @internal Create a UDP/TCP handle for an outgoing AF_INET* connection.
 *  socktype is SOCK_* */
static uv_handle_t *ioreq_spawn(struct qr_task *task, int socktype, sa_family_t family)
{
	bool precond = (socktype == SOCK_DGRAM || socktype == SOCK_STREAM)
			&& (family == AF_INET  || family == AF_INET6);
	if (!precond) {
		/* assert(false); see #245 */
		kr_log_verbose("[work] ioreq_spawn: pre-condition failed\n");
		return NULL;
	}

	if (qr_task_is_full(task)) {
		return NULL;
	}
	/* Create connection for iterative query */
	struct worker_ctx *worker = get_worker();
	void *h = iohandle_borrow(worker);
	uv_handle_t *handle = (uv_handle_t *)h;
	if (!handle) {
		return NULL;
	}
	int ret = io_create(worker->loop, handle, socktype, family);
	if (ret) {
		if (ret == UV_EMFILE) {
			worker->too_many_open = true;
			worker->rconcurrent_highwatermark = worker->stats.rconcurrent;
		}
		iohandle_release(worker, h);
		return NULL;
	}

	/* Bind to outgoing address, according to IP v4/v6. */
	union inaddr *addr;
	if (family == AF_INET) {
		addr = (union inaddr *)&worker->out_addr4;
	} else {
		addr = (union inaddr *)&worker->out_addr6;
	}
	if (addr->ip.sa_family != AF_UNSPEC) {
		assert(addr->ip.sa_family == family);
		if (socktype == SOCK_DGRAM) {
			uv_udp_t *udp = (uv_udp_t *)handle;
			ret = uv_udp_bind(udp, &addr->ip, 0);
		} else if (socktype == SOCK_STREAM){
			uv_tcp_t *tcp = (uv_tcp_t *)handle;
			ret = uv_tcp_bind(tcp, &addr->ip, 0);
		}
	}

	/* Set current handle as a subrequest type. */
	struct session *session = handle->data;
	if (ret == 0) {
		session_flags(session)->outgoing = true;
		ret = session_tasklist_add(session, task);
	}
	if (ret < 0) {
		io_deinit(handle);
		iohandle_release(worker, h);
		return NULL;
	}
	/* Connect or issue query datagram */
	qr_task_append(task, handle);
	return handle;
}


/** @cond This memory layout is internal to mempool.c, use only for debugging. */
#if defined(__SANITIZE_ADDRESS__)
struct mempool_chunk {
	struct mempool_chunk *next;
	size_t size;
};
static void mp_poison(struct mempool *mp, bool poison)
{
	if (!poison) { /* @note mempool is part of the first chunk, unpoison it first */
		kr_asan_unpoison(mp, sizeof(*mp));
	}
	struct mempool_chunk *chunk = mp->state.last[0];
	void *chunk_off = (void *)chunk - chunk->size;
	if (poison) {
		kr_asan_poison(chunk_off, chunk->size);
	} else {
		kr_asan_unpoison(chunk_off, chunk->size);
	}
}
#else
#define mp_poison(mp, enable)
#endif
/** @endcond */

/** Get a mempool.  (Recycle if possible.)  */
static inline struct mempool *pool_borrow(struct worker_ctx *worker)
{
	struct mempool *mp = NULL;
	if (worker->pool_mp.len > 0) {
		mp = array_tail(worker->pool_mp);
		array_pop(worker->pool_mp);
		mp_poison(mp, 0);
	} else { /* No mempool on the freelist, create new one */
		mp = mp_new (4 * CPU_PAGE_SIZE);
	}
	return mp;
}

/** Return a mempool.  (Cache them up to some count.) */
static inline void pool_release(struct worker_ctx *worker, struct mempool *mp)
{
	if (worker->pool_mp.len < MP_FREELIST_SIZE) {
		mp_flush(mp);
		array_push(worker->pool_mp, mp);
		mp_poison(mp, 1);
	} else {
		mp_delete(mp);
	}
}


/** Create a key for an outgoing subrequest: qname, qclass, qtype.
 * @param key Destination buffer for key size, MUST be SUBREQ_KEY_LEN or larger.
 * @return key length if successful or an error
 */
static const size_t SUBREQ_KEY_LEN = KR_RRKEY_LEN;
static int subreq_key(char *dst, knot_pkt_t *pkt)
{
	assert(pkt);
	return kr_rrkey(dst, knot_pkt_qclass(pkt), knot_pkt_qname(pkt),
			knot_pkt_qtype(pkt), knot_pkt_qtype(pkt));
}

/** Create and initialize a request_ctx (on a fresh mempool).
 *
 * handle and addr point to the source of the request, and they are NULL
 * in case the request didn't come from network.
 */
static struct request_ctx *request_create(struct worker_ctx *worker,
					  uv_handle_t *handle,
					  const struct sockaddr *addr)
{
	knot_mm_t pool = {
		.ctx = pool_borrow(worker),
		.alloc = (knot_mm_alloc_t) mp_alloc
	};

	/* Create request context */
	struct request_ctx *ctx = mm_alloc(&pool, sizeof(*ctx));
	if (!ctx) {
		pool_release(worker, pool.ctx);
		return NULL;
	}

	memset(ctx, 0, sizeof(*ctx));

	/* TODO Relocate pool to struct request */
	ctx->worker = worker;
	array_init(ctx->tasks);
	struct session *s = handle ? handle->data : NULL;
	if (s) {
		assert(session_flags(s)->outgoing == false);
	}
	ctx->source.session = s;

	struct kr_request *req = &ctx->req;
	req->pool = pool;
	req->vars_ref = LUA_NOREF;

	/* Remember query source addr */
	if (!addr || (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)) {
		ctx->source.addr.ip.sa_family = AF_UNSPEC;
	} else {
		size_t addr_len = sizeof(struct sockaddr_in);
		if (addr->sa_family == AF_INET6)
			addr_len = sizeof(struct sockaddr_in6);
		memcpy(&ctx->source.addr.ip, addr, addr_len);
		ctx->req.qsource.addr = &ctx->source.addr.ip;
	}

	worker->stats.rconcurrent += 1;

	if (!handle) {
		return ctx;
	}

	/* Remember the destination address. */
	int addr_len = sizeof(ctx->source.dst_addr);
	struct sockaddr *dst_addr = &ctx->source.dst_addr.ip;
	ctx->source.dst_addr.ip.sa_family = AF_UNSPEC;
	if (handle->type == UV_UDP) {
		if (uv_udp_getsockname((uv_udp_t *)handle, dst_addr, &addr_len) == 0) {
			req->qsource.dst_addr = dst_addr;
		}
		req->qsource.tcp = false;
	} else if (handle->type == UV_TCP) {
		if (uv_tcp_getsockname((uv_tcp_t *)handle, dst_addr, &addr_len) == 0) {
			req->qsource.dst_addr = dst_addr;
		}
		req->qsource.tcp = true;
	}

	return ctx;
}

/** More initialization, related to the particular incoming query/packet. */
static int request_start(struct request_ctx *ctx, knot_pkt_t *query)
{
	assert(query && ctx);
	size_t answer_max = KNOT_WIRE_MIN_PKTSIZE;
	struct kr_request *req = &ctx->req;

	/* source.session can be empty if request was generated by kresd itself */
	struct session *s = ctx->source.session;
	if (!s || session_get_handle(s)->type == UV_TCP) {
		answer_max = KNOT_WIRE_MAX_PKTSIZE;
	} else if (knot_pkt_has_edns(query)) { /* EDNS */
		answer_max = MAX(knot_edns_get_payload(query->opt_rr),
				 KNOT_WIRE_MIN_PKTSIZE);
	}
	req->qsource.size = query->size;

	req->answer = knot_pkt_new(NULL, answer_max, &req->pool);
	if (!req->answer) {
		return kr_error(ENOMEM);
	}

	/* Remember query source TSIG key */
	if (query->tsig_rr) {
		req->qsource.key = knot_rrset_copy(query->tsig_rr, &req->pool);
	}

	/* Remember query source EDNS data */
	if (query->opt_rr) {
		req->qsource.opt = knot_rrset_copy(query->opt_rr, &req->pool);
	}
	/* Start resolution */
	struct worker_ctx *worker = ctx->worker;
	struct engine *engine = worker->engine;
	kr_resolve_begin(req, &engine->resolver, req->answer);
	worker->stats.queries += 1;
	/* Throttle outbound queries only when high pressure */
	if (worker->stats.concurrent < QUERY_RATE_THRESHOLD) {
		req->options.NO_THROTTLE = true;
	}
	return kr_ok();
}

void worker_request_free(struct request_ctx *ctx)
{
	struct worker_ctx *worker = ctx->worker;
	/* Dereference any Lua vars table if exists */
	if (ctx->req.vars_ref != LUA_NOREF) {
		lua_State *L = worker->engine->L;
		/* Get worker variables table */
		lua_rawgeti(L, LUA_REGISTRYINDEX, worker->vars_table_ref);
		/* Get next free element (position 0) and store it under current reference (forming a list) */
		lua_rawgeti(L, -1, 0);
		lua_rawseti(L, -2, ctx->req.vars_ref);
		/* Set current reference as the next free element */
		lua_pushinteger(L, ctx->req.vars_ref);
		lua_rawseti(L, -2, 0);
		lua_pop(L, 1);
		ctx->req.vars_ref = LUA_NOREF;
	}
	/* Return mempool to ring or free it if it's full */
	pool_release(worker, ctx->req.pool.ctx);
	/* @note The 'task' is invalidated from now on. */
	/* Decommit memory every once in a while */
	static int mp_delete_count = 0;
	if (++mp_delete_count == 100000) {
		lua_gc(worker->engine->L, LUA_GCCOLLECT, 0);
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
		malloc_trim(0);
#endif
		mp_delete_count = 0;
	}
	worker->stats.rconcurrent -= 1;
}


int worker_request_add_tasks(struct request_ctx *ctx, struct qr_task *task)
{
	for (int i = 0; i < ctx->tasks.len; ++i) {
		if (ctx->tasks.at[i] == task) {
			return i;
		}
	}
	int ret = array_push(ctx->tasks, task);
	if (ret >= 0) {
		qr_task_ref(task);
	}
	return ret;
}

int worker_request_del_tasks(struct request_ctx *ctx, struct qr_task *task)
{
	int ret = kr_error(ENOENT);
	for (int i = 0; i < ctx->tasks.len; ++i) {
		if (ctx->tasks.at[i] == task) {
			array_del(ctx->tasks, i);
			qr_task_unref(task);
			ret = kr_ok();
			break;
		}
	}
	return ret;
}
















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
