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

#include <uv.h>
#include <lua.h>
#include <libknot/packet/pkt.h>
#include <libknot/descriptor.h>
#include <contrib/ucw/lib.h>
#include <contrib/ucw/mempool.h>
#include <contrib/wire.h>
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
#include <malloc.h>
#endif
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include "lib/utils.h"
#include "lib/layer.h"
#include "daemon/worker.h"
#include "daemon/bindings.h"
#include "daemon/engine.h"
#include "daemon/io.h"
#include "daemon/tls.h"
#include "daemon/zimport.h"
#include "daemon/session.h"

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

/** Query resolution task. */
struct qr_task
{
	struct request_ctx *ctx;
	knot_pkt_t *pktbuf;
	qr_tasklist_t waiting;
	uv_handle_t *pending[MAX_PENDING];
	uint16_t pending_count;
	uint16_t addrlist_count;
	uint16_t addrlist_turn;
	uint16_t timeouts;
	uint16_t iter_count;
	uint16_t bytes_remaining;
	struct sockaddr *addrlist;
	uint32_t refs;
	bool finished : 1;
	bool leading  : 1;
};


/* Convenience macros */
#define qr_task_ref(task) \
	do { ++(task)->refs; } while(0)
#define qr_task_unref(task) \
	do { if (task && --(task)->refs == 0) { qr_task_free(task); } } while (0)
#define qr_valid_handle(task, checked) \
	(!uv_is_closing((checked)) || (task)->ctx->source.session->handle == (checked))

/** @internal get key for tcp session
 *  @note kr_straddr() return pointer to static string
 */
#define tcpsess_key(addr) kr_straddr(addr)

/* Forward decls */
static void qr_task_free(struct qr_task *task);
static int qr_task_step(struct qr_task *task,
			const struct sockaddr *packet_source,
			knot_pkt_t *packet);
static int qr_task_send(struct qr_task *task, uv_handle_t *handle,
			struct sockaddr *addr, knot_pkt_t *pkt);
static int qr_task_finalize(struct qr_task *task, int state);
static void qr_task_complete(struct qr_task *task);
static struct session* worker_find_tcp_connected(struct worker_ctx *worker,
						 const struct sockaddr *addr);
static int worker_add_tcp_waiting(struct worker_ctx *worker,
				  const struct sockaddr *addr,
				  struct session *session);
static int worker_del_tcp_waiting(struct worker_ctx *worker,
				  const struct sockaddr *addr);
static struct session* worker_find_tcp_waiting(struct worker_ctx *worker,
					       const struct sockaddr *addr);
static void on_session_idle_timeout(uv_timer_t *timer);
static void on_tcp_connect_timeout(uv_timer_t *timer);
static void on_tcp_watchdog_timeout(uv_timer_t *timer);

/** @internal Get singleton worker. */
static inline struct worker_ctx *get_worker(void)
{
	return uv_default_loop()->data;
}

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

	if (task->pending_count >= MAX_PENDING) {
		return NULL;
	}
	/* Create connection for iterative query */
	struct worker_ctx *worker = task->ctx->worker;
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
		session_set_outgoing(session, true);
		ret = session_tasklist_add(session, task);
	}
	if (ret < 0) {
		io_deinit(handle);
		iohandle_release(worker, h);
		return NULL;
	}
	/* Connect or issue query datagram */
	task->pending[task->pending_count] = handle;
	task->pending_count += 1;
	return handle;
}

static void ioreq_kill_udp(uv_handle_t *req, struct qr_task *task)
{
	assert(req);
	struct session *s = req->data;
	assert(session_is_outgoing(s));
	if (session_is_closing(s)) {
		return;
	}
	uv_timer_t *t = session_get_timer(s);
	uv_timer_stop(t);
	session_tasklist_del(s, task);
	assert(session_tasklist_is_empty(s));
	session_close(s);
}

static void ioreq_kill_tcp(uv_handle_t *req, struct qr_task *task)
{
	assert(req);
	struct session *s = req->data;
	assert(session_is_outgoing(s));
	if (session_is_closing(s)) {
		return;
	}

	session_waitinglist_del(s, task);
	session_tasklist_del(s, task);

	int res = 0;

	const struct sockaddr *peer = session_get_peer(s);
	if (peer->sa_family != AF_UNSPEC && session_is_empty(s) && !session_is_closing(s)) {
		assert(peer->sa_family == AF_INET || peer->sa_family == AF_INET6);
		res = 1;
		if (session_is_connected(s)) {
			/* This is outbound TCP connection which can be reused.
			* Close it after timeout */
			uv_timer_t *t = session_get_timer(s);
			t->data = s;
			uv_timer_stop(t);
			res = uv_timer_start(t, on_session_idle_timeout,
					     KR_CONN_RTT_MAX, 0);
		}
	}

	if (res != 0) {
		/* if any errors, close the session immediately */
		session_close(s);
	}
}

static void ioreq_kill_pending(struct qr_task *task)
{
	for (uint16_t i = 0; i < task->pending_count; ++i) {
		if (task->pending[i]->type == UV_UDP) {
			ioreq_kill_udp(task->pending[i], task);
		} else if (task->pending[i]->type == UV_TCP) {
			ioreq_kill_tcp(task->pending[i], task);
		} else {
			assert(false);
		}
	}
	task->pending_count = 0;
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
		assert(session_is_outgoing(s) == false);
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

static void request_free(struct request_ctx *ctx)
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

static int request_add_tasks(struct request_ctx *ctx, struct qr_task *task)
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

static int request_del_tasks(struct request_ctx *ctx, struct qr_task *task)
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

static struct qr_task *qr_task_create(struct request_ctx *ctx)
{
	/* How much can client handle? */
	struct engine *engine = ctx->worker->engine;
	size_t pktbuf_max = KR_EDNS_PAYLOAD;
	if (engine->resolver.opt_rr) {
		pktbuf_max = MAX(knot_edns_get_payload(engine->resolver.opt_rr),
				 pktbuf_max);
	}

	/* Create resolution task */
	struct qr_task *task = mm_alloc(&ctx->req.pool, sizeof(*task));
	if (!task) {
		return NULL;
	}
	memset(task, 0, sizeof(*task)); /* avoid accidentally unintialized fields */

	/* Create packet buffers for answer and subrequests */
	knot_pkt_t *pktbuf = knot_pkt_new(NULL, pktbuf_max, &ctx->req.pool);
	if (!pktbuf) {
		mm_free(&ctx->req.pool, task);
		return NULL;
	}
	pktbuf->size = 0;

	task->ctx = ctx;
	task->pktbuf = pktbuf;
	array_init(task->waiting);
	task->refs = 0;
	int ret = request_add_tasks(ctx, task);
	if (ret < 0) {
		mm_free(&ctx->req.pool, task);
		mm_free(&ctx->req.pool, pktbuf);
		return NULL;
	}
	ctx->worker->stats.concurrent += 1;
	return task;
}

/* This is called when the task refcount is zero, free memory. */
static void qr_task_free(struct qr_task *task)
{
	struct request_ctx *ctx = task->ctx;

	assert(ctx);

	/* Process outbound session. */
	struct session *s = ctx->source.session;
	struct worker_ctx *worker = ctx->worker;

	/* Process source session. */
	if (s && session_tasklist_get_len(s) < worker->tcp_pipeline_max/2 &&
	    !session_is_closing(s) && !session_is_throttled(s)) {
		uv_handle_t *handle = session_get_handle(s);
		/* Start reading again if the session is throttled and
		 * the number of outgoing requests is below watermark. */
		if (handle) {
			io_start_read(handle);
			session_set_throttled(s, false);
		}
	}

	if (ctx->tasks.len == 0) {
		array_clear(ctx->tasks);
		request_free(ctx);
	}

	/* Update stats */
	worker->stats.concurrent -= 1;
}

/*@ Register new qr_task within session. */
static int qr_task_register(struct qr_task *task, struct session *session)
{
	assert(session_is_outgoing(session) == false &&
	       session_get_handle(session)->type == UV_TCP);

	int ret = session_tasklist_add(session, task);
	if (ret < 0) {
		return kr_error(ENOMEM);
	}

	struct request_ctx *ctx = task->ctx;
	assert(ctx && (ctx->source.session == NULL || ctx->source.session == session));
	ctx->source.session = session;
	/* Soft-limit on parallel queries, there is no "slow down" RCODE
	 * that we could use to signalize to client, but we can stop reading,
	 * an in effect shrink TCP window size. To get more precise throttling,
	 * we would need to copy remainder of the unread buffer and reassemble
	 * when resuming reading. This is NYI.  */
	if (session_tasklist_get_len(session) >= task->ctx->worker->tcp_pipeline_max) {
		uv_handle_t *handle = session_get_handle(session);
		if (handle && !session_is_throttled(session) && !session_is_closing(session)) {
			io_stop_read(handle);
			session_set_throttled(session, true);
		}
	}

	return 0;
}

static void qr_task_complete(struct qr_task *task)
{
	struct request_ctx *ctx = task->ctx;

	/* Kill pending I/O requests */
	ioreq_kill_pending(task);
	assert(task->waiting.len == 0);
	assert(task->leading == false);

	struct session *s = ctx->source.session;
	if (s) {
		assert(!session_is_outgoing(s) && session_waitinglist_is_empty(s));
		session_tasklist_del(s, task);
	}

	/* Release primary reference to task. */
	request_del_tasks(ctx, task);
}

/* This is called when we send subrequest / answer */
static int qr_task_on_send(struct qr_task *task, uv_handle_t *handle, int status)
{
	if (task->finished) {
		assert(task->leading == false);
		qr_task_complete(task);
		if (!handle || handle->type != UV_TCP) {
			return status;
		}
		struct session* s = handle->data;
		assert(s);
		if (!session_is_outgoing(s) || session_waitinglist_is_empty(s)) {
			return status;
		}
	}

	if (handle) {
		struct session* s = handle->data;
		bool outgoing = session_is_outgoing(s);
		if (!outgoing) {
			struct session* source_s = task->ctx->source.session;
			if (source_s) {
				assert (session_get_handle(source_s) == handle);
			}
		}
		if (handle->type == UV_TCP && outgoing && !session_waitinglist_is_empty(s)) {
			session_waitinglist_del(s, task);
			if (session_is_closing(s)) {
				return status;
			}
			/* Finalize the task, if any errors.
			 * We can't add it to the end of waiting list for retrying
			 * since it may lead endless loop in some circumstances
			 * (for instance: tls; send->tls_push->too many non-critical errors->
			 * on_send with nonzero status->re-add to waiting->send->etc).*/
			if (status != 0) {
				if (outgoing) {
					qr_task_finalize(task, KR_STATE_FAIL);
				} else {
					assert(task->ctx->source.session == s);
					task->ctx->source.session = NULL;
				}
				session_tasklist_del(s, task);
			}
			struct qr_task *waiting_task = session_waitinglist_get_first(s);
			if (waiting_task) {
				struct sockaddr *peer = session_get_peer(s);
				knot_pkt_t *pkt = waiting_task->pktbuf;
				int ret = qr_task_send(waiting_task, handle, peer, pkt);
				if (ret != kr_ok()) {
					session_tasks_finalize(s, KR_STATE_FAIL);
					session_close(s);
					return status;
				}
			}
		}
		if (!session_is_closing(s)) {
			io_start_read(handle); /* Start reading new query */
		}
	}
	return status;
}

static void on_send(uv_udp_send_t *req, int status)
{
	uv_handle_t *handle = (uv_handle_t *)(req->handle);
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;
	assert(worker == get_worker());
	struct qr_task *task = req->data;
	qr_task_on_send(task, handle, status);
	qr_task_unref(task);
	iorequest_release(worker, req);
}

static void on_task_write(uv_write_t *req, int status)
{
	uv_handle_t *handle = (uv_handle_t *)(req->handle);
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;
	assert(worker == get_worker());
	struct qr_task *task = req->data;
	qr_task_on_send(task, handle, status);
	qr_task_unref(task);
	iorequest_release(worker, req);
}

static int qr_task_send(struct qr_task *task, uv_handle_t *handle,
			struct sockaddr *addr, knot_pkt_t *pkt)
{
	if (!handle) {
		return qr_task_on_send(task, handle, kr_error(EIO));
	}

	int ret = 0;
	struct request_ctx *ctx = task->ctx;
	struct worker_ctx *worker = ctx->worker;
	struct kr_request *req = &ctx->req;
	void *ioreq = iorequest_borrow(worker);
	if (!ioreq) {
		return qr_task_on_send(task, handle, kr_error(ENOMEM));
	}
	if (knot_wire_get_qr(pkt->wire) == 0) {
		/*
		 * Query must be finalised using destination address before
		 * sending.
		 *
		 * Libuv does not offer a convenient way how to obtain a source
		 * IP address from a UDP handle that has been initialised using
		 * uv_udp_init(). The uv_udp_getsockname() fails because of the
		 * lazy socket initialisation.
		 *
		 * @note -- A solution might be opening a separate socket and
		 * trying to obtain the IP address from it.
		 */
		ret = kr_resolve_checkout(req, NULL, addr,
		                          handle->type == UV_UDP ? SOCK_DGRAM : SOCK_STREAM,
		                          pkt);
		if (ret != 0) {
			iorequest_release(worker, ioreq);
			return ret;
		}
	}

	/* Pending ioreq on current task */
	qr_task_ref(task);

	/* Send using given protocol */
	struct session *session = handle->data;
	assert(session->closing == false);
	if (session->has_tls) {
		uv_write_t *write_req = (uv_write_t *)ioreq;
		write_req->data = task;
		ret = tls_write(write_req, handle, pkt, &on_task_write);
	} else if (handle->type == UV_UDP) {
		uv_udp_send_t *send_req = (uv_udp_send_t *)ioreq;
		uv_buf_t buf = { (char *)pkt->wire, pkt->size };
		send_req->data = task;
		ret = uv_udp_send(send_req, (uv_udp_t *)handle, &buf, 1, addr, &on_send);
	} else if (handle->type == UV_TCP) {
		uv_write_t *write_req = (uv_write_t *)ioreq;
		uint16_t pkt_size = htons(pkt->size);
		uv_buf_t buf[2] = {
			{ (char *)&pkt_size, sizeof(pkt_size) },
			{ (char *)pkt->wire, pkt->size }
		};
		write_req->data = task;
		ret = uv_write(write_req, (uv_stream_t *)handle, buf, 2, &on_task_write);
	} else {
		assert(false);
	}

	if (ret == 0) {
		if (worker->too_many_open &&
		    worker->stats.rconcurrent <
			worker->rconcurrent_highwatermark - 10) {
			worker->too_many_open = false;
		}
	} else {
		iorequest_release(worker, ioreq);
		qr_task_unref(task);
		if (ret == UV_EMFILE) {
			worker->too_many_open = true;
			worker->rconcurrent_highwatermark = worker->stats.rconcurrent;
		}
	}

	/* Update statistics */
	if (ctx->source.session &&
	    handle != session_get_handle(ctx->source.session) &&
	    addr) {
		if (session->has_tls)
			worker->stats.tls += 1;
		else if (handle->type == UV_UDP)
			worker->stats.udp += 1;
		else
			worker->stats.tcp += 1;

		if (addr->sa_family == AF_INET6)
			worker->stats.ipv6 += 1;
		else if (addr->sa_family == AF_INET)
			worker->stats.ipv4 += 1;
	}

	return ret;
}

static int session_next_waiting_send(struct session *session)
{
	int ret = kr_ok();
	if (!session_waitinglist_is_empty(session)) {
		struct sockaddr *peer = session_get_peer(session);
		struct qr_task *task = session_waitinglist_get_first(session);
		uv_handle_t *handle = session_get_handle(session);
		ret = qr_task_send(task, handle, peer, task->pktbuf);
	}
	return ret;
}

static int session_tls_hs_cb(struct session *session, int status)
{
	assert(session_is_outgoing(session));
	uv_handle_t *handle = session_get_handle(session);
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;
	struct sockaddr *peer = session_get_peer(session);
	int deletion_res = worker_del_tcp_waiting(worker, peer);
	int ret = kr_ok();

	if (status) {
		kr_nsrep_update_rtt(NULL, peer, KR_NS_DEAD,
				    worker->engine->resolver.cache_rtt,
				    KR_NS_UPDATE_NORESET);
		return ret;
	}

	/* handshake was completed successfully */
	struct tls_client_ctx_t *tls_client_ctx = session_tls_get_client_ctx(session);
	struct tls_client_paramlist_entry *tls_params = tls_client_ctx->params;
	gnutls_session_t tls_session = tls_client_ctx->c.tls_session;
	if (gnutls_session_is_resumed(tls_session) != 0) {
		kr_log_verbose("[tls_client] TLS session has resumed\n");
	} else {
		kr_log_verbose("[tls_client] TLS session has not resumed\n");
		/* session wasn't resumed, delete old session data ... */
		if (tls_params->session_data.data != NULL) {
			gnutls_free(tls_params->session_data.data);
			tls_params->session_data.data = NULL;
			tls_params->session_data.size = 0;
		}
		/* ... and get the new session data */
		gnutls_datum_t tls_session_data = { NULL, 0 };
		ret = gnutls_session_get_data2(tls_session, &tls_session_data);
		if (ret == 0) {
			tls_params->session_data = tls_session_data;
		}
	}

	ret = worker_add_tcp_connected(worker, peer, session);
	if (deletion_res == kr_ok() && ret == kr_ok()) {
		ret = session_next_waiting_send(session);
	} else {
		ret = kr_error(EINVAL);
	}

	if (ret != kr_ok()) {
		/* Something went wrong.
		 * Session isn't in the list of waiting sessions,
		 * or addition to the list of connected sessions failed,
		 * or write to upstream failed. */
		session_waitinglist_finalize(session, KR_STATE_FAIL);
		worker_del_tcp_connected(worker, peer);
		assert(session_tasklist_is_empty(session));
		session_close(session);
	} else {
		uv_timer_t *t = session_get_timer(session);
		uv_timer_stop(t);
		t->data = session;
		session_timer_start(session, on_tcp_watchdog_timeout, MAX_TCP_INACTIVITY, 0);
	}
	return kr_ok();
}


static struct kr_query *task_get_last_pending_query(struct qr_task *task)
{
	if (!task || task->ctx->req.rplan.pending.len == 0) {
		return NULL;
	}

	return array_tail(task->ctx->req.rplan.pending);
}


static void on_connect(uv_connect_t *req, int status)
{
	struct worker_ctx *worker = get_worker();
	uv_stream_t *handle = req->handle;
	struct session *session = handle->data;
	struct sockaddr *peer = session_get_peer(session);

	assert(session_is_outgoing(session));

	if (status == UV_ECANCELED) {
		worker_del_tcp_waiting(worker, peer);
		assert(session_is_empty(session) && session_is_closing(session));
		iorequest_release(worker, req);
		return;
	}

	if (session_is_closing(session)) {
		worker_del_tcp_waiting(worker, peer);
		assert(session_is_empty(session));
		iorequest_release(worker, req);
		return;
	}

	uv_timer_t *t = session_get_timer(session);
	uv_timer_stop(t);

	if (status != 0) {
		worker_del_tcp_waiting(worker, peer);
		session_waitinglist_retry(session, false);
		assert(session_tasklist_is_empty(session));
		iorequest_release(worker, req);
		session_close(session);
		return;
	}

	if (!session_has_tls(session)) {
		/* if there is a TLS, session still waiting for handshake,
		 * otherwise remove it from waiting list */
		if (worker_del_tcp_waiting(worker, peer) != 0) {
			/* session isn't in list of waiting queries, *
			 * something gone wrong */
			session_waitinglist_finalize(session, KR_STATE_FAIL);
			assert(session_tasklist_is_empty(session));
			iorequest_release(worker, req);
			session_close(session);
			return;
		}
	}

	struct qr_task *task = session_waitinglist_get_first(session);
	struct kr_query *qry = task_get_last_pending_query(task);
	WITH_VERBOSE (qry) {
		struct sockaddr *peer = session_get_peer(session);
		char peer_str[INET6_ADDRSTRLEN];
		inet_ntop(peer->sa_family, kr_inaddr(peer), peer_str, sizeof(peer_str));
		VERBOSE_MSG(qry, "=> connected to '%s'\n", peer_str);
	}

	session_set_connected(session, true);

	int ret = kr_ok();
	if (session_has_tls(session)) {
		struct tls_client_ctx_t *tls_ctx = session_tls_get_client_ctx(session);
		ret = tls_client_connect_start(tls_ctx, session, session_tls_hs_cb);
		if (ret == kr_error(EAGAIN)) {
			iorequest_release(worker, req);
			session_start_read(session);
			session_timer_start(session, on_tcp_watchdog_timeout, MAX_TCP_INACTIVITY, 0);
			return;
		}
	}

	if (ret == kr_ok()) {
		ret = session_next_waiting_send(session);
		if (ret == kr_ok()) {
			session_timer_start(session, on_tcp_watchdog_timeout, MAX_TCP_INACTIVITY, 0);
			struct sockaddr *peer = session_get_peer(session);
			worker_add_tcp_connected(worker, peer, session);
			iorequest_release(worker, req);
			return;
		}
	}

	session_waitinglist_finalize(session, KR_STATE_FAIL);
	assert(session_tasklist_is_empty(session));
	iorequest_release(worker, req);
	session_close(session);
}

static void on_tcp_connect_timeout(uv_timer_t *timer)
{
	struct session *session = timer->data;

	uv_timer_stop(timer);
	struct worker_ctx *worker = get_worker();

	assert (session_waitinglist_get_len(session) == session_tasklist_get_len(session));

	struct sockaddr *peer = session_get_peer(session);
	worker_del_tcp_waiting(worker, peer);

	struct qr_task *task = session_waitinglist_get_first(session);
	struct kr_query *qry = task_get_last_pending_query(task);
	WITH_VERBOSE (qry) {
		char peer_str[INET6_ADDRSTRLEN];
		inet_ntop(peer->sa_family, kr_inaddr(peer), peer_str, sizeof(peer_str));
		VERBOSE_MSG(qry, "=> connection to '%s' failed\n", peer_str);
	}

	kr_nsrep_update_rtt(NULL, peer, KR_NS_DEAD,
			    worker->engine->resolver.cache_rtt,
			    KR_NS_UPDATE_NORESET);

	worker->stats.timeout += session_waitinglist_get_len(session);
	session_waitinglist_retry(session, true);
	assert (session_tasklist_is_empty(session));
	session_close(session);
}

static void on_tcp_watchdog_timeout(uv_timer_t *timer)
{
	struct session *session = timer->data;
	struct worker_ctx *worker =  timer->loop->data;
	struct sockaddr *peer = session_get_peer(session);

	assert(session_is_outgoing(session));

	uv_timer_stop(timer);

	if (session_has_tls(session)) {
		worker_del_tcp_waiting(worker, peer);
	}

	worker_del_tcp_connected(worker, peer);
	worker->stats.timeout += session_waitinglist_get_len(session);
	session_waitinglist_finalize(session, KR_STATE_FAIL);
	worker->stats.timeout += session_tasklist_get_len(session);
	session_tasklist_finalize(session, KR_STATE_FAIL);
	session_close(session);
}

/* This is called when I/O timeouts */
static void on_udp_timeout(uv_timer_t *timer)
{
	struct session *session = timer->data;
	assert(session_get_handle(session)->data == session);
	assert(session_tasklist_get_len(session) == 1);
	assert(session_waitinglist_is_empty(session));

	uv_timer_stop(timer);

	/* Penalize all tried nameservers with a timeout. */
	struct qr_task *task = session_tasklist_get_first(session);
	struct worker_ctx *worker = task->ctx->worker;
	if (task->leading && task->pending_count > 0) {
		struct kr_query *qry = array_tail(task->ctx->req.rplan.pending);
		struct sockaddr_in6 *addrlist = (struct sockaddr_in6 *)task->addrlist;
		for (uint16_t i = 0; i < MIN(task->pending_count, task->addrlist_count); ++i) {
			struct sockaddr *choice = (struct sockaddr *)(&addrlist[i]);
			WITH_VERBOSE(qry) {
				char addr_str[INET6_ADDRSTRLEN];
				inet_ntop(choice->sa_family, kr_inaddr(choice), addr_str, sizeof(addr_str));
				VERBOSE_MSG(qry, "=> server: '%s' flagged as 'bad'\n", addr_str);
			}
			kr_nsrep_update_rtt(&qry->ns, choice, KR_NS_DEAD,
					    worker->engine->resolver.cache_rtt,
					    KR_NS_UPDATE_NORESET);
		}
	}
	task->timeouts += 1;
	worker->stats.timeout += 1;
	qr_task_step(task, NULL, NULL);
}

static void on_session_idle_timeout(uv_timer_t *timer)
{
	struct session *s = timer->data;
	assert(s);
	uv_timer_stop(timer);
	if (session_is_closing(s)) {
		return;
	}
	/* session was not in use during timer timeout
	 * remove it from connection list and close
	 */
	assert(session_is_empty(s));
	session_close(s);
}

static uv_handle_t *retransmit(struct qr_task *task)
{
	uv_handle_t *ret = NULL;
	if (task && task->addrlist && task->addrlist_count > 0) {
		struct sockaddr_in6 *choice = &((struct sockaddr_in6 *)task->addrlist)[task->addrlist_turn];
		if (!choice) {
			return ret;
		}
		ret = ioreq_spawn(task, SOCK_DGRAM, choice->sin6_family);
		if (!ret) {
			return ret;
		}
		struct sockaddr *addr = (struct sockaddr *)choice;
		struct session *session = ret->data;
		struct sockaddr *peer = session_get_peer(session);
		assert (peer->sa_family == AF_UNSPEC && session_is_outgoing(session));
		memcpy(peer, addr, kr_sockaddr_len(addr));
		if (qr_task_send(task, ret, (struct sockaddr *)choice,
				 task->pktbuf) == 0) {
			task->addrlist_turn = (task->addrlist_turn + 1) %
					      task->addrlist_count; /* Round robin */
		}
	}
	return ret;
}

static void on_retransmit(uv_timer_t *req)
{
	struct session *session = req->data;
	assert(session_tasklist_get_len(session) == 1);

	uv_timer_stop(req);
	struct qr_task *task = session_tasklist_get_first(session);
	if (retransmit(task) == NULL) {
		/* Not possible to spawn request, start timeout timer with remaining deadline. */
		uint64_t timeout = KR_CONN_RTT_MAX - task->pending_count * KR_CONN_RETRY;
		uv_timer_start(req, on_udp_timeout, timeout, 0);
	} else {
		uv_timer_start(req, on_retransmit, KR_CONN_RETRY, 0);
	}
}

static void subreq_finalize(struct qr_task *task, const struct sockaddr *packet_source, knot_pkt_t *pkt)
{
	/* Close pending timer */
	ioreq_kill_pending(task);
	/* Clear from outgoing table. */
	if (!task->leading)
		return;
	char key[SUBREQ_KEY_LEN];
	const int klen = subreq_key(key, task->pktbuf);
	if (klen > 0) {
		void *val_deleted;
		int ret = trie_del(task->ctx->worker->subreq_out, key, klen, &val_deleted);
		assert(ret == KNOT_EOK && val_deleted == task); (void)ret;
	}
	/* Notify waiting tasks. */
	struct kr_query *leader_qry = array_tail(task->ctx->req.rplan.pending);
	for (size_t i = task->waiting.len; i > 0; i--) {
		struct qr_task *follower = task->waiting.at[i - 1];
		/* Reuse MSGID and 0x20 secret */
		if (follower->ctx->req.rplan.pending.len > 0) {
			struct kr_query *qry = array_tail(follower->ctx->req.rplan.pending);
			qry->id = leader_qry->id;
			qry->secret = leader_qry->secret;
			leader_qry->secret = 0; /* Next will be already decoded */
		}
		qr_task_step(follower, packet_source, pkt);
		qr_task_unref(follower);
	}
	task->waiting.len = 0;
	task->leading = false;
}

static void subreq_lead(struct qr_task *task)
{
	assert(task);
	char key[SUBREQ_KEY_LEN];
	const int klen = subreq_key(key, task->pktbuf);
	if (klen < 0)
		return;
	struct qr_task **tvp = (struct qr_task **)
		trie_get_ins(task->ctx->worker->subreq_out, key, klen);
	if (unlikely(!tvp))
		return; /*ENOMEM*/
	if (unlikely(*tvp != NULL)) {
		assert(false);
		return;
	}
	*tvp = task;
	task->leading = true;
}

static bool subreq_enqueue(struct qr_task *task)
{
	assert(task);
	char key[SUBREQ_KEY_LEN];
	const int klen = subreq_key(key, task->pktbuf);
	if (klen < 0)
		return false;
	struct qr_task **leader = (struct qr_task **)
		trie_get_try(task->ctx->worker->subreq_out, key, klen);
	if (!leader /*ENOMEM*/ || !*leader)
		return false;
	/* Enqueue itself to leader for this subrequest. */
	int ret = array_push_mm((*leader)->waiting, task,
				kr_memreserve, &(*leader)->ctx->req.pool);
	if (unlikely(ret < 0)) /*ENOMEM*/
		return false;
	qr_task_ref(task);
	return true;
}

static int qr_task_finalize(struct qr_task *task, int state)
{
	assert(task && task->leading == false);
	if (task->finished) {
		return 0;
	}
	struct request_ctx *ctx = task->ctx;
	kr_resolve_finish(&ctx->req, state);

	task->finished = true;
	if (ctx->source.session == NULL) {
		(void) qr_task_on_send(task, NULL, kr_error(EIO));
		return state == KR_STATE_DONE ? 0 : kr_error(EIO);
	}

	/* Reference task as the callback handler can close it */
	qr_task_ref(task);

	/* Send back answer */
	struct session *source_session = ctx->source.session;
	uv_handle_t *handle = session_get_handle(source_session);
	assert(!session_is_closing(source_session));
	assert(handle && handle->data == ctx->source.session);
	assert(ctx->source.addr.ip.sa_family != AF_UNSPEC);
	int res = qr_task_send(task, handle,
			       (struct sockaddr *)&ctx->source.addr,
			        ctx->req.answer);
	if (res != kr_ok()) {
		(void) qr_task_on_send(task, NULL, kr_error(EIO));
		/* Since source session is erroneous detach all tasks. */
		while (!session_tasklist_is_empty(source_session)) {
			struct qr_task *t = session_tasklist_get_first(source_session);
			struct request_ctx *c = t->ctx;
			assert(c->source.session == source_session);
			c->source.session = NULL;
			/* Don't finalize them as there can be other tasks
			 * waiting for answer to this particular task.
			 * (ie. task->leading is true) */
			session_tasklist_del_index(source_session, 0);
		}
		session_close(source_session);
	} else if (handle->type == UV_TCP && ctx->source.session) {
		/* Don't try to close source session at least
		 * retry_interval_for_timeout_timer milliseconds */
		session_timer_restart(ctx->source.session);
	}

	qr_task_unref(task);

	return state == KR_STATE_DONE ? 0 : kr_error(EIO);
}

static int qr_task_step(struct qr_task *task,
			const struct sockaddr *packet_source, knot_pkt_t *packet)
{
	/* No more steps after we're finished. */
	if (!task || task->finished) {
		return kr_error(ESTALE);
	}

	/* Close pending I/O requests */
	subreq_finalize(task, packet_source, packet);
	/* Consume input and produce next query */
	struct request_ctx *ctx = task->ctx;
	assert(ctx);
	struct kr_request *req = &ctx->req;
	struct worker_ctx *worker = ctx->worker;
	int sock_type = -1;
	task->addrlist = NULL;
	task->addrlist_count = 0;
	task->addrlist_turn = 0;
	req->has_tls = (ctx->source.session && session_has_tls(ctx->source.session));

	if (worker->too_many_open) {
		struct kr_rplan *rplan = &req->rplan;
		if (worker->stats.rconcurrent <
			worker->rconcurrent_highwatermark - 10) {
			worker->too_many_open = false;
		} else if (packet && kr_rplan_empty(rplan)) {
			/* new query; TODO - make this detection more obvious */
			kr_resolve_consume(req, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}
	}

	int state = kr_resolve_consume(req, packet_source, packet);
	while (state == KR_STATE_PRODUCE) {
		state = kr_resolve_produce(req, &task->addrlist,
					   &sock_type, task->pktbuf);
		if (unlikely(++task->iter_count > KR_ITER_LIMIT ||
			     task->timeouts >= KR_TIMEOUT_LIMIT)) {
			return qr_task_finalize(task, KR_STATE_FAIL);
		}
	}

	/* We're done, no more iterations needed */
	if (state & (KR_STATE_DONE|KR_STATE_FAIL)) {
		return qr_task_finalize(task, state);
	} else if (!task->addrlist || sock_type < 0) {
		return qr_task_step(task, NULL, NULL);
	}

	/* Count available address choices */
	struct sockaddr_in6 *choice = (struct sockaddr_in6 *)task->addrlist;
	for (size_t i = 0; i < KR_NSREP_MAXADDR && choice->sin6_family != AF_UNSPEC; ++i) {
		task->addrlist_count += 1;
		choice += 1;
	}

	/* Start fast retransmit with UDP, otherwise connect. */
	int ret = 0;
	if (sock_type == SOCK_DGRAM) {
		/* If there is already outgoing query, enqueue to it. */
		if (subreq_enqueue(task)) {
			return kr_ok(); /* Will be notified when outgoing query finishes. */
		}
		/* Start transmitting */
		uv_handle_t *handle = retransmit(task);
		if (handle == NULL) {
			return qr_task_step(task, NULL, NULL);
		}
		/* Check current query NSLIST */
		struct kr_query *qry = array_tail(req->rplan.pending);
		assert(qry != NULL);
		/* Retransmit at default interval, or more frequently if the mean
		 * RTT of the server is better. If the server is glued, use default rate. */
		size_t timeout = qry->ns.score;
		if (timeout > KR_NS_GLUED) {
			/* We don't have information about variance in RTT, expect +10ms */
			timeout = MIN(qry->ns.score + 10, KR_CONN_RETRY);
		} else {
			timeout = KR_CONN_RETRY;
		}
		/* Announce and start subrequest.
		 * @note Only UDP can lead I/O as it doesn't touch 'task->pktbuf' for reassembly.
		 */
		subreq_lead(task);
		struct session *session = handle->data;
		assert(session_get_handle(session) == handle && (handle->type == UV_UDP));
		ret = session_timer_start(session, on_retransmit, timeout, 0);
		/* Start next step with timeout, fatal if can't start a timer. */
		if (ret != 0) {
			subreq_finalize(task, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}
	} else {
		assert (sock_type == SOCK_STREAM);
		const struct sockaddr *addr =
			packet_source ? packet_source : task->addrlist;
		if (addr->sa_family == AF_UNSPEC) {
			subreq_finalize(task, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}
		struct session* session = NULL;
		if ((session = worker_find_tcp_waiting(ctx->worker, addr)) != NULL) {
			assert(session_is_outgoing(session));
			if (session_is_closing(session)) {
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}
			/* There are waiting tasks.
			 * It means that connection establishing or data sending
			 * is coming right now. */
			/* Task will be notified in on_connect() or qr_task_on_send(). */
			ret = session_waitinglist_add(session, task);
			if (ret < 0) {
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}
			ret = session_tasklist_add(session, task);
			if (ret < 0) {
				session_waitinglist_del(session, task);
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}
			assert(task->pending_count == 0);
			task->pending[task->pending_count] = session_get_handle(session);
			task->pending_count += 1;
		} else if ((session = worker_find_tcp_connected(ctx->worker, addr)) != NULL) {
			/* Connection has been already established */
			assert(session_is_outgoing(session));
			if (session_is_closing(session)) {
				session_tasklist_del(session, task);
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}

			if (session_tasklist_get_len(session) >= worker->tcp_pipeline_max) {
				session_tasklist_del(session, task);
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}

			/* will be removed in qr_task_on_send() */
			ret = session_waitinglist_add(session, task);
			if (ret < 0) {
				session_tasklist_del(session, task);
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}
			ret = session_tasklist_add(session, task);
			if (ret < 0) {
				session_waitinglist_del(session, task);
				session_tasklist_del(session, task);
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}
			if (session_waitinglist_get_len(session) == 1) {
				ret = qr_task_send(task, session_get_handle(session),
						   session_get_peer(session), task->pktbuf);
				if (ret < 0) {
					session_waitinglist_del(session, task);
					session_tasklist_del(session, task);
					session_tasklist_finalize(session, KR_STATE_FAIL);
					subreq_finalize(task, packet_source, packet);
					session_close(session);
					return qr_task_finalize(task, KR_STATE_FAIL);
				}
				if (session_tasklist_get_len(session) == 1) {
					session_timer_stop(session);
					ret = session_timer_start(session, on_tcp_watchdog_timeout,
								  MAX_TCP_INACTIVITY, 0);
				}
				if (ret < 0) {
					session_waitinglist_del(session, task);
					session_tasklist_del(session, task);
					session_tasklist_finalize(session, KR_STATE_FAIL);
					subreq_finalize(task, packet_source, packet);
					session_close(session);
					return qr_task_finalize(task, KR_STATE_FAIL);
				}
			}
			assert(task->pending_count == 0);
			task->pending[task->pending_count] = session_get_handle(session);
			task->pending_count += 1;
		} else {
			/* Make connection */
			uv_connect_t *conn = (uv_connect_t *)iorequest_borrow(ctx->worker);
			if (!conn) {
				return qr_task_step(task, NULL, NULL);
			}
			uv_handle_t *client = ioreq_spawn(task, sock_type,
							  addr->sa_family);
			if (!client) {
				iorequest_release(ctx->worker, conn);
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}
			session = client->data;
			ret = worker_add_tcp_waiting(ctx->worker, addr, session);
			if (ret < 0) {
				session_tasklist_del(session, task);
				iorequest_release(ctx->worker, conn);
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}
			/* will be removed in qr_task_on_send() */
			ret = session_waitinglist_add(session, task);
			if (ret < 0) {
				session_tasklist_del(session, task);
				worker_del_tcp_waiting(ctx->worker, addr);
				iorequest_release(ctx->worker, conn);
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}

			/* Check if there must be TLS */
			struct engine *engine = ctx->worker->engine;
			struct network *net = &engine->net;
			const char *key = tcpsess_key(addr);
			struct tls_client_paramlist_entry *entry = map_get(&net->tls_client_params, key);
			if (entry) {
				assert(session_tls_get_client_ctx(session) == NULL);
				struct tls_client_ctx_t *tls_ctx = tls_client_ctx_new(entry, worker);
				if (!tls_ctx) {
					session_tasklist_del(session, task);
					session_waitinglist_del(session, task);
					worker_del_tcp_waiting(ctx->worker, addr);
					iorequest_release(ctx->worker, conn);
					subreq_finalize(task, packet_source, packet);
					return qr_task_step(task, NULL, NULL);
				}
				tls_client_ctx_set_session(tls_ctx, session);
				session_tls_set_client_ctx(session, tls_ctx);
				session_set_has_tls(session, true);
			}

			conn->data = session;
			struct sockaddr *peer = session_get_peer(session);
			memcpy(peer, addr, kr_sockaddr_len(addr));

			ret = session_timer_start(session, on_tcp_connect_timeout,
						  KR_CONN_RTT_MAX, 0);
			if (ret != 0) {
				session_tasklist_del(session, task);
				session_waitinglist_del(session, task);
				worker_del_tcp_waiting(ctx->worker, addr);
				iorequest_release(ctx->worker, conn);
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}

			struct qr_task *task = session_waitinglist_get_first(session);
			struct kr_query *qry = task_get_last_pending_query(task);
			WITH_VERBOSE (qry) {
				char peer_str[INET6_ADDRSTRLEN];
				inet_ntop(peer->sa_family, kr_inaddr(peer), peer_str, sizeof(peer_str));
				VERBOSE_MSG(qry, "=> connecting to: '%s'\n", peer_str);
			}

			if (uv_tcp_connect(conn, (uv_tcp_t *)client,
					   addr , on_connect) != 0) {
				session_timer_stop(session);
				session_tasklist_del(session, task);
				session_waitinglist_del(session, task);
				worker_del_tcp_waiting(ctx->worker, addr);
				iorequest_release(ctx->worker, conn);
				subreq_finalize(task, packet_source, packet);
				return qr_task_step(task, NULL, NULL);
			}
		}
	}
	return kr_ok();
}

static int parse_packet(knot_pkt_t *query)
{
	if (!query){
		return kr_error(EINVAL);
	}

	/* Parse query packet. */
	int ret = knot_pkt_parse(query, 0);
	if (ret == KNOT_ETRAIL) {
		/* Extra data after message end. */
		ret = kr_error(EMSGSIZE);
	} else if (ret != KNOT_EOK) {
		/* Malformed query. */
		ret = kr_error(EPROTO);
	} else {
		ret = kr_ok();
	}

	return ret;
}

int worker_submit(struct session *session, knot_pkt_t *query)
{
	if (!session) {
		assert(false);
		return kr_error(EINVAL);
	}

	uv_handle_t *handle = session_get_handle(session);
	bool OK = handle && handle->loop->data;
	if (!OK) {
		assert(false);
		return kr_error(EINVAL);
	}

	struct worker_ctx *worker = handle->loop->data;

	/* Parse packet */
	int ret = parse_packet(query);

	/* Start new task on listening sockets,
	 * or resume if this is subrequest */
	struct qr_task *task = NULL;
	struct sockaddr *addr = NULL;
	if (!session_is_outgoing(session)) { /* request from a client */
		/* Ignore badly formed queries. */
		if (!query || ret != 0 || knot_wire_get_qr(query->wire)) {
			if (query) worker->stats.dropped += 1;
			return kr_error(EILSEQ);
		}
		struct request_ctx *ctx = request_create(worker, handle,
							 session_get_peer(session));
		if (!ctx) {
			return kr_error(ENOMEM);
		}

		ret = request_start(ctx, query);
		if (ret != 0) {
			request_free(ctx);
			return kr_error(ENOMEM);
		}

		task = qr_task_create(ctx);
		if (!task) {
			request_free(ctx);
			return kr_error(ENOMEM);
		}
		addr = NULL;
	} else if (query) { /* response from upstream */
		if ((ret != kr_ok() && ret != kr_error(EMSGSIZE)) ||
		    !knot_wire_get_qr(query->wire)) {
			/* Ignore badly formed responses. */
			return kr_error(EILSEQ);
		}
		task = session_tasklist_find(session, knot_wire_get_id(query->wire));
		if (task == NULL) {
			return kr_error(ENOENT);
		}
		assert(!session_is_closing(session));
	}
	assert(uv_is_closing(session_get_handle(session)) == false);

	/* Consume input and produce next message */
	return qr_task_step(task, addr, query);
}

static int map_add_tcp_session(map_t *map, const struct sockaddr* addr,
			       struct session *session)
{
	assert(map && addr);
	const char *key = tcpsess_key(addr);
	assert(key);
	assert(map_contains(map, key) == 0);
	int ret = map_set(map, key, session);
	return ret ? kr_error(EINVAL) : kr_ok();
}

static int map_del_tcp_session(map_t *map, const struct sockaddr* addr)
{
	assert(map && addr);
	const char *key = tcpsess_key(addr);
	assert(key);
	int ret = map_del(map, key);
	return ret ? kr_error(ENOENT) : kr_ok();
}

static struct session* map_find_tcp_session(map_t *map,
					    const struct sockaddr *addr)
{
	assert(map && addr);
	const char *key = tcpsess_key(addr);
	assert(key);
	struct session* ret = map_get(map, key);
	return ret;
}

int worker_add_tcp_connected(struct worker_ctx *worker,
				    const struct sockaddr* addr,
				    struct session *session)
{
#ifndef NDEBUG
	assert(addr);
	const char *key = tcpsess_key(addr);
	assert(key);
	assert(map_contains(&worker->tcp_connected, key) == 0);
#endif
	return map_add_tcp_session(&worker->tcp_connected, addr, session);
}

int worker_del_tcp_connected(struct worker_ctx *worker,
				    const struct sockaddr* addr)
{
	assert(addr && tcpsess_key(addr));
	return map_del_tcp_session(&worker->tcp_connected, addr);
}

static struct session* worker_find_tcp_connected(struct worker_ctx *worker,
						 const struct sockaddr* addr)
{
	return map_find_tcp_session(&worker->tcp_connected, addr);
}

static int worker_add_tcp_waiting(struct worker_ctx *worker,
				  const struct sockaddr* addr,
				  struct session *session)
{
#ifndef NDEBUG
	assert(addr);
	const char *key = tcpsess_key(addr);
	assert(key);
	assert(map_contains(&worker->tcp_waiting, key) == 0);
#endif
	return map_add_tcp_session(&worker->tcp_waiting, addr, session);
}

static int worker_del_tcp_waiting(struct worker_ctx *worker,
				  const struct sockaddr* addr)
{
	assert(addr && tcpsess_key(addr));
	return map_del_tcp_session(&worker->tcp_waiting, addr);
}

static struct session* worker_find_tcp_waiting(struct worker_ctx *worker,
					       const struct sockaddr* addr)
{
	return map_find_tcp_session(&worker->tcp_waiting, addr);
}

/* Return DNS/TCP message size. */
static int get_msg_size(const uint8_t *msg)
{
	return wire_read_u16(msg);
}

int worker_end_tcp(struct session *session)
{
	if (!session) {
		return kr_error(EINVAL);
	}

	session_timer_stop(session);
	
	uv_handle_t *handle = session_get_handle(session);
	struct worker_ctx *worker = handle->loop->data;
	struct sockaddr *peer = session_get_peer(session);
	worker_del_tcp_connected(worker, peer);
	session_set_connected(session, false);

	struct tls_client_ctx_t *tls_client_ctx = session_tls_get_client_ctx(session);
	if (tls_client_ctx) {
		/* Avoid gnutls_bye() call */
		tls_set_hs_state(&tls_client_ctx->c, TLS_HS_NOT_STARTED);
	}

	struct tls_ctx_t *tls_ctx = session_tls_get_server_ctx(session);
	if (tls_ctx) {
		/* Avoid gnutls_bye() call */
		tls_set_hs_state(&tls_ctx->c, TLS_HS_NOT_STARTED);
	}

	assert(session_tasklist_get_len(session) >= session_waitinglist_get_len(session));
	while (!session_waitinglist_is_empty(session)) {
		struct qr_task *task = session_waitinglist_get_first(session);
		session_waitinglist_del_index(session, 0);
		assert(task->refs > 1);
		session_tasklist_del(session, task);
		if (session_is_outgoing(session)) {
			if (task->ctx->req.options.FORWARD) {
				/* We are in TCP_FORWARD mode.
				 * To prevent failing at kr_resolve_consume()
				 * qry.flags.TCP must be cleared.
				 * TODO - refactoring is needed. */
					struct kr_request *req = &task->ctx->req;
					struct kr_rplan *rplan = &req->rplan;
					struct kr_query *qry = array_tail(rplan->pending);
					qry->flags.TCP = false;
			}
			qr_task_step(task, NULL, NULL);
		} else {
			assert(task->ctx->source.session == session);
			task->ctx->source.session = NULL;
		}
		qr_task_unref(task);
	}
	while (!session_tasklist_is_empty(session)) {
		struct qr_task *task = session_tasklist_get_first(session);
		session_tasklist_del_index(session, 0);
		if (session_is_outgoing(session)) {
			if (task->ctx->req.options.FORWARD) {
				struct kr_request *req = &task->ctx->req;
				struct kr_rplan *rplan = &req->rplan;
				struct kr_query *qry = array_tail(rplan->pending);
				qry->flags.TCP = false;
			}
			qr_task_step(task, NULL, NULL);
		} else {
			assert(task->ctx->source.session == session);
			task->ctx->source.session = NULL;
		}
	}
	session_close(session);
	return kr_ok();
}

struct qr_task *worker_resolve_start(struct worker_ctx *worker, knot_pkt_t *query, struct kr_qflags options)
{
	if (!worker || !query) {
		assert(!EINVAL);
		return NULL;
	}

	struct request_ctx *ctx = request_create(worker, NULL, NULL);
	if (!ctx) {
		return NULL;
	}

	/* Create task */
	struct qr_task *task = qr_task_create(ctx);
	if (!task) {
		request_free(ctx);
		return NULL;
	}

	/* Start task */
	int ret = request_start(ctx, query);
	if (ret != 0) {
		/* task is attached to request context,
		 * so dereference (and deallocate) it first */
		request_del_tasks(ctx, task);
		array_clear(ctx->tasks);
		request_free(ctx);
		return NULL;
	}

	/* Set options late, as qr_task_start() -> kr_resolve_begin() rewrite it. */
	kr_qflags_set(&task->ctx->req.options, options);
	return task;
}

int worker_resolve_exec(struct qr_task *task, knot_pkt_t *query)
{
	if (!task) {
		return kr_error(EINVAL);
	}
	return qr_task_step(task, NULL, query);
}

int worker_task_numrefs(const struct qr_task *task)
{
	return task->refs;
}

struct kr_request *worker_task_request(struct qr_task *task)
{
	if (!task || !task->ctx) {
		return NULL;
	}

	return &task->ctx->req;
}

int worker_task_finalize(struct qr_task *task, int state)
{
	return qr_task_finalize(task, state);
}

 int worker_task_step(struct qr_task *task, const struct sockaddr *packet_source,
		      knot_pkt_t *packet)
 {
	 return qr_task_step(task, packet_source, packet);
 }

void worker_task_complete(struct qr_task *task)
{
	return qr_task_complete(task);
}

void worker_task_ref(struct qr_task *task)
{
	qr_task_ref(task);
}

void worker_task_unref(struct qr_task *task)
{
	qr_task_unref(task);
}

void worker_task_timeout_inc(struct qr_task *task)
{
	task->timeouts += 1;
}

struct session *worker_session_borrow(struct worker_ctx *worker)
{
	struct session *s = NULL;
	if (worker->pool_sessions.len > 0) {
		s = array_tail(worker->pool_sessions);
		array_pop(worker->pool_sessions);
		kr_asan_custom_unpoison(session, s);
	} else {
		s = session_new();
	}
	return s;
}

void worker_session_release(struct worker_ctx *worker, uv_handle_t *handle)
{
	if (!worker || !handle) {
		return;
	}
	struct session *s = handle->data;
	if (!s) {
		return;
	}
	assert(session_is_empty(s));
	if (worker->pool_sessions.len < MP_FREELIST_SIZE) {
		session_clear(s);
		array_push(worker->pool_sessions, s);
		kr_asan_custom_poison(session, s);
	} else {
		session_free(s);
	}
}

knot_pkt_t *worker_task_get_pktbuf(const struct qr_task *task)
{
	return task->pktbuf;
}

struct request_ctx *worker_task_get_request(struct qr_task *task)
{
	return task->ctx;
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
