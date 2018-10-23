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


/* Magic defaults for the worker. */
#ifndef MP_FREELIST_SIZE
# ifdef __clang_analyzer__
#  define MP_FREELIST_SIZE 0
# else
#  define MP_FREELIST_SIZE 64 /**< Maximum length of the worker mempool freelist */
# endif
#endif
#ifndef QUERY_RATE_THRESHOLD
#define QUERY_RATE_THRESHOLD (2 * MP_FREELIST_SIZE) /**< Nr of parallel queries considered as high rate */
#endif
#ifndef MAX_PIPELINED
#define MAX_PIPELINED 100
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
	struct qr_task *task;
};

/** Query resolution task. */
struct qr_task
{
	struct request_ctx *ctx;
	knot_pkt_t *pktbuf;
	qr_tasklist_t waiting;
	struct session *pending[MAX_PENDING];
	uint16_t pending_count;
	uint16_t addrlist_count;
	uint16_t addrlist_turn;
	uint16_t timeouts;
	uint16_t iter_count;
	struct sockaddr *addrlist;
	uint32_t refs;
	bool finished : 1;
	bool leading  : 1;
	uint64_t creation_time;
};


/* Convenience macros */
#define qr_task_ref(task) \
	do { ++(task)->refs; } while(0)
#define qr_task_unref(task) \
	do { if (task && --(task)->refs == 0) { qr_task_free(task); } } while (0)

/** @internal get key for tcp session
 *  @note kr_straddr() return pointer to static string
 */
#define tcpsess_key(addr) kr_straddr(addr)

/* Forward decls */
static void qr_task_free(struct qr_task *task);
static int qr_task_step(struct qr_task *task,
			const struct sockaddr *packet_source,
			knot_pkt_t *packet);
static int qr_task_send(struct qr_task *task, struct session *session,
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
static void on_tcp_connect_timeout(uv_timer_t *timer);

/** @internal Get singleton worker. */
static inline struct worker_ctx *get_worker(void)
{
	return uv_default_loop()->data;
}

/*! @internal Create a UDP/TCP handle for an outgoing AF_INET* connection.
 *  socktype is SOCK_* */
static uv_handle_t *ioreq_spawn(struct worker_ctx *worker, int socktype, sa_family_t family)
{
	bool precond = (socktype == SOCK_DGRAM || socktype == SOCK_STREAM)
			&& (family == AF_INET  || family == AF_INET6);
	if (!precond) {
		/* assert(false); see #245 */
		kr_log_verbose("[work] ioreq_spawn: pre-condition failed\n");
		return NULL;
	}

	/* Create connection for iterative query */
	uv_handle_t *handle = malloc(socktype == SOCK_DGRAM
					? sizeof(uv_udp_t) : sizeof(uv_tcp_t));
	if (!handle) {
		return NULL;
	}
	int ret = io_create(worker->loop, handle, socktype, family);
	if (ret) {
		if (ret == UV_EMFILE) {
			worker->too_many_open = true;
			worker->rconcurrent_highwatermark = worker->stats.rconcurrent;
		}
		free(handle);
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

	if (ret != 0) {
		io_deinit(handle);
		free(handle);
		return NULL;
	}

	/* Set current handle as a subrequest type. */
	struct session *session = handle->data;
	session_flags(session)->outgoing = true;
	/* Connect or issue query datagram */
	return handle;
}

static void ioreq_kill_pending(struct qr_task *task)
{
	for (uint16_t i = 0; i < task->pending_count; ++i) {
		session_kill_ioreq(task->pending[i], task);
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
					  const struct sockaddr *addr,
					  uint32_t uid)
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
	struct session *s = handle ? handle->data : NULL;
	if (s) {
		assert(session_flags(s)->outgoing == false);
	}
	ctx->source.session = s;

	struct kr_request *req = &ctx->req;
	req->pool = pool;
	req->vars_ref = LUA_NOREF;
	req->uid = uid;

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
	assert(ctx->task == NULL);
	ctx->task = task;
	/* Make the primary reference to task. */
	qr_task_ref(task);
	task->creation_time = kr_now();
	ctx->worker->stats.concurrent += 1;
	return task;
}

/* This is called when the task refcount is zero, free memory. */
static void qr_task_free(struct qr_task *task)
{
	struct request_ctx *ctx = task->ctx;

	assert(ctx);

	struct worker_ctx *worker = ctx->worker;

	if (ctx->task == NULL) {
		request_free(ctx);
	}

	/* Update stats */
	worker->stats.concurrent -= 1;
}

/*@ Register new qr_task within session. */
static int qr_task_register(struct qr_task *task, struct session *session)
{
	assert(!session_flags(session)->outgoing && session_get_handle(session)->type == UV_TCP);

	session_tasklist_add(session, task);

	struct request_ctx *ctx = task->ctx;
	assert(ctx && (ctx->source.session == NULL || ctx->source.session == session));
	ctx->source.session = session;
	/* Soft-limit on parallel queries, there is no "slow down" RCODE
	 * that we could use to signalize to client, but we can stop reading,
	 * an in effect shrink TCP window size. To get more precise throttling,
	 * we would need to copy remainder of the unread buffer and reassemble
	 * when resuming reading. This is NYI.  */
	if (session_tasklist_get_len(session) >= task->ctx->worker->tcp_pipeline_max &&
	    !session_flags(session)->throttled && !session_flags(session)->closing) {
		session_stop_read(session);
		session_flags(session)->throttled = true;
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
		assert(!session_flags(s)->outgoing && session_waitinglist_is_empty(s));
		ctx->source.session = NULL;
		session_tasklist_del(s, task);
	}

	/* Release primary reference to task. */
	if (ctx->task == task) {
		ctx->task = NULL;
		qr_task_unref(task);
	}
}

/* This is called when we send subrequest / answer */
static int qr_task_on_send(struct qr_task *task, uv_handle_t *handle, int status)
{

	if (task->finished) {
		assert(task->leading == false);
		qr_task_complete(task);
	}

	if (!handle || handle->type != UV_TCP) {
		return status;
	}

	struct session* s = handle->data;
	assert(s);
	if (status != 0) {
		session_tasklist_del(s, task);
	}

	if (session_flags(s)->outgoing || session_flags(s)->closing) {
		return status;
	}

	struct worker_ctx *worker = task->ctx->worker;
	if (session_flags(s)->throttled &&
	    session_tasklist_get_len(s) < worker->tcp_pipeline_max/2) {
	   /* Start reading again if the session is throttled and
	    * the number of outgoing requests is below watermark. */
		session_start_read(s);
		session_flags(s)->throttled = false;
	}

	return status;
}

static void on_send(uv_udp_send_t *req, int status)
{
	struct qr_task *task = req->data;
	uv_handle_t *h = (uv_handle_t *)req->handle;
	qr_task_on_send(task, h, status);
	qr_task_unref(task);
	free(req);
}

static void on_write(uv_write_t *req, int status)
{
	struct qr_task *task = req->data;
	uv_handle_t *h = (uv_handle_t *)req->handle;
	qr_task_on_send(task, h, status);
	qr_task_unref(task);
	free(req);
}

static int qr_task_send(struct qr_task *task, struct session *session,
			struct sockaddr *addr, knot_pkt_t *pkt)
{
	if (!session) {
		return qr_task_on_send(task, NULL, kr_error(EIO));
	}

	int ret = 0;
	struct request_ctx *ctx = task->ctx;
	struct kr_request *req = &ctx->req;

	uv_handle_t *handle = session_get_handle(session);
	assert(handle && handle->data == session);
	const bool is_stream = handle->type == UV_TCP;
	if (!is_stream && handle->type != UV_UDP) abort();

	if (addr == NULL) {
		addr = session_get_peer(session);
	}

	if (pkt == NULL) {
		pkt = worker_task_get_pktbuf(task);
	}

	if (session_flags(session)->outgoing && handle->type == UV_TCP) {
		size_t try_limit = session_tasklist_get_len(session) + 1;
		uint16_t msg_id = knot_wire_get_id(pkt->wire);
		size_t try_count = 0;
		while (session_tasklist_find_msgid(session, msg_id) &&
		       try_count <= try_limit) {
			++msg_id;
			++try_count;
		}
		if (try_count > try_limit) {
			return kr_error(ENOENT);
		}
		worker_task_pkt_set_msgid(task, msg_id);
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
		                          is_stream ? SOCK_STREAM : SOCK_DGRAM,
		                          pkt);
		if (ret != 0) {
			return ret;
		}
	}

	uv_handle_t *ioreq = malloc(is_stream ? sizeof(uv_write_t) : sizeof(uv_udp_send_t));
	if (!ioreq) {
		return qr_task_on_send(task, handle, kr_error(ENOMEM));
	}

	/* Pending ioreq on current task */
	qr_task_ref(task);

	struct worker_ctx *worker = ctx->worker;
	/* Send using given protocol */
	assert(!session_flags(session)->closing);
	if (session_flags(session)->has_tls) {
		uv_write_t *write_req = (uv_write_t *)ioreq;
		write_req->data = task;
		ret = tls_write(write_req, handle, pkt, &on_write);
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
		ret = uv_write(write_req, (uv_stream_t *)handle, buf, 2, &on_write);
	} else {
		assert(false);
	}

	if (ret == 0) {
		session_touch(session);
		if (session_flags(session)->outgoing) {
			session_tasklist_add(session, task);
		}
		if (worker->too_many_open &&
		    worker->stats.rconcurrent <
			worker->rconcurrent_highwatermark - 10) {
			worker->too_many_open = false;
		}
	} else {
		free(ioreq);
		qr_task_unref(task);
		if (ret == UV_EMFILE) {
			worker->too_many_open = true;
			worker->rconcurrent_highwatermark = worker->stats.rconcurrent;
			ret = kr_error(UV_EMFILE);
		}
	}

	/* Update statistics */
	if (session_flags(session)->outgoing && addr) {
		if (session_flags(session)->has_tls)
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

static int session_tls_hs_cb(struct session *session, int status)
{
	assert(session_flags(session)->outgoing);
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
		while (!session_waitinglist_is_empty(session)) {
			struct qr_task *t = session_waitinglist_get(session);
			ret = qr_task_send(t, session, NULL, NULL);
			if (ret != 0) {
				break;
			}
			session_waitinglist_pop(session, true);
		}
	} else {
		ret = kr_error(EINVAL);
	}

	if (ret != kr_ok()) {
		/* Something went wrong.
		 * Session isn't in the list of waiting sessions,
		 * or addition to the list of connected sessions failed,
		 * or write to upstream failed. */
		worker_del_tcp_connected(worker, peer);
		session_waitinglist_finalize(session, KR_STATE_FAIL);
		assert(session_tasklist_is_empty(session));
		session_close(session);
	} else {
		session_timer_stop(session);
		session_timer_start(session, tcp_timeout_trigger,
				    MAX_TCP_INACTIVITY, MAX_TCP_INACTIVITY);
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

static int send_waiting(struct session *session)
{
	int ret = 0;
	while (!session_waitinglist_is_empty(session)) {
		struct qr_task *t = session_waitinglist_get(session);
		ret = qr_task_send(t, session, NULL, NULL);
		if (ret != 0) {
			session_waitinglist_finalize(session, KR_STATE_FAIL);
			session_tasklist_finalize(session, KR_STATE_FAIL);
			session_close(session);
			break;
		}
		session_waitinglist_pop(session, true);
	}
	return ret;
}

static void on_connect(uv_connect_t *req, int status)
{
	struct worker_ctx *worker = get_worker();
	uv_stream_t *handle = req->handle;
	struct session *session = handle->data;
	struct sockaddr *peer = session_get_peer(session);
	free(req);

	assert(session_flags(session)->outgoing);

	if (status == UV_ECANCELED) {
		worker_del_tcp_waiting(worker, peer);
		assert(session_is_empty(session) && session_flags(session)->closing);
		return;
	}

	if (session_flags(session)->closing) {
		worker_del_tcp_waiting(worker, peer);
		assert(session_is_empty(session));
		return;
	}

	if (status != 0) {
		worker_del_tcp_waiting(worker, peer);
		assert(session_tasklist_is_empty(session));
		session_waitinglist_retry(session, false);
		session_close(session);
		return;
	}

	if (!session_flags(session)->has_tls) {
		/* if there is a TLS, session still waiting for handshake,
		 * otherwise remove it from waiting list */
		if (worker_del_tcp_waiting(worker, peer) != 0) {
			/* session isn't in list of waiting queries, *
			 * something gone wrong */
			session_waitinglist_finalize(session, KR_STATE_FAIL);
			assert(session_tasklist_is_empty(session));
			session_close(session);
			return;
		}
	}

	struct qr_task *task = session_waitinglist_get(session);
	struct kr_query *qry = task_get_last_pending_query(task);
	WITH_VERBOSE (qry) {
		struct sockaddr *peer = session_get_peer(session);
		char peer_str[INET6_ADDRSTRLEN];
		inet_ntop(peer->sa_family, kr_inaddr(peer), peer_str, sizeof(peer_str));
		VERBOSE_MSG(qry, "=> connected to '%s'\n", peer_str);
	}

	session_flags(session)->connected = true;
	session_start_read(session);

	int ret = kr_ok();
	if (session_flags(session)->has_tls) {
		struct tls_client_ctx_t *tls_ctx = session_tls_get_client_ctx(session);
		ret = tls_client_connect_start(tls_ctx, session, session_tls_hs_cb);
		if (ret == kr_error(EAGAIN)) {
			session_timer_stop(session);
			session_timer_start(session, tcp_timeout_trigger,
					    MAX_TCP_INACTIVITY, MAX_TCP_INACTIVITY);
			return;
		}
	} else {
		worker_add_tcp_connected(worker, peer, session);
	}

	ret = send_waiting(session);
	if (ret != 0) {
		worker_del_tcp_connected(worker, peer);
		return;
	}

	session_timer_stop(session);
	session_timer_start(session, tcp_timeout_trigger,
			    MAX_TCP_INACTIVITY, MAX_TCP_INACTIVITY);
}

static void on_tcp_connect_timeout(uv_timer_t *timer)
{
	struct session *session = timer->data;

	uv_timer_stop(timer);
	struct worker_ctx *worker = get_worker();

	assert (session_tasklist_is_empty(session));

	struct sockaddr *peer = session_get_peer(session);
	worker_del_tcp_waiting(worker, peer);

	struct qr_task *task = session_waitinglist_get(session);
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

static uv_handle_t *retransmit(struct qr_task *task)
{
	uv_handle_t *ret = NULL;
	if (task && task->addrlist && task->addrlist_count > 0) {
		struct sockaddr_in6 *choice = &((struct sockaddr_in6 *)task->addrlist)[task->addrlist_turn];
		if (!choice) {
			return ret;
		}
		if (task->pending_count >= MAX_PENDING) {
			return ret;
		}
		ret = ioreq_spawn(task->ctx->worker, SOCK_DGRAM, choice->sin6_family);
		if (!ret) {
			return ret;
		}
		struct sockaddr *addr = (struct sockaddr *)choice;
		struct session *session = ret->data;
		struct sockaddr *peer = session_get_peer(session);
		assert (peer->sa_family == AF_UNSPEC && session_flags(session)->outgoing);
		memcpy(peer, addr, kr_sockaddr_len(addr));
		if (qr_task_send(task, session, (struct sockaddr *)choice,
				 task->pktbuf) != 0) {
			session_close(session);
			ret = NULL;
		} else {
			task->pending[task->pending_count] = session;
			task->pending_count += 1;
			task->addrlist_turn = (task->addrlist_turn + 1) %
					      task->addrlist_count; /* Round robin */
			session_start_read(session); /* Start reading answer */
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
	if (!task || task->finished) {
		return;
	}
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
	assert(!session_flags(source_session)->closing);
	assert(ctx->source.addr.ip.sa_family != AF_UNSPEC);
	int res = qr_task_send(task, source_session,
			       (struct sockaddr *)&ctx->source.addr,
			        ctx->req.answer);
	if (res != kr_ok()) {
		(void) qr_task_on_send(task, NULL, kr_error(EIO));
		/* Since source session is erroneous detach all tasks. */
		while (!session_tasklist_is_empty(source_session)) {
			struct qr_task *t = session_tasklist_del_first(source_session, false);
			struct request_ctx *c = t->ctx;
			assert(c->source.session == source_session);
			c->source.session = NULL;
			/* Don't finalize them as there can be other tasks
			 * waiting for answer to this particular task.
			 * (ie. task->leading is true) */
			worker_task_unref(t);
		}
		session_close(source_session);
	}

	qr_task_unref(task);

	return state == KR_STATE_DONE ? 0 : kr_error(EIO);
}

static int udp_task_step(struct qr_task *task,
			 const struct sockaddr *packet_source, knot_pkt_t *packet)
{
	struct request_ctx *ctx = task->ctx;
	struct kr_request *req = &ctx->req;

	/* If there is already outgoing query, enqueue to it. */
	if (subreq_enqueue(task)) {
		return kr_ok(); /* Will be notified when outgoing query finishes. */
	}
	/* Start transmitting */
	uv_handle_t *handle = retransmit(task);
	if (handle == NULL) {
		subreq_finalize(task, packet_source, packet);
		return qr_task_finalize(task, KR_STATE_FAIL);
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
	int ret = session_timer_start(session, on_retransmit, timeout, 0);
	/* Start next step with timeout, fatal if can't start a timer. */
	if (ret != 0) {
		subreq_finalize(task, packet_source, packet);
		return qr_task_finalize(task, KR_STATE_FAIL);
	}
	return kr_ok();
}

static int tcp_task_step(struct qr_task *task,
			 const struct sockaddr *packet_source, knot_pkt_t *packet)
{
	assert(task->pending_count == 0);
	struct request_ctx *ctx = task->ctx;
	struct worker_ctx *worker = ctx->worker;

	const struct sockaddr *addr =
		packet_source ? packet_source : task->addrlist;
	if (addr->sa_family == AF_UNSPEC) {
		/* Target isn't defined. Finalize task with SERVFAIL.
		 * Although task->pending_count is zero, there are can be followers,
		 * so we need to call subreq_finalize() to handle them properly. */
		subreq_finalize(task, packet_source, packet);
		return qr_task_finalize(task, KR_STATE_FAIL);
	}
	int ret = 0;
	struct session* session = NULL;
	if ((session = worker_find_tcp_waiting(ctx->worker, addr)) != NULL) {
		/* Connection is in the list of waiting connections.
		 * It means that connection establishing is coming right now. */
		assert(session_flags(session)->outgoing);
		if (session_flags(session)->closing) {
			/* Something went wrong. Better answer with KR_STATE_FAIL.
			 * TODO: (here and below) normally should not happen,
			 * consider possibility to transform this into
			 * assert(!session_flags(session)->closing). */
			subreq_finalize(task, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}
		/* Add task to the end of list of waiting tasks.
		 * It will be notified in on_connect() or qr_task_on_send(). */
		ret = session_waitinglist_push(session, task);
		if (ret < 0) {
			subreq_finalize(task, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}
	} else if ((session = worker_find_tcp_connected(ctx->worker, addr)) != NULL) {
		/* Connection has been already established. */
		assert(session_flags(session)->outgoing);
		if (session_flags(session)->closing) {
			subreq_finalize(task, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}

		/* If there are any unsent queries, send it first. */
		ret = send_waiting(session);
		if (ret != 0) {
			subreq_finalize(task, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}

		/* No unsent queries at that point. */
		if (session_tasklist_get_len(session) >= worker->tcp_pipeline_max) {
			/* Too many outstanding queries, answer with SERFVAIL, */
			subreq_finalize(task, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}

		/* Send query to upstream. */
		ret = qr_task_send(task, session, NULL, NULL);
		if (ret != 0) {
			/* Error, finalize task with SERVFAIL and
			 * close connection to upstream. */
			session_tasklist_finalize(session, KR_STATE_FAIL);
			subreq_finalize(task, packet_source, packet);
			session_close(session);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}
	} else {
		/* Make connection. */
		uv_connect_t *conn = malloc(sizeof(uv_connect_t));
		if (!conn) {
			return qr_task_step(task, NULL, NULL);
		}
		uv_handle_t *client = ioreq_spawn(worker, SOCK_STREAM,
						  addr->sa_family);
		if (!client) {
			free(conn);
			subreq_finalize(task, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}
		session = client->data;

		/* Add address to the waiting list.
		 * Now it "is waiting to be connected to." */
		ret = worker_add_tcp_waiting(ctx->worker, addr, session);
		if (ret < 0) {
			free(conn);
			subreq_finalize(task, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}

		/* Check if there must be TLS */
		struct engine *engine = ctx->worker->engine;
		struct network *net = &engine->net;
		const char *key = tcpsess_key(addr);
		struct tls_client_paramlist_entry *entry = map_get(&net->tls_client_params, key);
		if (entry) {
			/* Address is configured to be used with TLS.
			 * We need to allocate auxiliary data structure. */
			assert(session_tls_get_client_ctx(session) == NULL);
			struct tls_client_ctx_t *tls_ctx = tls_client_ctx_new(entry, worker);
			if (!tls_ctx) {
				worker_del_tcp_waiting(ctx->worker, addr);
				free(conn);
				subreq_finalize(task, packet_source, packet);
				return qr_task_step(task, NULL, NULL);
			}
			tls_client_ctx_set_session(tls_ctx, session);
			session_tls_set_client_ctx(session, tls_ctx);
			session_flags(session)->has_tls = true;
		}

		conn->data = session;
		/*  Store peer address for the session. */
		struct sockaddr *peer = session_get_peer(session);
		memcpy(peer, addr, kr_sockaddr_len(addr));

		/*  Start watchdog to catch eventual connection timeout. */
		ret = session_timer_start(session, on_tcp_connect_timeout,
					  KR_CONN_RTT_MAX, 0);
		if (ret != 0) {
			worker_del_tcp_waiting(ctx->worker, addr);
			free(conn);
			subreq_finalize(task, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}

		struct kr_query *qry = task_get_last_pending_query(task);
		WITH_VERBOSE (qry) {
			const char *peer_str = kr_straddr(peer);
			VERBOSE_MSG(qry, "=> connecting to: '%s'\n", peer_str ? peer_str : "");
		}

		/*  Start connection process to upstream. */
		if (uv_tcp_connect(conn, (uv_tcp_t *)client, addr , on_connect) != 0) {
			session_timer_stop(session);
			worker_del_tcp_waiting(ctx->worker, addr);
			free(conn);
			subreq_finalize(task, packet_source, packet);
			return qr_task_step(task, NULL, NULL);
		}

		/* Add task to the end of list of waiting tasks.
		 * Will be notified either in on_connect() or in qr_task_on_send(). */
		ret = session_waitinglist_push(session, task);
		if (ret < 0) {
			subreq_finalize(task, packet_source, packet);
			return qr_task_finalize(task, KR_STATE_FAIL);
		}
	}

	return kr_ok();
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
	req->has_tls = (ctx->source.session && session_flags(ctx->source.session)->has_tls);

	if (worker->too_many_open) {
		/* */
		struct kr_rplan *rplan = &req->rplan;
		if (worker->stats.rconcurrent <
			worker->rconcurrent_highwatermark - 10) {
			worker->too_many_open = false;
		} else {
			if (packet && kr_rplan_empty(rplan)) {
				/* new query; TODO - make this detection more obvious */
				kr_resolve_consume(req, packet_source, packet);
			}
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

	int ret = 0;
	if (sock_type == SOCK_DGRAM) {
		/* Start fast retransmit with UDP. */
		ret = udp_task_step(task, packet_source, packet);
	} else {
		/* TCP. Connect to upstream or send the query if connection already exists. */
		assert (sock_type == SOCK_STREAM);
		ret = tcp_task_step(task, packet_source, packet);
	}
	return ret;
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

	const bool is_query = (knot_wire_get_qr(query->wire) == 0);
	const bool is_outgoing = session_flags(session)->outgoing;
	/* Ignore badly formed queries. */
	if (!query ||
	    (ret != kr_ok() && ret != kr_error(EMSGSIZE)) ||
	    (is_query == is_outgoing)) {
		if (query && !is_outgoing) worker->stats.dropped += 1;
		return kr_error(EILSEQ);
	}

	/* Start new task on listening sockets,
	 * or resume if this is subrequest */
	struct qr_task *task = NULL;
	struct sockaddr *addr = NULL;
	if (!is_outgoing) { /* request from a client */
		struct request_ctx *ctx = request_create(worker, handle,
							 session_get_peer(session),
							 knot_wire_get_id(query->wire));
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

		if (handle->type == UV_TCP && qr_task_register(task, session)) {
			return kr_error(ENOMEM);
		}
	} else if (query) { /* response from upstream */
		task = session_tasklist_del_msgid(session, knot_wire_get_id(query->wire));
		if (task == NULL) {
			return kr_error(ENOENT);
		}
		assert(!session_flags(session)->closing);
		addr = session_get_peer(session);
	}
	assert(uv_is_closing(session_get_handle(session)) == false);

	/* Packet was successfully parsed.
	 * Task was created (found). */
	session_touch(session);
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
	session_flags(session)->connected = false;

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

	while (!session_waitinglist_is_empty(session)) {
		struct qr_task *task = session_waitinglist_pop(session, false);
		assert(task->refs > 1);
		session_tasklist_del(session, task);
		if (session_flags(session)->outgoing) {
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
		worker_task_unref(task);
	}
	while (!session_tasklist_is_empty(session)) {
		struct qr_task *task = session_tasklist_del_first(session, false);
		if (session_flags(session)->outgoing) {
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
		worker_task_unref(task);
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


	struct request_ctx *ctx = request_create(worker, NULL, NULL, worker->next_request_uid);
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
		ctx->task = NULL;
		qr_task_unref(task);
		request_free(ctx);
		return NULL;
	}

	worker->next_request_uid += 1;
	if (worker->next_request_uid == 0) {
		worker->next_request_uid = UINT16_MAX + 1;
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

uint16_t worker_task_pkt_get_msgid(struct qr_task *task)
{
	knot_pkt_t *pktbuf = worker_task_get_pktbuf(task);
	uint16_t msg_id = knot_wire_get_id(pktbuf->wire);
	return msg_id;
}

void worker_task_pkt_set_msgid(struct qr_task *task, uint16_t msgid)
{
	knot_pkt_t *pktbuf = worker_task_get_pktbuf(task);
	knot_wire_set_id(pktbuf->wire, msgid);
	struct kr_query *q = task_get_last_pending_query(task);
	q->id = msgid;
}

uint64_t worker_task_creation_time(struct qr_task *task)
{
	return task->creation_time;
}

void worker_task_subreq_finalize(struct qr_task *task)
{
	subreq_finalize(task, NULL, NULL);
}

bool worker_task_finished(struct qr_task *task)
{
	return task->finished;
}
/** Reserve worker buffers */
static int worker_reserve(struct worker_ctx *worker, size_t ring_maxlen)
{
	array_init(worker->pool_mp);
	if (array_reserve(worker->pool_mp, ring_maxlen)) {
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

static inline void reclaim_mp_freelist(mp_freelist_t *list)
{
	for (unsigned i = 0; i < list->len; ++i) {
		struct mempool *e = list->at[i];
		kr_asan_unpoison(e, sizeof(*e));
		mp_delete(e);
	}
	array_clear(*list);
}

void worker_reclaim(struct worker_ctx *worker)
{
	reclaim_mp_freelist(&worker->pool_mp);
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
	worker->next_request_uid = UINT16_MAX + 1;
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
