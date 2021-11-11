/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "kresconfig.h"
#include "daemon/worker.h"

#include <uv.h>
#include <lua.h>
#include <lauxlib.h>
#include <libknot/packet/pkt.h>
#include <libknot/descriptor.h>
#include <contrib/cleanup.h>
#include <contrib/ucw/lib.h>
#include <contrib/ucw/mempool.h>
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
#include <malloc.h>
#endif
#include <sys/types.h>
#include <unistd.h>
#include <gnutls/gnutls.h>

#if ENABLE_XDP
	#include <libknot/xdp/xdp.h>
#endif

#include "daemon/bindings/api.h"
#include "daemon/engine.h"
#include "daemon/io.h"
#include "daemon/session.h"
#include "daemon/tls.h"
#include "daemon/http.h"
#include "daemon/udp_queue.h"
#include "daemon/zimport.h"
#include "lib/layer.h"
#include "lib/utils.h"


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

#define VERBOSE_MSG(qry, ...) kr_log_q(qry, WORKER, __VA_ARGS__)

/** Client request state. */
struct request_ctx
{
	struct kr_request req;

	struct worker_ctx *worker;
	struct qr_task *task;
	struct {
		/** NULL if the request didn't come over network. */
		struct session *session;
		/** Requestor's address; separate because of UDP session "sharing". */
		union kr_sockaddr addr;
		/** Local address.  For AF_XDP we couldn't use session's,
		 * as the address might be different every time. */
		union kr_sockaddr dst_addr;
		/** MAC addresses - ours [0] and router's [1], in case of AF_XDP socket. */
		uint8_t eth_addrs[2][6];
	} source;
};

/** Query resolution task. */
struct qr_task
{
	struct request_ctx *ctx;
	knot_pkt_t *pktbuf;
	qr_tasklist_t waiting;
	struct session *pending[MAX_PENDING];
	uint16_t pending_count;
	uint16_t timeouts;
	uint16_t iter_count;
	uint32_t refs;
	bool finished : 1;
	bool leading  : 1;
	uint64_t creation_time;
	uint64_t send_time;
	uint64_t recv_time;
	struct kr_transport *transport;
};


/* Convenience macros */
#define qr_task_ref(task) \
	do { ++(task)->refs; } while(0)
#define qr_task_unref(task) \
	do { \
		if (task) \
			kr_require((task)->refs > 0); \
		if ((task) && --(task)->refs == 0) \
			qr_task_free((task)); \
	} while (0)

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
			const struct sockaddr *addr, knot_pkt_t *pkt);
static int qr_task_finalize(struct qr_task *task, int state);
static void qr_task_complete(struct qr_task *task);
struct session* worker_find_tcp_connected(struct worker_ctx *worker,
						 const struct sockaddr *addr);
static int worker_add_tcp_waiting(struct worker_ctx *worker,
				  const struct sockaddr *addr,
				  struct session *session);
struct session* worker_find_tcp_waiting(struct worker_ctx *worker,
					       const struct sockaddr *addr);
static void on_tcp_connect_timeout(uv_timer_t *timer);
static void on_udp_timeout(uv_timer_t *timer);
static void subreq_finalize(struct qr_task *task, const struct sockaddr *packet_source, knot_pkt_t *pkt);


struct worker_ctx the_worker_value; /**< Static allocation is suitable for the singleton. */
struct worker_ctx *the_worker = NULL;

/*! @internal Create a UDP/TCP handle for an outgoing AF_INET* connection.
 *  socktype is SOCK_* */
static uv_handle_t *ioreq_spawn(struct worker_ctx *worker,
				int socktype, sa_family_t family, bool has_tls,
				bool has_http)
{
	bool precond = (socktype == SOCK_DGRAM || socktype == SOCK_STREAM)
			&& (family == AF_INET  || family == AF_INET6);
	if (kr_fails_assert(precond)) {
		kr_log_debug(WORKER, "ioreq_spawn: pre-condition failed\n");
		return NULL;
	}

	/* Create connection for iterative query */
	uv_handle_t *handle = malloc(socktype == SOCK_DGRAM
					? sizeof(uv_udp_t) : sizeof(uv_tcp_t));
	if (!handle) {
		return NULL;
	}
	int ret = io_create(worker->loop, handle, socktype, family, has_tls, has_http);
	if (ret) {
		if (ret == UV_EMFILE) {
			worker->too_many_open = true;
			worker->rconcurrent_highwatermark = worker->stats.rconcurrent;
		}
		free(handle);
		return NULL;
	}

	/* Bind to outgoing address, according to IP v4/v6. */
	union kr_sockaddr *addr;
	if (family == AF_INET) {
		addr = (union kr_sockaddr *)&worker->out_addr4;
	} else {
		addr = (union kr_sockaddr *)&worker->out_addr6;
	}
	if (addr->ip.sa_family != AF_UNSPEC) {
		if (kr_fails_assert(addr->ip.sa_family == family)) {
			io_free(handle);
			return NULL;
		}
		if (socktype == SOCK_DGRAM) {
			uv_udp_t *udp = (uv_udp_t *)handle;
			ret = uv_udp_bind(udp, &addr->ip, 0);
		} else if (socktype == SOCK_STREAM){
			uv_tcp_t *tcp = (uv_tcp_t *)handle;
			ret = uv_tcp_bind(tcp, &addr->ip, 0);
		}
	}

	if (ret != 0) {
		io_free(handle);
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
	void *chunk_off = (uint8_t *)chunk - chunk->size;
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
	kr_require(pkt);
	return kr_rrkey(dst, knot_pkt_qclass(pkt), knot_pkt_qname(pkt),
			knot_pkt_qtype(pkt), knot_pkt_qtype(pkt));
}

#if ENABLE_XDP
static uint8_t *alloc_wire_cb(struct kr_request *req, uint16_t *maxlen)
{
	if (kr_fails_assert(maxlen))
		return NULL;
	struct request_ctx *ctx = (struct request_ctx *)req;
	/* We know it's an AF_XDP socket; otherwise this CB isn't assigned. */
	uv_handle_t *handle = session_get_handle(ctx->source.session);
	if (kr_fails_assert(handle->type == UV_POLL))
		return NULL;
	xdp_handle_data_t *xhd = handle->data;
	knot_xdp_msg_t out;
	bool ipv6 = ctx->source.addr.ip.sa_family == AF_INET6;
	int ret = knot_xdp_send_alloc(xhd->socket,
			#if KNOT_VERSION_HEX >= 0x030100
					ipv6 ? KNOT_XDP_MSG_IPV6 : 0, &out);
			#else
					ipv6, &out, NULL);
			#endif
	if (ret != KNOT_EOK) {
		kr_assert(ret == KNOT_ENOMEM);
		*maxlen = 0;
		return NULL;
	}
	*maxlen = MIN(*maxlen, out.payload.iov_len);
	/* It's most convenient to fill the MAC addresses at this point. */
	memcpy(out.eth_from, &ctx->source.eth_addrs[0], 6);
	memcpy(out.eth_to,   &ctx->source.eth_addrs[1], 6);
	return out.payload.iov_base;
}
static void free_wire(const struct request_ctx *ctx)
{
	if (kr_fails_assert(ctx->req.alloc_wire_cb == alloc_wire_cb))
		return;
	knot_pkt_t *ans = ctx->req.answer;
	if (unlikely(ans == NULL)) /* dropped */
		return;
	if (likely(ans->wire == NULL)) /* sent most likely */
		return;
	/* We know it's an AF_XDP socket; otherwise alloc_wire_cb isn't assigned. */
	uv_handle_t *handle = session_get_handle(ctx->source.session);
	if (kr_fails_assert(handle->type == UV_POLL))
		return;
	xdp_handle_data_t *xhd = handle->data;
	/* Freeing is done by sending an empty packet (the API won't really send it). */
	knot_xdp_msg_t out;
	out.payload.iov_base = ans->wire;
	out.payload.iov_len = 0;
	uint32_t sent;
	int ret = knot_xdp_send(xhd->socket, &out, 1, &sent);
	kr_assert(ret == KNOT_EOK && sent == 0);
	kr_log_debug(XDP, "freed unsent buffer, ret = %d\n", ret);
}
#endif
/* Helper functions for transport selection */
static inline bool is_tls_capable(struct sockaddr *address) {
	tls_client_param_t *tls_entry = tls_client_param_get(the_worker->engine->net.tls_client_params, address);
	return tls_entry;
}

static inline bool is_tcp_connected(struct sockaddr *address) {
	return worker_find_tcp_connected(the_worker, address);
}

static inline bool is_tcp_waiting(struct sockaddr *address) {
	return worker_find_tcp_waiting(the_worker, address);
}

/** Create and initialize a request_ctx (on a fresh mempool).
 *
 * session and addr point to the source of the request, and they are NULL
 * in case the request didn't come from network.
 */
static struct request_ctx *request_create(struct worker_ctx *worker,
					  struct session *session,
					  const struct sockaddr *addr,
					  const struct sockaddr *dst_addr,
					  const uint8_t *eth_from,
					  const uint8_t *eth_to,
					  uint32_t uid)
{
	knot_mm_t pool = {
		.ctx = pool_borrow(worker),
		.alloc = (knot_mm_alloc_t) mp_alloc
	};

	/* Create request context */
	struct request_ctx *ctx = mm_calloc(&pool, 1, sizeof(*ctx));
	if (!ctx) {
		pool_release(worker, pool.ctx);
		return NULL;
	}

	/* TODO Relocate pool to struct request */
	ctx->worker = worker;
	if (session && kr_fails_assert(session_flags(session)->outgoing == false)) {
		pool_release(worker, pool.ctx);
		return NULL;
	}
	ctx->source.session = session;
	if (kr_fails_assert(!!eth_to == !!eth_from)) {
		pool_release(worker, pool.ctx);
		return NULL;
	}
	const bool is_xdp = eth_to != NULL;
	if (is_xdp) {
	#if ENABLE_XDP
		if (kr_fails_assert(session)) {
			pool_release(worker, pool.ctx);
			return NULL;
		}
		memcpy(&ctx->source.eth_addrs[0], eth_to,   sizeof(ctx->source.eth_addrs[0]));
		memcpy(&ctx->source.eth_addrs[1], eth_from, sizeof(ctx->source.eth_addrs[1]));
		ctx->req.alloc_wire_cb = alloc_wire_cb;
	#else
		kr_assert(!EINVAL);
		pool_release(worker, pool.ctx);
		return NULL;
	#endif
	}

	struct kr_request *req = &ctx->req;
	req->pool = pool;
	req->vars_ref = LUA_NOREF;
	req->uid = uid;
	req->qsource.flags.xdp = is_xdp;
	kr_request_set_extended_error(req, KNOT_EDNS_EDE_NONE, NULL);
	array_init(req->qsource.headers);
	if (session) {
		req->qsource.flags.tcp = session_get_handle(session)->type == UV_TCP;
		req->qsource.flags.tls = session_flags(session)->has_tls;
		req->qsource.flags.http = session_flags(session)->has_http;
		req->qsource.stream_id = -1;
#if ENABLE_DOH2
		if (req->qsource.flags.http) {
			struct http_ctx *http_ctx = session_http_get_server_ctx(session);
			struct http_stream stream = queue_head(http_ctx->streams);
			req->qsource.stream_id = stream.id;
			if (stream.headers) {
				req->qsource.headers = *stream.headers;
				free(stream.headers);
				stream.headers = NULL;
			}
		}
#endif
		/* We need to store a copy of peer address. */
		memcpy(&ctx->source.addr.ip, addr, kr_sockaddr_len(addr));
		req->qsource.addr = &ctx->source.addr.ip;
		if (!dst_addr) /* We wouldn't have to copy in this case, but for consistency. */
			dst_addr = session_get_sockname(session);
		memcpy(&ctx->source.dst_addr.ip, dst_addr, kr_sockaddr_len(dst_addr));
		req->qsource.dst_addr = &ctx->source.dst_addr.ip;
	}

	req->selection_context.is_tls_capable = is_tls_capable;
	req->selection_context.is_tcp_connected = is_tcp_connected;
	req->selection_context.is_tcp_waiting = is_tcp_waiting;
	array_init(req->selection_context.forwarding_targets);
	array_reserve_mm(req->selection_context.forwarding_targets, 1, kr_memreserve, &req->pool);

	worker->stats.rconcurrent += 1;

	return ctx;
}

/** More initialization, related to the particular incoming query/packet. */
static int request_start(struct request_ctx *ctx, knot_pkt_t *query)
{
	if (kr_fails_assert(query && ctx))
		return kr_error(EINVAL);

	struct kr_request *req = &ctx->req;
	req->qsource.size = query->size;
	if (knot_pkt_has_tsig(query)) {
		req->qsource.size += query->tsig_wire.len;
	}

	knot_pkt_t *pkt = knot_pkt_new(NULL, req->qsource.size, &req->pool);
	if (!pkt) {
		return kr_error(ENOMEM);
	}

	int ret = knot_pkt_copy(pkt, query);
	if (ret != KNOT_EOK && ret != KNOT_ETRAIL) {
		return kr_error(ENOMEM);
	}
	req->qsource.packet = pkt;

	/* Start resolution */
	struct worker_ctx *worker = ctx->worker;
	struct engine *engine = worker->engine;
	kr_resolve_begin(req, &engine->resolver);
	worker->stats.queries += 1;
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
	/* Free HTTP/2 headers for DoH requests. */
	for(int i = 0; i < ctx->req.qsource.headers.len; i++) {
		free(ctx->req.qsource.headers.at[i].name);
		free(ctx->req.qsource.headers.at[i].value);
	}
	array_clear(ctx->req.qsource.headers);

	/* Make sure to free XDP buffer in case it wasn't sent. */
	if (ctx->req.alloc_wire_cb) {
	#if ENABLE_XDP
		free_wire(ctx);
	#else
		kr_assert(!EINVAL);
	#endif
	}
	/* Return mempool to ring or free it if it's full */
	pool_release(worker, ctx->req.pool.ctx);
	/* @note The 'task' is invalidated from now on. */
	worker->stats.rconcurrent -= 1;
}

static struct qr_task *qr_task_create(struct request_ctx *ctx)
{
	/* Choose (initial) pktbuf size.  As it is now, pktbuf can be used
	 * for UDP answers from upstream *and* from cache
	 * and for sending queries upstream */
	uint16_t pktbuf_max = KR_EDNS_PAYLOAD;
	const knot_rrset_t *opt_our = ctx->worker->engine->resolver.upstream_opt_rr;
	if (opt_our) {
		pktbuf_max = MAX(pktbuf_max, knot_edns_get_payload(opt_our));
	}

	/* Create resolution task */
	struct qr_task *task = mm_calloc(&ctx->req.pool, 1, sizeof(*task));
	if (!task) {
		return NULL;
	}

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
	kr_assert(ctx->task == NULL);
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

	if (kr_fails_assert(ctx))
		return;

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
	if (kr_fails_assert(!session_flags(session)->outgoing && session_get_handle(session)->type == UV_TCP))
		return kr_error(EINVAL);

	session_tasklist_add(session, task);

	struct request_ctx *ctx = task->ctx;
	if (kr_fails_assert(ctx && (ctx->source.session == NULL || ctx->source.session == session)))
		return kr_error(EINVAL);
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
	kr_require(task->waiting.len == 0);
	kr_require(task->leading == false);

	struct session *s = ctx->source.session;
	if (s) {
		kr_require(!session_flags(s)->outgoing && session_waitinglist_is_empty(s));
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
int qr_task_on_send(struct qr_task *task, const uv_handle_t *handle, int status)
{
	if (task->finished) {
		kr_require(task->leading == false);
		qr_task_complete(task);
	}

	if (!handle || kr_fails_assert(handle->data))
		return status;
	struct session* s = handle->data;

	if (handle->type == UV_UDP && session_flags(s)->outgoing) {
		// This should ensure that we are only dealing with our question to upstream
		if (kr_fails_assert(!knot_wire_get_qr(task->pktbuf->wire)))
			return status;
		// start the timer
		struct kr_query *qry = array_tail(task->ctx->req.rplan.pending);
		if (kr_fails_assert(qry && task->transport))
			return status;
		size_t timeout = task->transport->timeout;
		int ret = session_timer_start(s, on_udp_timeout, timeout, 0);
		/* Start next step with timeout, fatal if can't start a timer. */
		if (ret != 0) {
			subreq_finalize(task, &task->transport->address.ip, task->pktbuf);
			qr_task_finalize(task, KR_STATE_FAIL);
		}
	}

	if (handle->type == UV_TCP) {
		if (status != 0) { // session probably not usable anymore; typically: ECONNRESET
			const struct kr_request *req = &task->ctx->req;
			if (kr_log_is_debug(WORKER, req)) {
				const char *peer_str = NULL;
				if (!session_flags(s)->outgoing) {
					peer_str = "hidden"; // avoid logging downstream IPs
				} else if (task->transport) {
					peer_str = kr_straddr(&task->transport->address.ip);
				}
				if (!peer_str)
					peer_str = "unknown"; // probably shouldn't happen
				kr_log_req(req, 0, 0, WORKER,
						"=> disconnected from '%s': %s\n",
						peer_str, uv_strerror(status));
			}
			worker_end_tcp(s);
			return status;
		}

		if (session_flags(s)->outgoing || session_flags(s)->closing)
			return status;

		struct worker_ctx *worker = task->ctx->worker;
		if (session_flags(s)->throttled &&
		    session_tasklist_get_len(s) < worker->tcp_pipeline_max/2) {
			/* Start reading again if the session is throttled and
			 * the number of outgoing requests is below watermark. */
			session_start_read(s);
			session_flags(s)->throttled = false;
		}
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
			const struct sockaddr *addr, knot_pkt_t *pkt)
{
	if (!session)
		return qr_task_on_send(task, NULL, kr_error(EIO));

	int ret = 0;
	struct request_ctx *ctx = task->ctx;

	uv_handle_t *handle = session_get_handle(session);
	if (kr_fails_assert(handle && handle->data == session))
		return qr_task_on_send(task, NULL, kr_error(EINVAL));
	const bool is_stream = handle->type == UV_TCP;
	if (!is_stream && handle->type != UV_UDP) abort();

	if (addr == NULL)
		addr = session_get_peer(session);

	if (pkt == NULL)
		pkt = worker_task_get_pktbuf(task);

	if (session_flags(session)->outgoing && handle->type == UV_TCP) {
		size_t try_limit = session_tasklist_get_len(session) + 1;
		uint16_t msg_id = knot_wire_get_id(pkt->wire);
		size_t try_count = 0;
		while (session_tasklist_find_msgid(session, msg_id) &&
		       try_count <= try_limit) {
			++msg_id;
			++try_count;
		}
		if (try_count > try_limit)
			return kr_error(ENOENT);
		worker_task_pkt_set_msgid(task, msg_id);
	}

	uv_handle_t *ioreq = malloc(is_stream ? sizeof(uv_write_t) : sizeof(uv_udp_send_t));
	if (!ioreq)
		return qr_task_on_send(task, handle, kr_error(ENOMEM));

	/* Pending ioreq on current task */
	qr_task_ref(task);

	struct worker_ctx *worker = ctx->worker;
	/* Note time for upstream RTT */
	task->send_time = kr_now();
	task->recv_time = 0; // task structure is being reused so we have to zero this out here
	/* Send using given protocol */
	if (kr_fails_assert(!session_flags(session)->closing))
		return qr_task_on_send(task, NULL, kr_error(EIO));
	if (session_flags(session)->has_http) {
#if ENABLE_DOH2
		uv_write_t *write_req = (uv_write_t *)ioreq;
		write_req->data = task;
		ret = http_write(write_req, handle, pkt, ctx->req.qsource.stream_id, &on_write);
#else
		ret = kr_error(ENOPROTOOPT);
#endif
	} else if (session_flags(session)->has_tls) {
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
		/* We need to write message length in native byte order,
		 * but we don't have a convenient place to store those bytes.
		 * The problem is that all memory referenced from buf[] MUST retain
		 * its contents at least until on_write() is called, and I currently
		 * can't see any convenient place outside the `pkt` structure.
		 * So we use directly the *individual* bytes in pkt->size.
		 * The call to htonl() and the condition will probably be inlinable. */
		int lsbi, slsbi; /* (second) least significant byte index */
		if (htonl(1) == 1) { /* big endian */
			lsbi  = sizeof(pkt->size) - 1;
			slsbi = sizeof(pkt->size) - 2;
		} else {
			lsbi  = 0;
			slsbi = 1;
		}
		uv_buf_t buf[3] = {
			{ (char *)&pkt->size + slsbi, 1 },
			{ (char *)&pkt->size + lsbi,  1 },
			{ (char *)pkt->wire, pkt->size },
		};
		write_req->data = task;
		ret = uv_write(write_req, (uv_stream_t *)handle, buf, 3, &on_write);
	} else {
		kr_assert(false);
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

		if (session_flags(session)->has_http)
			worker->stats.err_http += 1;
		else if (session_flags(session)->has_tls)
			worker->stats.err_tls += 1;
		else if (handle->type == UV_UDP)
			worker->stats.err_udp += 1;
		else
			worker->stats.err_tcp += 1;
	}

	/* Update outgoing query statistics */
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

static struct kr_query *task_get_last_pending_query(struct qr_task *task)
{
	if (!task || task->ctx->req.rplan.pending.len == 0) {
		return NULL;
	}

	return array_tail(task->ctx->req.rplan.pending);
}

static int session_tls_hs_cb(struct session *session, int status)
{
	if (kr_fails_assert(session_flags(session)->outgoing))
		return kr_error(EINVAL);
	struct sockaddr *peer = session_get_peer(session);
	int deletion_res = worker_del_tcp_waiting(the_worker, peer);
	int ret = kr_ok();

	if (status) {
		struct qr_task *task = session_waitinglist_get(session);
		if (task) {
			// TLS handshake failed, report it to server selection
			struct kr_query *qry = array_tail(task->ctx->req.rplan.pending);
			qry->server_selection.error(qry, task->transport, KR_SELECTION_TLS_HANDSHAKE_FAILED);
		}
#ifndef NDEBUG
		else {
			/* Task isn't in the list of tasks
			 * waiting for connection to upstream.
			 * So that it MUST be unsuccessful rehandshake.
			 * Check it. */
			kr_require(deletion_res != 0);
			const char *key = tcpsess_key(peer);
			kr_require(key);
			kr_require(map_contains(&the_worker->tcp_connected, key) != 0);
		}
#endif
		return ret;
	}

	/* handshake was completed successfully */
	struct tls_client_ctx *tls_client_ctx = session_tls_get_client_ctx(session);
	tls_client_param_t *tls_params = tls_client_ctx->params;
	gnutls_session_t tls_session = tls_client_ctx->c.tls_session;
	if (gnutls_session_is_resumed(tls_session) != 0) {
		kr_log_debug(TLSCLIENT, "TLS session has resumed\n");
	} else {
		kr_log_debug(TLSCLIENT, "TLS session has not resumed\n");
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

	struct session *s = worker_find_tcp_connected(the_worker, peer);
	ret = kr_ok();
	if (deletion_res == kr_ok()) {
		/* peer was in the waiting list, add to the connected list. */
		if (s) {
			/* Something went wrong,
			 * peer already is in the connected list. */
			ret = kr_error(EINVAL);
		} else {
			ret = worker_add_tcp_connected(the_worker, peer, session);
		}
	} else {
		/* peer wasn't in the waiting list.
		 * It can be
		 * 1) either successful rehandshake; in this case peer
		 *    must be already in the connected list.
		 * 2) or successful handshake with session, which was timed out
		 *    by on_tcp_connect_timeout(); after successful tcp connection;
		 *    in this case peer isn't in the connected list.
		 **/
		if (!s || s != session) {
			ret = kr_error(EINVAL);
		}
	}
	if (ret == kr_ok()) {
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
		 * Either addition to the list of connected sessions
		 * or write to upstream failed. */
		worker_del_tcp_connected(the_worker, peer);
		session_waitinglist_finalize(session, KR_STATE_FAIL);
		session_tasklist_finalize(session, KR_STATE_FAIL);
		session_close(session);
	} else {
		session_timer_stop(session);
		session_timer_start(session, tcp_timeout_trigger,
				    MAX_TCP_INACTIVITY, MAX_TCP_INACTIVITY);
	}
	return kr_ok();
}

static int send_waiting(struct session *session)
{
	int ret = 0;
	while (!session_waitinglist_is_empty(session)) {
		struct qr_task *t = session_waitinglist_get(session);
		ret = qr_task_send(t, session, NULL, NULL);
		if (ret != 0) {
			struct worker_ctx *worker = t->ctx->worker;
			struct sockaddr *peer = session_get_peer(session);
			session_waitinglist_finalize(session, KR_STATE_FAIL);
			session_tasklist_finalize(session, KR_STATE_FAIL);
			worker_del_tcp_connected(worker, peer);
			session_close(session);
			break;
		}
		session_waitinglist_pop(session, true);
	}
	return ret;
}

static void on_connect(uv_connect_t *req, int status)
{
	struct worker_ctx *worker = the_worker;
	kr_require(worker);
	uv_stream_t *handle = req->handle;
	struct session *session = handle->data;
	struct sockaddr *peer = session_get_peer(session);
	free(req);

	if (kr_fails_assert(session_flags(session)->outgoing))
		return;

	if (session_flags(session)->closing) {
		worker_del_tcp_waiting(worker, peer);
		kr_assert(session_is_empty(session));
		return;
	}

	const bool log_debug = kr_log_is_debug(WORKER, NULL);

	/* Check if the connection is in the waiting list.
	 * If no, most likely this is timed out connection
	 * which was removed from waiting list by
	 * on_tcp_connect_timeout() callback. */
	struct session *s = worker_find_tcp_waiting(worker, peer);
	if (!s || s != session) {
		/* session isn't on the waiting list.
		 * it's timed out session. */
		if (log_debug) {
			const char *peer_str = kr_straddr(peer);
			kr_log_debug(WORKER, "=> connected to '%s', but session "
					"is already timed out, close\n",
					peer_str ? peer_str : "");
		}
		kr_assert(session_tasklist_is_empty(session));
		session_waitinglist_retry(session, false);
		session_close(session);
		return;
	}

	s = worker_find_tcp_connected(worker, peer);
	if (s) {
		/* session already in the connected list.
		 * Something went wrong, it can be due to races when kresd has tried
		 * to reconnect to upstream after unsuccessful attempt. */
		if (log_debug) {
			const char *peer_str = kr_straddr(peer);
			kr_log_debug(WORKER, "=> connected to '%s', but peer "
					"is already connected, close\n",
					peer_str ? peer_str : "");
		}
		kr_assert(session_tasklist_is_empty(session));
		session_waitinglist_retry(session, false);
		session_close(session);
		return;
	}

	if (status != 0) {
		if (log_debug) {
			const char *peer_str = kr_straddr(peer);
			kr_log_debug(WORKER, "=> connection to '%s' failed (%s), flagged as 'bad'\n",
					peer_str ? peer_str : "", uv_strerror(status));
		}
		worker_del_tcp_waiting(worker, peer);
		struct qr_task *task = session_waitinglist_get(session);
		if (task && status != UV_ETIMEDOUT) {
			/* Penalize upstream.
			* In case of UV_ETIMEDOUT upstream has been
			* already penalized in on_tcp_connect_timeout() */
			struct kr_query *qry = array_tail(task->ctx->req.rplan.pending);
			qry->server_selection.error(qry, task->transport, KR_SELECTION_TCP_CONNECT_FAILED);
		}
		kr_assert(session_tasklist_is_empty(session));
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
			kr_assert(session_tasklist_is_empty(session));
			session_close(session);
			return;
		}
	}

	if (log_debug) {
		const char *peer_str = kr_straddr(peer);
		kr_log_debug(WORKER, "=> connected to '%s'\n", peer_str ? peer_str : "");
	}

	session_flags(session)->connected = true;
	session_start_read(session);

	int ret = kr_ok();
	if (session_flags(session)->has_tls) {
		struct tls_client_ctx *tls_ctx = session_tls_get_client_ctx(session);
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
	struct worker_ctx *worker = the_worker;
	kr_require(worker);

	kr_assert(session_tasklist_is_empty(session));

	struct sockaddr *peer = session_get_peer(session);
	worker_del_tcp_waiting(worker, peer);

	struct qr_task *task = session_waitinglist_get(session);
	if (!task) {
		/* Normally shouldn't happen. */
		const char *peer_str = kr_straddr(peer);
		VERBOSE_MSG(NULL, "=> connection to '%s' failed (internal timeout), empty waitinglist\n",
			    peer_str ? peer_str : "");
		return;
	}

	struct kr_query *qry = task_get_last_pending_query(task);
	if (kr_log_is_debug_qry(WORKER, qry)) {
		const char *peer_str = kr_straddr(peer);
		VERBOSE_MSG(qry, "=> connection to '%s' failed (internal timeout)\n",
			    peer_str ? peer_str : "");
	}

	qry->server_selection.error(qry, task->transport, KR_SELECTION_TCP_CONNECT_TIMEOUT);

	worker->stats.timeout += session_waitinglist_get_len(session);
	session_waitinglist_retry(session, true);
	kr_assert(session_tasklist_is_empty(session));
	/* uv_cancel() doesn't support uv_connect_t request,
	 * so that we can't cancel it.
	 * There still exists possibility of successful connection
	 * for this request.
	 * So connection callback (on_connect()) must check
	 * if connection is in the list of waiting connection.
	 * If no, most likely this is timed out connection even if
	 * it was successful. */
}

/* This is called when I/O timeouts */
static void on_udp_timeout(uv_timer_t *timer)
{
	struct session *session = timer->data;
	kr_assert(session_get_handle(session)->data == session);
	kr_assert(session_tasklist_get_len(session) == 1);
	kr_assert(session_waitinglist_is_empty(session));

	uv_timer_stop(timer);

	struct qr_task *task = session_tasklist_get_first(session);
	if (!task)
		return;
	struct worker_ctx *worker = task->ctx->worker;

	if (task->leading && task->pending_count > 0) {
		struct kr_query *qry = array_tail(task->ctx->req.rplan.pending);
		qry->server_selection.error(qry, task->transport, KR_SELECTION_QUERY_TIMEOUT);
	}

	task->timeouts += 1;
	worker->stats.timeout += 1;
	qr_task_step(task, NULL, NULL);
}

static uv_handle_t *transmit(struct qr_task *task)
{
	uv_handle_t *ret = NULL;

	if (task) {
		struct kr_transport* transport = task->transport;

		struct sockaddr_in6 *choice = (struct sockaddr_in6 *)&transport->address;

		if (!choice) {
			return ret;
		}
		if (task->pending_count >= MAX_PENDING) {
			return ret;
		}
		/* Checkout answer before sending it */
		struct request_ctx *ctx = task->ctx;
		if (kr_resolve_checkout(&ctx->req, NULL, transport, task->pktbuf) != 0) {
			return ret;
		}
		ret = ioreq_spawn(ctx->worker, SOCK_DGRAM, choice->sin6_family, false, false);
		if (!ret) {
			return ret;
		}
		struct sockaddr *addr = (struct sockaddr *)choice;
		struct session *session = ret->data;
		struct sockaddr *peer = session_get_peer(session);
		kr_assert(peer->sa_family == AF_UNSPEC && session_flags(session)->outgoing);
		memcpy(peer, addr, kr_sockaddr_len(addr));
		if (qr_task_send(task, session, (struct sockaddr *)choice,
				 task->pktbuf) != 0) {
			session_close(session);
			ret = NULL;
		} else {
			task->pending[task->pending_count] = session;
			task->pending_count += 1;
			session_start_read(session); /* Start reading answer */
		}
	}
	return ret;
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
		kr_assert(ret == KNOT_EOK && val_deleted == task);
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

			// Note that this transport may not be present in `leader_qry`'s server selection
			follower->transport = task->transport;
			if(follower->transport) {
				follower->transport->deduplicated = true;
			}
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
	if (kr_fails_assert(task))
		return;
	char key[SUBREQ_KEY_LEN];
	const int klen = subreq_key(key, task->pktbuf);
	if (klen < 0)
		return;
	struct qr_task **tvp = (struct qr_task **)
		trie_get_ins(task->ctx->worker->subreq_out, key, klen);
	if (unlikely(!tvp))
		return; /*ENOMEM*/
	if (kr_fails_assert(*tvp == NULL))
		return;
	*tvp = task;
	task->leading = true;
}

static bool subreq_enqueue(struct qr_task *task)
{
	if (kr_fails_assert(task))
		return false;
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

#if ENABLE_XDP
static void xdp_tx_waker(uv_idle_t *handle)
{
	int ret = knot_xdp_send_finish(handle->data);
	if (ret != KNOT_EAGAIN && ret != KNOT_EOK)
		kr_log_error(XDP, "check: ret = %d, %s\n", ret, knot_strerror(ret));
	/* Apparently some drivers need many explicit wake-up calls
	 * even if we push no additional packets (in case they accumulated a lot) */
	if (ret != KNOT_EAGAIN)
		uv_idle_stop(handle);
	knot_xdp_send_prepare(handle->data);
	/* LATER(opt.): it _might_ be better for performance to do these two steps
	 * at different points in time */
}
#endif
/** Send an answer packet over XDP. */
static int xdp_push(struct qr_task *task, const uv_handle_t *src_handle)
{
#if ENABLE_XDP
	struct request_ctx *ctx = task->ctx;
	xdp_handle_data_t *xhd = src_handle->data;
	if (kr_fails_assert(xhd && xhd->socket && xhd->session == ctx->source.session))
		return qr_task_on_send(task, src_handle, kr_error(EINVAL));

	knot_xdp_msg_t msg;
	const struct sockaddr *ip_from = &ctx->source.dst_addr.ip;
	const struct sockaddr *ip_to   = &ctx->source.addr.ip;
	memcpy(&msg.ip_from, ip_from, kr_sockaddr_len(ip_from));
	memcpy(&msg.ip_to,   ip_to,   kr_sockaddr_len(ip_to));
	msg.payload.iov_base = ctx->req.answer->wire;
	msg.payload.iov_len  = ctx->req.answer->size;

	uint32_t sent;
	int ret = knot_xdp_send(xhd->socket, &msg, 1, &sent);
	ctx->req.answer->wire = NULL; /* it's been freed */

	uv_idle_start(&xhd->tx_waker, xdp_tx_waker);
	kr_log_debug(XDP, "pushed a packet, ret = %d\n", ret);

	return qr_task_on_send(task, src_handle, ret);
#else
	kr_assert(!EINVAL);
	return kr_error(EINVAL);
#endif
}

static int qr_task_finalize(struct qr_task *task, int state)
{
	kr_require(task && task->leading == false);
	if (task->finished) {
		return kr_ok();
	}
	struct request_ctx *ctx = task->ctx;
	struct session *source_session = ctx->source.session;
	kr_resolve_finish(&ctx->req, state);

	task->finished = true;
	if (source_session == NULL) {
		(void) qr_task_on_send(task, NULL, kr_error(EIO));
		return state == KR_STATE_DONE ? kr_ok() : kr_error(EIO);
	}

	if (unlikely(ctx->req.answer == NULL)) { /* meant to be dropped */
		(void) qr_task_on_send(task, NULL, kr_ok());
		return kr_ok();
	}

	if (session_flags(source_session)->closing ||
	    ctx->source.addr.ip.sa_family == AF_UNSPEC)
		return kr_error(EINVAL);

	/* Reference task as the callback handler can close it */
	qr_task_ref(task);

	/* Send back answer */
	int ret;
	const uv_handle_t *src_handle = session_get_handle(source_session);
	if (kr_fails_assert(src_handle->type == UV_UDP || src_handle->type == UV_TCP
		       || src_handle->type == UV_POLL)) {
		ret = kr_error(EINVAL);
	} else if (src_handle->type == UV_POLL) {
		ret = xdp_push(task, src_handle);
	} else if (src_handle->type == UV_UDP && ENABLE_SENDMMSG) {
		int fd;
		ret = uv_fileno(src_handle, &fd);
		if (ret == 0)
			udp_queue_push(fd, &ctx->req, task);
		else
			kr_assert(false);
	} else {
		ret = qr_task_send(task, source_session, &ctx->source.addr.ip, ctx->req.answer);
	}

	if (ret != kr_ok()) {
		(void) qr_task_on_send(task, NULL, kr_error(EIO));
		/* Since source session is erroneous detach all tasks. */
		while (!session_tasklist_is_empty(source_session)) {
			struct qr_task *t = session_tasklist_del_first(source_session, false);
			struct request_ctx *c = t->ctx;
			kr_assert(c->source.session == source_session);
			c->source.session = NULL;
			/* Don't finalize them as there can be other tasks
			 * waiting for answer to this particular task.
			 * (ie. task->leading is true) */
			worker_task_unref(t);
		}
		session_close(source_session);
	}

	qr_task_unref(task);

	if (ret != kr_ok() || state != KR_STATE_DONE)
		return kr_error(EIO);
	return kr_ok();
}

static int udp_task_step(struct qr_task *task,
			 const struct sockaddr *packet_source, knot_pkt_t *packet)
{
	/* If there is already outgoing query, enqueue to it. */
	if (subreq_enqueue(task)) {
		return kr_ok(); /* Will be notified when outgoing query finishes. */
	}
	/* Start transmitting */
	uv_handle_t *handle = transmit(task);
	if (handle == NULL) {
		subreq_finalize(task, packet_source, packet);
		return qr_task_finalize(task, KR_STATE_FAIL);
	}

	/* Announce and start subrequest.
	 * @note Only UDP can lead I/O as it doesn't touch 'task->pktbuf' for reassembly.
	 */
	subreq_lead(task);

	return kr_ok();
}

static int tcp_task_waiting_connection(struct session *session, struct qr_task *task)
{
	if (kr_fails_assert(session_flags(session)->outgoing && !session_flags(session)->closing))
		return kr_error(EINVAL);
	/* Add task to the end of list of waiting tasks.
	 * It will be notified in on_connect() or qr_task_on_send(). */
	int ret = session_waitinglist_push(session, task);
	if (ret < 0) {
		return kr_error(EINVAL);
	}
	return kr_ok();
}

static int tcp_task_existing_connection(struct session *session, struct qr_task *task)
{
	if (kr_fails_assert(session_flags(session)->outgoing && !session_flags(session)->closing))
		return kr_error(EINVAL);
	struct request_ctx *ctx = task->ctx;
	struct worker_ctx *worker = ctx->worker;

	/* If there are any unsent queries, send it first. */
	int ret = send_waiting(session);
	if (ret != 0) {
		return kr_error(EINVAL);
	}

	/* No unsent queries at that point. */
	if (session_tasklist_get_len(session) >= worker->tcp_pipeline_max) {
		/* Too many outstanding queries, answer with SERVFAIL, */
		return kr_error(EINVAL);
	}

	/* Send query to upstream. */
	ret = qr_task_send(task, session, NULL, NULL);
	if (ret != 0) {
		/* Error, finalize task with SERVFAIL and
		 * close connection to upstream. */
		session_tasklist_finalize(session, KR_STATE_FAIL);
		worker_del_tcp_connected(worker, session_get_peer(session));
		session_close(session);
		return kr_error(EINVAL);
	}

	return kr_ok();
}

static int tcp_task_make_connection(struct qr_task *task, const struct sockaddr *addr)
{
	struct request_ctx *ctx = task->ctx;
	struct worker_ctx *worker = ctx->worker;

	/* Check if there must be TLS */
	struct tls_client_ctx *tls_ctx = NULL;
	struct network *net = &worker->engine->net;
	tls_client_param_t *entry = tls_client_param_get(net->tls_client_params, addr);
	if (entry) {
		/* Address is configured to be used with TLS.
		 * We need to allocate auxiliary data structure. */
		tls_ctx = tls_client_ctx_new(entry, worker);
		if (!tls_ctx) {
			return kr_error(EINVAL);
		}
	}

	uv_connect_t *conn = malloc(sizeof(uv_connect_t));
	if (!conn) {
		tls_client_ctx_free(tls_ctx);
		return kr_error(EINVAL);
	}
	bool has_http = false;
	bool has_tls = (tls_ctx != NULL);
	uv_handle_t *client = ioreq_spawn(worker, SOCK_STREAM, addr->sa_family, has_tls, has_http);
	if (!client) {
		tls_client_ctx_free(tls_ctx);
		free(conn);
		return kr_error(EINVAL);
	}
	struct session *session = client->data;
	if (kr_fails_assert(session_flags(session)->has_tls == has_tls)) {
		tls_client_ctx_free(tls_ctx);
		free(conn);
		return kr_error(EINVAL);
	}
	if (has_tls) {
		tls_client_ctx_set_session(tls_ctx, session);
		session_tls_set_client_ctx(session, tls_ctx);
	}

	/* Add address to the waiting list.
	 * Now it "is waiting to be connected to." */
	int ret = worker_add_tcp_waiting(worker, addr, session);
	if (ret < 0) {
		free(conn);
		session_close(session);
		return kr_error(EINVAL);
	}

	conn->data = session;
	/*  Store peer address for the session. */
	struct sockaddr *peer = session_get_peer(session);
	memcpy(peer, addr, kr_sockaddr_len(addr));

	/*  Start watchdog to catch eventual connection timeout. */
	ret = session_timer_start(session, on_tcp_connect_timeout,
				  KR_CONN_RTT_MAX, 0);
	if (ret != 0) {
		worker_del_tcp_waiting(worker, addr);
		free(conn);
		session_close(session);
		return kr_error(EINVAL);
	}

	struct kr_query *qry = task_get_last_pending_query(task);
	if (kr_log_is_debug_qry(WORKER, qry)) {
		const char *peer_str = kr_straddr(peer);
		VERBOSE_MSG(qry, "=> connecting to: '%s'\n", peer_str ? peer_str : "");
	}

	/*  Start connection process to upstream. */
	ret = uv_tcp_connect(conn, (uv_tcp_t *)client, addr , on_connect);
	if (ret != 0) {
		session_timer_stop(session);
		worker_del_tcp_waiting(worker, addr);
		free(conn);
		session_close(session);
		qry->server_selection.error(qry, task->transport, KR_SELECTION_TCP_CONNECT_FAILED);
		return kr_error(EAGAIN);
	}

	/* Add task to the end of list of waiting tasks.
	 * Will be notified either in on_connect() or in qr_task_on_send(). */
	ret = session_waitinglist_push(session, task);
	if (ret < 0) {
		session_timer_stop(session);
		worker_del_tcp_waiting(worker, addr);
		free(conn);
		session_close(session);
		return kr_error(EINVAL);
	}

	return kr_ok();
}

static int tcp_task_step(struct qr_task *task,
			 const struct sockaddr *packet_source, knot_pkt_t *packet)
{
	if (kr_fails_assert(task->pending_count == 0)) {
		subreq_finalize(task, packet_source, packet);
		return qr_task_finalize(task, KR_STATE_FAIL);
	}

	/* target */
	const struct sockaddr *addr = &task->transport->address.ip;
	if (addr->sa_family == AF_UNSPEC) {
		/* Target isn't defined. Finalize task with SERVFAIL.
		 * Although task->pending_count is zero, there are can be followers,
		 * so we need to call subreq_finalize() to handle them properly. */
		subreq_finalize(task, packet_source, packet);
		return qr_task_finalize(task, KR_STATE_FAIL);
	}
	/* Checkout task before connecting */
	struct request_ctx *ctx = task->ctx;
	if (kr_resolve_checkout(&ctx->req, NULL, task->transport, task->pktbuf) != 0) {
		subreq_finalize(task, packet_source, packet);
		return qr_task_finalize(task, KR_STATE_FAIL);
	}
	int ret;
	struct session* session = NULL;
	if ((session = worker_find_tcp_waiting(ctx->worker, addr)) != NULL) {
		/* Connection is in the list of waiting connections.
		 * It means that connection establishing is coming right now. */
		ret = tcp_task_waiting_connection(session, task);
	} else if ((session = worker_find_tcp_connected(ctx->worker, addr)) != NULL) {
		/* Connection has been already established. */
		ret = tcp_task_existing_connection(session, task);
	} else {
		/* Make connection. */
		ret = tcp_task_make_connection(task, addr);
	}

	if (ret != kr_ok()) {
		subreq_finalize(task, addr, packet);
		if (ret == kr_error(EAGAIN)) {
			ret = qr_task_step(task, addr, NULL);
		} else {
			ret = qr_task_finalize(task, KR_STATE_FAIL);
		}
	}

	return ret;
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
	if ((kr_now() - worker_task_creation_time(task)) >= KR_RESOLVE_TIME_LIMIT) {
		struct kr_request *req = worker_task_request(task);
		if (!kr_fails_assert(req))
			kr_query_inform_timeout(req, req->current_query);
		return qr_task_finalize(task, KR_STATE_FAIL);
	}

	/* Consume input and produce next query */
	struct request_ctx *ctx = task->ctx;
	if (kr_fails_assert(ctx))
		return qr_task_finalize(task, KR_STATE_FAIL);
	struct kr_request *req = &ctx->req;
	struct worker_ctx *worker = ctx->worker;

	if (worker->too_many_open) {
		/* */
		struct kr_rplan *rplan = &req->rplan;
		if (worker->stats.rconcurrent <
			worker->rconcurrent_highwatermark - 10) {
			worker->too_many_open = false;
		} else {
			if (packet && kr_rplan_empty(rplan)) {
				/* new query; TODO - make this detection more obvious */
				kr_resolve_consume(req, &task->transport, packet);
			}
			return qr_task_finalize(task, KR_STATE_FAIL);
		}
	}

	// Report network RTT back to server selection
	if (packet && task->send_time && task->recv_time) {
		struct kr_query *qry = array_tail(req->rplan.pending);
		qry->server_selection.update_rtt(qry, task->transport, task->recv_time - task->send_time);
	}

	int state = kr_resolve_consume(req, &task->transport, packet);

	task->transport = NULL;
	while (state == KR_STATE_PRODUCE) {
		state = kr_resolve_produce(req, &task->transport, task->pktbuf);
		if (unlikely(++task->iter_count > KR_ITER_LIMIT ||
			     task->timeouts >= KR_TIMEOUT_LIMIT)) {

			struct kr_rplan *rplan = &req->rplan;
			struct kr_query *last = kr_rplan_last(rplan);
			if (task->iter_count > KR_ITER_LIMIT) {
				char *msg = "cancelling query due to exceeded iteration count limit";
				VERBOSE_MSG(last, "%s of %d\n", msg, KR_ITER_LIMIT);
				kr_request_set_extended_error(req, KNOT_EDNS_EDE_OTHER, msg);
			}
			if (task->timeouts >= KR_TIMEOUT_LIMIT) {
				char *msg = "cancelling query due to exceeded timeout retries limit";
				VERBOSE_MSG(last, "%s of %d\n", msg, KR_TIMEOUT_LIMIT);
				kr_request_set_extended_error(req, KNOT_EDNS_EDE_NREACH_AUTH, NULL);
			}

			return qr_task_finalize(task, KR_STATE_FAIL);
		}
	}

	/* We're done, no more iterations needed */
	if (state & (KR_STATE_DONE|KR_STATE_FAIL)) {
		return qr_task_finalize(task, state);
	} else if (!task->transport || !task->transport->protocol) {
		return qr_task_step(task, NULL, NULL);
	}

	switch (task->transport->protocol)
	{
	case KR_TRANSPORT_UDP:
		return udp_task_step(task, packet_source, packet);
	case KR_TRANSPORT_TCP: // fall through
	case KR_TRANSPORT_TLS:
		return tcp_task_step(task, packet_source, packet);
	default:
		kr_assert(!EINVAL);
		return kr_error(EINVAL);
	}
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

int worker_submit(struct session *session,
		  const struct sockaddr *peer, const struct sockaddr *dst_addr,
		  const uint8_t *eth_from, const uint8_t *eth_to, knot_pkt_t *pkt)
{
	if (!session || !pkt)
		return kr_error(EINVAL);

	uv_handle_t *handle = session_get_handle(session);
	if (!handle || !handle->loop->data)
		return kr_error(EINVAL);

	int ret = parse_packet(pkt);

	const bool is_query = (knot_wire_get_qr(pkt->wire) == 0);
	const bool is_outgoing = session_flags(session)->outgoing;

	struct http_ctx *http_ctx = NULL;
#if ENABLE_DOH2
	http_ctx = session_http_get_server_ctx(session);
#endif

	if (!is_outgoing && http_ctx && queue_len(http_ctx->streams) <= 0)
		return kr_error(ENOENT);

	/* Ignore badly formed queries. */
	if ((ret != kr_ok() && ret != kr_error(EMSGSIZE)) ||
	    (is_query == is_outgoing)) {
		if (!is_outgoing) {
			the_worker->stats.dropped += 1;
		#if ENABLE_DOH2
			if (http_ctx) {
				struct http_stream stream = queue_head(http_ctx->streams);
				http_free_headers(stream.headers);
				queue_pop(http_ctx->streams);
			}
		#endif
		}
		return kr_error(EILSEQ);
	}

	/* Start new task on listening sockets,
	 * or resume if this is subrequest */
	struct qr_task *task = NULL;
	const struct sockaddr *addr = NULL;
	if (!is_outgoing) { /* request from a client */
		struct request_ctx *ctx =
			request_create(the_worker, session, peer, dst_addr,
					eth_from, eth_to, knot_wire_get_id(pkt->wire));
		if (http_ctx)
			queue_pop(http_ctx->streams);
		if (!ctx)
			return kr_error(ENOMEM);

		ret = request_start(ctx, pkt);
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
	} else { /* response from upstream */
		const uint16_t id = knot_wire_get_id(pkt->wire);
		task = session_tasklist_del_msgid(session, id);
		if (task == NULL) {
			VERBOSE_MSG(NULL, "=> ignoring packet with mismatching ID %d\n",
					(int)id);
			return kr_error(ENOENT);
		}
		if (kr_fails_assert(!session_flags(session)->closing))
			return kr_error(EINVAL);
		addr = peer;
		/* Note receive time for RTT calculation */
		task->recv_time = kr_now();
	}
	if (kr_fails_assert(!uv_is_closing(session_get_handle(session))))
		return kr_error(EINVAL);

	/* Packet was successfully parsed.
	 * Task was created (found). */
	session_touch(session);

	/* Consume input and produce next message */
	return qr_task_step(task, addr, pkt);
}

static int map_add_tcp_session(map_t *map, const struct sockaddr* addr,
			       struct session *session)
{
	if (kr_fails_assert(map && addr))
		return kr_error(EINVAL);
	const char *key = tcpsess_key(addr);
	if (kr_fails_assert(key && map_contains(map, key) == 0))
		return kr_error(EINVAL);
	int ret = map_set(map, key, session);
	return ret ? kr_error(EINVAL) : kr_ok();
}

static int map_del_tcp_session(map_t *map, const struct sockaddr* addr)
{
	if (kr_fails_assert(map && addr))
		return kr_error(EINVAL);
	const char *key = tcpsess_key(addr);
	if (kr_fails_assert(key))
		return kr_error(EINVAL);
	int ret = map_del(map, key);
	return ret ? kr_error(ENOENT) : kr_ok();
}

static struct session* map_find_tcp_session(map_t *map,
					    const struct sockaddr *addr)
{
	if (kr_fails_assert(map && addr))
		return NULL;
	const char *key = tcpsess_key(addr);
	if (kr_fails_assert(key))
		return NULL;
	struct session* ret = map_get(map, key);
	return ret;
}

int worker_add_tcp_connected(struct worker_ctx *worker,
				    const struct sockaddr* addr,
				    struct session *session)
{
	return map_add_tcp_session(&worker->tcp_connected, addr, session);
}

int worker_del_tcp_connected(struct worker_ctx *worker,
				    const struct sockaddr* addr)
{
	return map_del_tcp_session(&worker->tcp_connected, addr);
}

struct session* worker_find_tcp_connected(struct worker_ctx *worker,
						 const struct sockaddr* addr)
{
	return map_find_tcp_session(&worker->tcp_connected, addr);
}

static int worker_add_tcp_waiting(struct worker_ctx *worker,
				  const struct sockaddr* addr,
				  struct session *session)
{
	return map_add_tcp_session(&worker->tcp_waiting, addr, session);
}

int worker_del_tcp_waiting(struct worker_ctx *worker,
			   const struct sockaddr* addr)
{
	return map_del_tcp_session(&worker->tcp_waiting, addr);
}

struct session* worker_find_tcp_waiting(struct worker_ctx *worker,
					       const struct sockaddr* addr)
{
	return map_find_tcp_session(&worker->tcp_waiting, addr);
}

int worker_end_tcp(struct session *session)
{
	if (!session)
		return kr_error(EINVAL);

	session_timer_stop(session);

	struct sockaddr *peer = session_get_peer(session);

	worker_del_tcp_waiting(the_worker, peer);
	worker_del_tcp_connected(the_worker, peer);
	session_flags(session)->connected = false;

	struct tls_client_ctx *tls_client_ctx = session_tls_get_client_ctx(session);
	if (tls_client_ctx) {
		/* Avoid gnutls_bye() call */
		tls_set_hs_state(&tls_client_ctx->c, TLS_HS_NOT_STARTED);
	}

	struct tls_ctx *tls_ctx = session_tls_get_server_ctx(session);
	if (tls_ctx) {
		/* Avoid gnutls_bye() call */
		tls_set_hs_state(&tls_ctx->c, TLS_HS_NOT_STARTED);
	}

	while (!session_waitinglist_is_empty(session)) {
		struct qr_task *task = session_waitinglist_pop(session, false);
		kr_assert(task->refs > 1);
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
			kr_assert(task->ctx->source.session == session);
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
			kr_assert(task->ctx->source.session == session);
			task->ctx->source.session = NULL;
		}
		worker_task_unref(task);
	}
	session_close(session);
	return kr_ok();
}

knot_pkt_t *worker_resolve_mk_pkt_dname(knot_dname_t *qname, uint16_t qtype, uint16_t qclass,
				   const struct kr_qflags *options)
{
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_EDNS_MAX_UDP_PAYLOAD, NULL);
	if (!pkt)
		return NULL;
	knot_pkt_put_question(pkt, qname, qclass, qtype);
	knot_wire_set_rd(pkt->wire);
	knot_wire_set_ad(pkt->wire);

	/* Add OPT RR, including wire format so modules can see both representations.
	 * knot_pkt_put() copies the outside; we need to duplicate the inside manually. */
	knot_rrset_t *opt = knot_rrset_copy(the_worker->engine->resolver.downstream_opt_rr, NULL);
	if (!opt) {
		knot_pkt_free(pkt);
		return NULL;
	}
	if (options->DNSSEC_WANT) {
		knot_edns_set_do(opt);
	}
	knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	int ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, opt, KNOT_PF_FREE);
	if (ret == KNOT_EOK) {
		free(opt); /* inside is owned by pkt now */
	} else {
		knot_rrset_free(opt, NULL);
		knot_pkt_free(pkt);
		return NULL;
	}

	if (options->DNSSEC_CD) {
		knot_wire_set_cd(pkt->wire);
	}

	return pkt;
}

knot_pkt_t *worker_resolve_mk_pkt(const char *qname_str, uint16_t qtype, uint16_t qclass,
				   const struct kr_qflags *options)
{
	uint8_t qname[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(qname, qname_str, sizeof(qname)))
		return NULL;
	return worker_resolve_mk_pkt_dname(qname, qtype, qclass, options);
}

struct qr_task *worker_resolve_start(knot_pkt_t *query, struct kr_qflags options)
{
	struct worker_ctx *worker = the_worker;
	if (kr_fails_assert(worker && query))
		return NULL;


	struct request_ctx *ctx = request_create(worker, NULL, NULL, NULL, NULL, NULL,
						 worker->next_request_uid);
	if (!ctx)
		return NULL;

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
	if (worker->next_request_uid == 0)
		worker->next_request_uid = UINT16_MAX + 1;

	/* Set options late, as qr_task_start() -> kr_resolve_begin() rewrite it. */
	kr_qflags_set(&task->ctx->req.options, options);
	return task;
}

int worker_resolve_exec(struct qr_task *task, knot_pkt_t *query)
{
	if (!task)
		return kr_error(EINVAL);
	return qr_task_step(task, NULL, query);
}

int worker_task_numrefs(const struct qr_task *task)
{
	return task->refs;
}

struct kr_request *worker_task_request(struct qr_task *task)
{
	if (!task || !task->ctx)
		return NULL;

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
	qr_task_complete(task);
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

struct session *worker_request_get_source_session(const struct kr_request *req)
{
	static_assert(offsetof(struct request_ctx, req) == 0,
			"Bad struct request_ctx definition.");
	return ((struct request_ctx *)req)->source.session;
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

/** Reserve worker buffers.  We assume worker's been zeroed. */
static int worker_reserve(struct worker_ctx *worker, size_t ring_maxlen)
{
	worker->tcp_connected = map_make(NULL);
	worker->tcp_waiting = map_make(NULL);
	worker->subreq_out = trie_create(NULL);

	array_init(worker->pool_mp);
	if (array_reserve(worker->pool_mp, ring_maxlen)) {
		return kr_error(ENOMEM);
	}

	mm_ctx_mempool(&worker->pkt_pool, 4 * sizeof(knot_pkt_t));

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

void worker_deinit(void)
{
	struct worker_ctx *worker = the_worker;
	if (kr_fails_assert(worker))
		return;
	if (worker->z_import != NULL) {
		zi_free(worker->z_import);
		worker->z_import = NULL;
	}
	map_clear(&worker->tcp_connected);
	map_clear(&worker->tcp_waiting);
	trie_free(worker->subreq_out);
	worker->subreq_out = NULL;

	for (int i = 0; i < worker->doh_qry_headers.len; i++)
		free((void *)worker->doh_qry_headers.at[i]);
	array_clear(worker->doh_qry_headers);

	reclaim_mp_freelist(&worker->pool_mp);
	mp_delete(worker->pkt_pool.ctx);
	worker->pkt_pool.ctx = NULL;

	the_worker = NULL;
}

int worker_init(struct engine *engine, int worker_count)
{
	if (kr_fails_assert(engine && engine->L && the_worker == NULL))
		return kr_error(EINVAL);
	kr_bindings_register(engine->L);

	/* Create main worker. */
	struct worker_ctx *worker = &the_worker_value;
	memset(worker, 0, sizeof(*worker));
	worker->engine = engine;

	uv_loop_t *loop = uv_default_loop();
	worker->loop = loop;

	worker->count = worker_count;

	/* Register table for worker per-request variables */
	lua_newtable(engine->L);
	lua_setfield(engine->L, -2, "vars");
	lua_getfield(engine->L, -1, "vars");
	worker->vars_table_ref = luaL_ref(engine->L, LUA_REGISTRYINDEX);
	lua_pop(engine->L, 1);

	worker->tcp_pipeline_max = MAX_PIPELINED;
	worker->out_addr4.sin_family = AF_UNSPEC;
	worker->out_addr6.sin6_family = AF_UNSPEC;

	array_init(worker->doh_qry_headers);

	int ret = worker_reserve(worker, MP_FREELIST_SIZE);
	if (ret) return ret;
	worker->next_request_uid = UINT16_MAX + 1;

	/* Set some worker.* fields in Lua */
	lua_getglobal(engine->L, "worker");
	pid_t pid = getpid();

	auto_free char *pid_str = NULL;
	const char *inst_name = getenv("SYSTEMD_INSTANCE");
	if (inst_name) {
		lua_pushstring(engine->L, inst_name);
	} else {
		ret = asprintf(&pid_str, "%ld", (long)pid);
		kr_assert(ret > 0);
		lua_pushstring(engine->L, pid_str);
	}
	lua_setfield(engine->L, -2, "id");

	lua_pushnumber(engine->L, pid);
	lua_setfield(engine->L, -2, "pid");
	lua_pushnumber(engine->L, worker_count);
	lua_setfield(engine->L, -2, "count");

	char cwd[PATH_MAX];
	get_workdir(cwd, sizeof(cwd));
	lua_pushstring(engine->L, cwd);
	lua_setfield(engine->L, -2, "cwd");

	the_worker = worker;
	loop->data = the_worker;
	/* ^^^^ Now this shouldn't be used anymore, but it's hard to be 100% sure. */
	return kr_ok();
}

#undef VERBOSE_MSG
