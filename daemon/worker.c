/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
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
#include "daemon/proxyv2.h"
#include "daemon/session2.h"
#include "daemon/tls.h"
#include "lib/cache/util.h" /* packet_ttl */
#include "lib/layer.h"
#include "lib/layer/iterate.h" /* kr_response_classify */
#include "lib/utils.h"
#include "daemon/defer.h"


/* Magic defaults for the worker. */
#ifndef MAX_PIPELINED
#define MAX_PIPELINED 100
#endif

#define MAX_DGRAM_LEN UINT16_MAX

#define VERBOSE_MSG(qry, ...) kr_log_q(qry, WORKER, __VA_ARGS__)

/** Client request state. */
struct request_ctx
{
	struct kr_request req;

	struct qr_task *task;
	struct {
		/** NULL if the request didn't come over network. */
		struct session2 *session;
		/** Requestor's address; separate because of UDP session "sharing". */
		union kr_sockaddr addr;
		/** Request communication address; if not from a proxy, same as addr. */
		union kr_sockaddr comm_addr;
		/** Local address.  For AF_XDP we couldn't use session's,
		 * as the address might be different every time. */
		union kr_sockaddr dst_addr;

		/** Router's MAC address for XDP. */
		ethaddr_t eth_from;
		/** Our MAC address for XDP. */
		ethaddr_t eth_to;
		/** Whether XDP was used. */
		bool xdp : 1;
	} source;
};

/** Query resolution task. */
struct qr_task
{
	struct request_ctx *ctx;
	knot_pkt_t *pktbuf;
	qr_tasklist_t waiting;
	struct session2 *pending[MAX_PENDING];
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

struct pl_dns_stream_sess_data {
	struct protolayer_data h;
	bool single : 1; /**< True: Stream only allows a single packet */
	bool produced : 1; /**< True: At least one packet has been produced */
	bool connected : 1; /**< True: The stream is connected */
	bool half_closed : 1; /**< True: EOF was received, the stream is half-closed */
};

/* Forward decls */
static void qr_task_free(struct qr_task *task);
static int qr_task_step(struct qr_task *task,
			const struct sockaddr *packet_source,
			knot_pkt_t *packet);
static int qr_task_send(struct qr_task *task, struct session2 *session,
			const struct comm_info *comm, knot_pkt_t *pkt);
static int qr_task_finalize(struct qr_task *task, int state);
static void qr_task_complete(struct qr_task *task);
static int worker_add_tcp_connected(const struct sockaddr* addr, struct session2 *session);
static int worker_del_tcp_connected(const struct sockaddr* addr);
static struct session2* worker_find_tcp_connected(const struct sockaddr* addr);
static int worker_add_tcp_waiting(const struct sockaddr* addr,
				  struct session2 *session);
static int worker_del_tcp_waiting(const struct sockaddr* addr);
static struct session2* worker_find_tcp_waiting(const struct sockaddr* addr);

static void subreq_finalize(struct qr_task *task, const struct sockaddr *packet_source, knot_pkt_t *pkt);

struct worker_ctx the_worker_value; /**< Static allocation is suitable for the singleton. */
struct worker_ctx *the_worker = NULL;


static inline void defer_sample_task(const struct qr_task *task)
{
	if (task && task->ctx->source.session) {
		defer_sample_addr(&task->ctx->source.addr, task->ctx->source.session->stream);
		defer_sample_state.price_factor16 = task->ctx->req.qsource.price_factor16;
	}
}

/*! @internal Create a UDP/TCP handle for an outgoing AF_INET* connection.
 *  socktype is SOCK_* */
static struct session2 *ioreq_spawn(int socktype, sa_family_t family,
                                    enum kr_proto grp,
                                    struct protolayer_data_param *layer_param,
                                    size_t layer_param_count)
{
	bool precond = (socktype == SOCK_DGRAM || socktype == SOCK_STREAM)
			&& (family == AF_INET  || family == AF_INET6);
	if (kr_fails_assert(precond)) {
		kr_log_debug(WORKER, "ioreq_spawn: pre-condition failed\n");
		return NULL;
	}

	/* Create connection for iterative query */
	struct session2 *s;
	int ret = io_create(the_worker->loop, &s, socktype, family, grp,
			layer_param, layer_param_count, true);
	if (ret) {
		if (ret == UV_EMFILE) {
			the_worker->too_many_open = true;
			the_worker->rconcurrent_highwatermark = the_worker->stats.rconcurrent;
		}
		return NULL;
	}

	/* Bind to outgoing address, according to IP v4/v6. */
	union kr_sockaddr *addr;
	if (family == AF_INET) {
		addr = (union kr_sockaddr *)&the_worker->out_addr4;
	} else {
		addr = (union kr_sockaddr *)&the_worker->out_addr6;
	}
	if (addr->ip.sa_family != AF_UNSPEC) {
		if (kr_fails_assert(addr->ip.sa_family == family)) {
			session2_force_close(s);
			return NULL;
		}
		if (socktype == SOCK_DGRAM) {
			uv_udp_t *udp = (uv_udp_t *)session2_get_handle(s);
			ret = uv_udp_bind(udp, &addr->ip, 0);
		} else if (socktype == SOCK_STREAM){
			uv_tcp_t *tcp = (uv_tcp_t *)session2_get_handle(s);
			ret = uv_tcp_bind(tcp, &addr->ip, 0);
		}
	}

	if (ret != 0) {
		session2_force_close(s);
		return NULL;
	}

	/* Connect or issue query datagram */
	return s;
}

static void ioreq_kill_pending(struct qr_task *task)
{
	for (uint16_t i = 0; i < task->pending_count; ++i) {
		session2_kill_ioreq(task->pending[i], task);
	}
	task->pending_count = 0;
}

/** Get a mempool. */
static inline struct mempool *pool_borrow(void)
{
	/* The implementation used to have extra caching layer,
	 * but it didn't work well.  Now it's very simple. */
	return mp_new((size_t)16 * 1024);
}
/** Return a mempool. */
static inline void pool_release(struct mempool *mp)
{
	mp_delete(mp);
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
	uv_handle_t *handle = session2_get_handle(ctx->source.session);
	if (kr_fails_assert(handle->type == UV_POLL))
		return NULL;
	xdp_handle_data_t *xhd = handle->data;
	knot_xdp_msg_t out;
	bool ipv6 = ctx->source.comm_addr.ip.sa_family == AF_INET6;
	int ret = knot_xdp_send_alloc(xhd->socket, ipv6 ? KNOT_XDP_MSG_IPV6 : 0, &out);
	if (ret != KNOT_EOK) {
		kr_assert(ret == KNOT_ENOMEM);
		*maxlen = 0;
		return NULL;
	}
	*maxlen = MIN(*maxlen, out.payload.iov_len);
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
	if (!ctx->source.session)
		return;
	/* We know it's an AF_XDP socket; otherwise alloc_wire_cb isn't assigned. */
	uv_handle_t *handle = session2_get_handle(ctx->source.session);
	if (!handle || kr_fails_assert(handle->type == UV_POLL))
		return;
	xdp_handle_data_t *xhd = handle->data;
	/* Freeing is done by sending an empty packet (the API won't really send it). */
	knot_xdp_msg_t out;
	out.payload.iov_base = ans->wire;
	out.payload.iov_len = 0;
	uint32_t sent = 0;
	int ret = 0;
	knot_xdp_send_free(xhd->socket, &out, 1);
	kr_assert(ret == KNOT_EOK && sent == 0);
	kr_log_debug(XDP, "freed unsent buffer, ret = %d\n", ret);
}
#endif
/* Helper functions for transport selection */
static inline bool is_tls_capable(struct sockaddr *address) {
	tls_client_param_t *tls_entry = tls_client_param_get(
			the_network->tls_client_params, address);
	return tls_entry;
}

static inline bool is_tcp_connected(struct sockaddr *address) {
	return worker_find_tcp_connected(address);
}

static inline bool is_tcp_waiting(struct sockaddr *address) {
	return worker_find_tcp_waiting(address);
}

/** Create and initialize a request_ctx (on a fresh mempool).
 *
 * session and addr point to the source of the request, and they are NULL
 * in case the request didn't come from network.
 */
static struct request_ctx *request_create(struct session2 *session,
                                          struct comm_info *comm,
                                          uint32_t uid)
{
	knot_mm_t pool = {
		.ctx = pool_borrow(),
		.alloc = (knot_mm_alloc_t) mp_alloc
	};

	/* Create request context */
	struct request_ctx *ctx = mm_calloc(&pool, 1, sizeof(*ctx));
	if (!ctx) {
		pool_release(pool.ctx);
		return NULL;
	}

	/* TODO Relocate pool to struct request */
	if (session && kr_fails_assert(session->outgoing == false)) {
		pool_release(pool.ctx);
		return NULL;
	}
	ctx->source.session = session;
	if (comm && comm->xdp) {
	#if ENABLE_XDP
		if (kr_fails_assert(session)) {
			pool_release(pool.ctx);
			return NULL;
		}
		memcpy(ctx->source.eth_to,   comm->eth_to,   sizeof(ctx->source.eth_to));
		memcpy(ctx->source.eth_from, comm->eth_from, sizeof(ctx->source.eth_from));
		ctx->req.alloc_wire_cb = alloc_wire_cb;
	#else
		kr_assert(!EINVAL);
		pool_release(pool.ctx);
		return NULL;
	#endif
	}

	struct kr_request *req = &ctx->req;
	req->pool = pool;
	req->vars_ref = LUA_NOREF;
	req->uid = uid;
	req->qsource.comm_flags.xdp = comm && comm->xdp;
	req->qsource.price_factor16 = 1 << 16; // meaning *1.0
	kr_request_set_extended_error(req, KNOT_EDNS_EDE_NONE, NULL);
	array_init(req->qsource.headers);
	if (session) {
		kr_require(comm);

		const struct sockaddr *src_addr = comm->src_addr;
		const struct sockaddr *comm_addr = comm->comm_addr;
		const struct sockaddr *dst_addr = comm->dst_addr;
		const struct proxy_result *proxy = comm->proxy;

		req->qsource.stream_id = -1;
		session2_init_request(session, req);

		req->qsource.flags = req->qsource.comm_flags;
		if (proxy) {
			req->qsource.flags.tcp = proxy->protocol == SOCK_STREAM;
			req->qsource.flags.tls = proxy->has_tls;
		}

		/* We need to store a copy of peer address. */
		memcpy(&ctx->source.addr.ip, src_addr, kr_sockaddr_len(src_addr));
		req->qsource.addr = &ctx->source.addr.ip;

		if (!comm_addr)
			comm_addr = src_addr;
		memcpy(&ctx->source.comm_addr.ip, comm_addr, kr_sockaddr_len(comm_addr));
		req->qsource.comm_addr = &ctx->source.comm_addr.ip;

		if (!dst_addr) /* We wouldn't have to copy in this case, but for consistency. */
			dst_addr = session2_get_sockname(session);
		memcpy(&ctx->source.dst_addr.ip, dst_addr, kr_sockaddr_len(dst_addr));
		req->qsource.dst_addr = &ctx->source.dst_addr.ip;
	}

	req->selection_context.is_tls_capable = is_tls_capable;
	req->selection_context.is_tcp_connected = is_tcp_connected;
	req->selection_context.is_tcp_waiting = is_tcp_waiting;
	array_init(req->selection_context.forwarding_targets);
	array_reserve_mm(req->selection_context.forwarding_targets, 1, kr_memreserve, &req->pool);

	the_worker->stats.rconcurrent += 1;

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
	kr_resolve_begin(req, the_resolver);
	the_worker->stats.queries += 1;
	return kr_ok();
}

static void request_free(struct request_ctx *ctx)
{
	/* Dereference any Lua vars table if exists */
	if (ctx->req.vars_ref != LUA_NOREF) {
		lua_State *L = the_engine->L;
		/* Get worker variables table */
		lua_rawgeti(L, LUA_REGISTRYINDEX, the_worker->vars_table_ref);
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
	pool_release(ctx->req.pool.ctx);
	/* @note The 'task' is invalidated from now on. */
	the_worker->stats.rconcurrent -= 1;
}

static struct qr_task *qr_task_create(struct request_ctx *ctx)
{
	/* Choose (initial) pktbuf size.  As it is now, pktbuf can be used
	 * for UDP answers from upstream *and* from cache
	 * and for sending queries upstream */
	uint16_t pktbuf_max = KR_EDNS_PAYLOAD;
	const knot_rrset_t *opt_our = the_resolver->upstream_opt_rr;
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
	the_worker->stats.concurrent += 1;
	return task;
}

/* This is called when the task refcount is zero, free memory. */
static void qr_task_free(struct qr_task *task)
{
	struct request_ctx *ctx = task->ctx;

	if (kr_fails_assert(ctx))
		return;

	kr_require(ctx->task == NULL);
	request_free(ctx);

	/* Update stats */
	the_worker->stats.concurrent -= 1;
}

/*@ Register new qr_task within session. */
static int qr_task_register(struct qr_task *task, struct session2 *session)
{
	if (kr_fails_assert(!session->outgoing && session->stream))
		return kr_error(EINVAL);

	session2_tasklist_add(session, task);

	struct request_ctx *ctx = task->ctx;
	if (kr_fails_assert(ctx && (ctx->source.session == NULL || ctx->source.session == session)))
		return kr_error(EINVAL);
	ctx->source.session = session;
	/* Soft-limit on parallel queries, there is no "slow down" RCODE
	 * that we could use to signalize to client, but we can stop reading,
	 * an in effect shrink TCP window size. To get more precise throttling,
	 * we would need to copy remainder of the unread buffer and reassemble
	 * when resuming reading. This is NYI.  */
	if (session2_tasklist_get_len(session) >= the_worker->tcp_pipeline_max &&
	    !session->throttled && !session->closing) {
		session2_stop_read(session);
		session->throttled = true;
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

	struct session2 *s = ctx->source.session;
	if (s) {
		kr_require(!s->outgoing && session2_waitinglist_is_empty(s));
		ctx->source.session = NULL;
		session2_tasklist_del(s, task);
	}

	/* Release primary reference to task. */
	if (ctx->task == task) {
		ctx->task = NULL;
		qr_task_unref(task);
	}
}

/* This is called when we send subrequest / answer */
int qr_task_on_send(struct qr_task *task, struct session2 *s, int status)
{
	if (task->finished) {
		kr_require(task->leading == false);
		qr_task_complete(task);
	}

	if (!s)
		return status;

	if (!s->stream && s->outgoing) {
		// This should ensure that we are only dealing with our question to upstream
		if (kr_fails_assert(!knot_wire_get_qr(task->pktbuf->wire)))
			return status;
		// start the timer
		struct kr_query *qry = array_tail(task->ctx->req.rplan.pending);
		if (kr_fails_assert(qry && task->transport))
			return status;
		size_t timeout = task->transport->timeout;
		int ret = session2_timer_start(s, PROTOLAYER_EVENT_GENERAL_TIMEOUT,
				timeout, 0);
		/* Start next step with timeout, fatal if can't start a timer. */
		if (ret != 0) {
			subreq_finalize(task, &task->transport->address.ip, task->pktbuf);
			qr_task_finalize(task, KR_STATE_FAIL);
		}
	}

	if (s->stream) {
		if (status != 0) { // session probably not usable anymore; typically: ECONNRESET
			const struct kr_request *req = &task->ctx->req;
			if (kr_log_is_debug(WORKER, req)) {
				const char *peer_str = NULL;
				if (!s->outgoing) {
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
			session2_force_close(s);
			return status;
		}

		if (s->outgoing || s->closing)
			return status;

		if (s->throttled &&
		    session2_tasklist_get_len(s) < the_worker->tcp_pipeline_max/2) {
			/* Start reading again if the session is throttled and
			 * the number of outgoing requests is below watermark. */
			session2_start_read(s);
			s->throttled = false;
		}
	}

	return status;
}

static void qr_task_wrap_finished(int status, struct session2 *session,
                                  const struct comm_info *comm, void *baton)
{
	struct qr_task *task = baton;
	qr_task_on_send(task, session, status);
	qr_task_unref(task);
}

static int qr_task_send(struct qr_task *task, struct session2 *session,
			const struct comm_info *comm, knot_pkt_t *pkt)
{
	if (!session)
		return qr_task_on_send(task, NULL, kr_error(EIO));

	int ret = 0;

	if (pkt == NULL)
		pkt = worker_task_get_pktbuf(task);

	if (session->outgoing && session->stream) {
		size_t try_limit = session2_tasklist_get_len(session) + 1;
		uint16_t msg_id = knot_wire_get_id(pkt->wire);
		size_t try_count = 0;
		while (session2_tasklist_find_msgid(session, msg_id) &&
		       try_count <= try_limit) {
			++msg_id;
			++try_count;
		}
		if (try_count > try_limit)
			return kr_error(ENOENT);
		worker_task_pkt_set_msgid(task, msg_id);
	}

	/* Note time for upstream RTT */
	task->send_time = kr_now();
	task->recv_time = 0; // task structure is being reused so we have to zero this out here
	/* Send using given protocol */
	if (kr_fails_assert(!session->closing))
		return qr_task_on_send(task, NULL, kr_error(EIO));

	/* Pending '_finished' callback on current task */
	qr_task_ref(task);
	struct protolayer_payload payload = protolayer_payload_buffer(
			(char *)pkt->wire, pkt->size, false);
	payload.ttl = packet_ttl(pkt);
	ret = session2_wrap(session, payload, comm, qr_task_wrap_finished, task);

	if (ret >= 0) {
		session2_touch(session);
		if (session->outgoing) {
			session2_tasklist_add(session, task);
		}
		if (the_worker->too_many_open &&
		    the_worker->stats.rconcurrent <
			the_worker->rconcurrent_highwatermark - 10) {
			the_worker->too_many_open = false;
		}
		ret = kr_ok();
	} else {
		if (ret == UV_EMFILE) {
			the_worker->too_many_open = true;
			the_worker->rconcurrent_highwatermark = the_worker->stats.rconcurrent;
			ret = kr_error(UV_EMFILE);
		}

		session2_event(session, PROTOLAYER_EVENT_STATS_SEND_ERR, NULL);
	}

	/* Update outgoing query statistics */
	if (session->outgoing && comm) {
		session2_event(session, PROTOLAYER_EVENT_STATS_QRY_OUT, NULL);

		if (comm->comm_addr->sa_family == AF_INET6)
			the_worker->stats.ipv6 += 1;
		else if (comm->comm_addr->sa_family == AF_INET)
			the_worker->stats.ipv4 += 1;
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

static int send_waiting(struct session2 *session)
{
	if (session2_waitinglist_is_empty(session))
		return 0;

	defer_sample_state_t defer_prev_sample_state;
	defer_sample_start(&defer_prev_sample_state);
	int ret = 0;
	do {
		struct qr_task *t = session2_waitinglist_get(session);
		defer_sample_task(t);
		ret = qr_task_send(t, session, NULL, NULL);
		defer_sample_restart();
		if (ret != 0) {
			struct sockaddr *peer = session2_get_peer(session);
			session2_waitinglist_finalize(session, KR_STATE_FAIL);
			session2_tasklist_finalize(session, KR_STATE_FAIL);
			worker_del_tcp_connected(peer);
			session2_close(session);
			break;
		}
		session2_waitinglist_pop(session, true);
	} while (!session2_waitinglist_is_empty(session));
	defer_sample_stop(&defer_prev_sample_state, true);

	return ret;
}

static void on_connect(uv_connect_t *req, int status)
{
	kr_require(the_worker);
	uv_stream_t *handle = req->handle;
	struct session2 *session = handle->data;
	struct sockaddr *peer = session2_get_peer(session);
	free(req);

	if (kr_fails_assert(session->outgoing))
		return;

	if (session->closing) {
		worker_del_tcp_waiting(peer);
		kr_assert(session2_is_empty(session));
		return;
	}

	const bool log_debug = kr_log_is_debug(WORKER, NULL);

	/* Check if the connection is in the waiting list.
	 * If no, most likely this is timed out connection
	 * which was removed from waiting list by
	 * on_tcp_connect_timeout() callback. */
	struct session2 *found_session = worker_find_tcp_waiting(peer);
	if (!found_session || found_session != session) {
		/* session isn't on the waiting list.
		 * it's timed out session. */
		if (log_debug) {
			const char *peer_str = kr_straddr(peer);
			kr_log_debug(WORKER, "=> connected to '%s', but session "
					"is already timed out, close\n",
					peer_str ? peer_str : "");
		}
		kr_assert(session2_tasklist_is_empty(session));
		session2_waitinglist_retry(session, false);
		session2_close(session);
		return;
	}

	found_session = worker_find_tcp_connected(peer);
	if (found_session) {
		/* session already in the connected list.
		 * Something went wrong, it can be due to races when kresd has tried
		 * to reconnect to upstream after unsuccessful attempt. */
		if (log_debug) {
			const char *peer_str = kr_straddr(peer);
			kr_log_debug(WORKER, "=> connected to '%s', but peer "
					"is already connected, close\n",
					peer_str ? peer_str : "");
		}
		kr_assert(session2_tasklist_is_empty(session));
		session2_waitinglist_retry(session, false);
		session2_close(session);
		return;
	}

	if (status != 0) {
		if (log_debug) {
			const char *peer_str = kr_straddr(peer);
			kr_log_debug(WORKER, "=> connection to '%s' failed (%s), flagged as 'bad'\n",
					peer_str ? peer_str : "", uv_strerror(status));
		}
		worker_del_tcp_waiting(peer);
		if (status != UV_ETIMEDOUT) {
			/* In case of UV_ETIMEDOUT upstream has been
			 * already penalized in on_tcp_connect_timeout() */
			session2_event(session, PROTOLAYER_EVENT_CONNECT_FAIL, NULL);
		}
		kr_assert(session2_tasklist_is_empty(session));
		session2_close(session);
		return;
	}

	if (log_debug) {
		const char *peer_str = kr_straddr(peer);
		kr_log_debug(WORKER, "=> connected to '%s'\n", peer_str ? peer_str : "");
	}

	session2_event(session, PROTOLAYER_EVENT_CONNECT, NULL);
	session2_start_read(session);
	session2_timer_stop(session);
	session2_timer_start(session, PROTOLAYER_EVENT_GENERAL_TIMEOUT,
			MAX_TCP_INACTIVITY, MAX_TCP_INACTIVITY);
}

static int transmit(struct qr_task *task)
{
	if (!task)
		return kr_error(EINVAL);

	struct kr_transport* transport = task->transport;
	struct sockaddr_in6 *choice = (struct sockaddr_in6 *)&transport->address;

	if (!choice)
		return kr_error(EINVAL);
	if (task->pending_count >= MAX_PENDING)
		return kr_error(EBUSY);
	/* Checkout answer before sending it */
	struct request_ctx *ctx = task->ctx;
	int ret = kr_resolve_checkout(&ctx->req, NULL, transport, task->pktbuf);
	if (ret)
		return ret;

	struct session2 *session = ioreq_spawn(SOCK_DGRAM, choice->sin6_family,
			KR_PROTO_UDP53, NULL, 0);
	if (!session)
		return kr_error(EINVAL);

	struct sockaddr *addr = (struct sockaddr *)choice;
	struct sockaddr *peer = session2_get_peer(session);
	kr_assert(peer->sa_family == AF_UNSPEC && session->outgoing);
	kr_require(addr->sa_family == AF_INET || addr->sa_family == AF_INET6);
	memcpy(peer, addr, kr_sockaddr_len(addr));

	struct comm_info out_comm = {
		.comm_addr = (struct sockaddr *)choice
	};

	if (the_network->enable_connect_udp && session->outgoing && !session->stream) {
		uv_udp_t *udp = (uv_udp_t *)session2_get_handle(session);
		int connect_tries = 3;

		do {
			ret = uv_udp_connect(udp, out_comm.comm_addr);
		} while (ret == UV_EADDRINUSE && --connect_tries > 0);
		if (ret < 0) {
			kr_log_info(IO, "Failed to establish udp connection to %s: %s\n",
					kr_straddr(out_comm.comm_addr), uv_strerror(ret));
		}
	}
	ret = qr_task_send(task, session, &out_comm, task->pktbuf);
	if (ret) {
		session2_close(session);
		return ret;
	}

	task->pending[task->pending_count] = session;
	task->pending_count += 1;
	session2_start_read(session); /* Start reading answer */
	return kr_ok();
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
		int ret = trie_del(the_worker->subreq_out, key, klen, &val_deleted);
		kr_assert(ret == KNOT_EOK && val_deleted == task);
	}
	/* Notify waiting tasks. */
	if (task->waiting.len > 0) {
		struct kr_query *leader_qry = array_tail(task->ctx->req.rplan.pending);
		defer_sample_state_t defer_prev_sample_state;
		defer_sample_start(&defer_prev_sample_state);
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
			defer_sample_restart();
		}
		defer_sample_stop(&defer_prev_sample_state, true);
		task->waiting.len = 0;
	}
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
		trie_get_ins(the_worker->subreq_out, key, klen);
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
		trie_get_try(the_worker->subreq_out, key, klen);
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
	kr_require(task && task->leading == false);
	if (task->finished) {
		return kr_ok();
	}

	defer_sample_task(task);

	struct request_ctx *ctx = task->ctx;
	struct session2 *source_session = ctx->source.session;
	kr_resolve_finish(&ctx->req, state);

	task->finished = true;
	if (source_session == NULL) {
		(void) qr_task_on_send(task, NULL, kr_error(EIO));
		return state == KR_STATE_DONE ? kr_ok() : kr_error(EIO);
	}

	/* meant to be dropped */
	if (unlikely(ctx->req.answer == NULL || ctx->req.options.NO_ANSWER)) {
		/* For NO_ANSWER, a well-behaved layer should set the state to FAIL */
		kr_assert(!ctx->req.options.NO_ANSWER || (ctx->req.state & KR_STATE_FAIL));

		(void) qr_task_on_send(task, NULL, kr_ok());
		return kr_ok();
	}

	if (source_session->closing ||
	    ctx->source.addr.ip.sa_family == AF_UNSPEC)
		return kr_error(EINVAL);

	/* Reference task as the callback handler can close it */
	qr_task_ref(task);

	/* Send back answer */
	struct comm_info out_comm = {
		.src_addr = &ctx->source.addr.ip,
		.dst_addr = &ctx->source.dst_addr.ip,
		.comm_addr = &ctx->source.comm_addr.ip,
		.xdp = ctx->source.xdp
	};
	if (ctx->source.xdp) {
		memcpy(out_comm.eth_from, ctx->source.eth_from, sizeof(out_comm.eth_from));
		memcpy(out_comm.eth_to,   ctx->source.eth_to,   sizeof(out_comm.eth_to));
	}
	int ret = qr_task_send(task, source_session, &out_comm, ctx->req.answer);

	if (ret != kr_ok()) {
		(void) qr_task_on_send(task, NULL, kr_error(EIO));
		/* Since source session is erroneous detach all tasks. */
		while (!session2_tasklist_is_empty(source_session)) {
			struct qr_task *t = session2_tasklist_del_first(source_session, false);
			struct request_ctx *c = t->ctx;
			kr_assert(c->source.session == source_session);
			c->source.session = NULL;
			/* Don't finalize them as there can be other tasks
			 * waiting for answer to this particular task.
			 * (ie. task->leading is true) */
			worker_task_unref(t);
		}
		session2_close(source_session);
	}

	if (source_session->stream && !source_session->closing) {
		struct pl_dns_stream_sess_data *stream =
			protolayer_sess_data_get_proto(source_session, PROTOLAYER_TYPE_DNS_MULTI_STREAM);
		if (!stream)
			stream = protolayer_sess_data_get_proto(source_session, PROTOLAYER_TYPE_DNS_UNSIZED_STREAM);
		if (!stream)
			stream = protolayer_sess_data_get_proto(source_session, PROTOLAYER_TYPE_DNS_SINGLE_STREAM);
		if (stream && stream->half_closed) {
			session2_force_close(source_session);
		}
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
	int err = transmit(task);
	if (err) {
		subreq_finalize(task, packet_source, packet);
		return qr_task_finalize(task, KR_STATE_FAIL);
	}

	/* Announce and start subrequest.
	 * @note Only UDP can lead I/O as it doesn't touch 'task->pktbuf' for reassembly.
	 */
	subreq_lead(task);

	return kr_ok();
}

static int tcp_task_waiting_connection(struct session2 *session, struct qr_task *task)
{
	if (kr_fails_assert(session->outgoing && !session->closing))
		return kr_error(EINVAL);
	/* Add task to the end of list of waiting tasks.
	 * It will be notified in on_connect() or qr_task_on_send(). */
	int ret = session2_waitinglist_push(session, task);
	if (ret < 0) {
		return kr_error(EINVAL);
	}
	return kr_ok();
}

static int tcp_task_existing_connection(struct session2 *session, struct qr_task *task)
{
	if (kr_fails_assert(session->outgoing && !session->closing))
		return kr_error(EINVAL);

	/* If there are any unsent queries, send it first. */
	int ret = send_waiting(session);
	if (ret != 0) {
		return kr_error(EINVAL);
	}

	/* No unsent queries at that point. */
	if (session2_tasklist_get_len(session) >= the_worker->tcp_pipeline_max) {
		/* Too many outstanding queries, answer with SERVFAIL, */
		return kr_error(EINVAL);
	}

	/* Send query to upstream. */
	ret = qr_task_send(task, session, NULL, NULL);
	if (ret != 0) {
		/* Error, finalize task with SERVFAIL and
		 * close connection to upstream. */
		session2_tasklist_finalize(session, KR_STATE_FAIL);
		worker_del_tcp_connected(session2_get_peer(session));
		session2_close(session);
		return kr_error(EINVAL);
	}

	return kr_ok();
}

static int tcp_task_make_connection(struct qr_task *task, const struct sockaddr *addr)
{
	/* Check if there must be TLS */
	tls_client_param_t *tls_entry = tls_client_param_get(
			the_network->tls_client_params, addr);

	uv_connect_t *conn = malloc(sizeof(uv_connect_t));
	if (!conn) {
		return kr_error(EINVAL);
	}
	struct session2 *session;

	bool has_tls = tls_entry;
	if (has_tls) {
		struct protolayer_data_param param = {
			.protocol = PROTOLAYER_TYPE_TLS,
			.param = tls_entry
		};
		session = ioreq_spawn(SOCK_STREAM, addr->sa_family,
				KR_PROTO_DOT, &param, 1);
	} else {
		session = ioreq_spawn(SOCK_STREAM, addr->sa_family,
				KR_PROTO_TCP53, NULL, 0);
	}
	if (!session) {
		free(conn);
		return kr_error(EINVAL);
	}
	if (kr_fails_assert(session->secure == has_tls)) {
		free(conn);
		return kr_error(EINVAL);
	}

	/* Add address to the waiting list.
	 * Now it "is waiting to be connected to." */
	int ret = worker_add_tcp_waiting(addr, session);
	if (ret < 0) {
		free(conn);
		session2_close(session);
		return kr_error(EINVAL);
	}

	conn->data = session;
	/*  Store peer address for the session. */
	struct sockaddr *peer = session2_get_peer(session);
	memcpy(peer, addr, kr_sockaddr_len(addr));

	/*  Start watchdog to catch eventual connection timeout. */
	ret = session2_timer_start(session, PROTOLAYER_EVENT_CONNECT_TIMEOUT,
			KR_CONN_RTT_MAX, 0);
	if (ret != 0) {
		worker_del_tcp_waiting(addr);
		free(conn);
		session2_close(session);
		return kr_error(EINVAL);
	}

	struct kr_query *qry = task_get_last_pending_query(task);
	if (kr_log_is_debug_qry(WORKER, qry)) {
		const char *peer_str = kr_straddr(peer);
		VERBOSE_MSG(qry, "=> connecting to: '%s'\n", peer_str ? peer_str : "");
	}

	/*  Start connection process to upstream. */
	ret = uv_tcp_connect(conn, (uv_tcp_t *)session2_get_handle(session),
			addr , on_connect);
	if (ret != 0) {
		session2_timer_stop(session);
		worker_del_tcp_waiting(addr);
		free(conn);
		session2_close(session);
		qry->server_selection.error(qry, task->transport, KR_SELECTION_TCP_CONNECT_FAILED);
		return kr_error(EAGAIN);
	}

	/* Add task to the end of list of waiting tasks.
	 * Will be notified either in on_connect() or in qr_task_on_send(). */
	ret = session2_waitinglist_push(session, task);
	if (ret < 0) {
		session2_timer_stop(session);
		worker_del_tcp_waiting(addr);
		free(conn);
		session2_close(session);
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
	struct session2* session = NULL;
	if ((session = worker_find_tcp_waiting(addr)) != NULL) {
		/* Connection is in the list of waiting connections.
		 * It means that connection establishing is coming right now. */
		ret = tcp_task_waiting_connection(session, task);
	} else if ((session = worker_find_tcp_connected(addr)) != NULL) {
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
	defer_sample_task(task);

	/* No more steps after we're finished. */
	if (!task || task->finished) {
		return kr_error(ESTALE);
	}

	/* Close pending I/O requests */
	subreq_finalize(task, packet_source, packet);
	if ((kr_now() - task->creation_time) >= KR_RESOLVE_TIME_LIMIT) {
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

	if (the_worker->too_many_open) {
		/* */
		struct kr_rplan *rplan = &req->rplan;
		if (the_worker->stats.rconcurrent <
			the_worker->rconcurrent_highwatermark - 10) {
			the_worker->too_many_open = false;
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
				kr_request_set_extended_error(req, KNOT_EDNS_EDE_OTHER,
					"OGHD: exceeded iteration count limit");
			}
			if (task->timeouts >= KR_TIMEOUT_LIMIT) {
				char *msg = "cancelling query due to exceeded timeout retries limit";
				VERBOSE_MSG(last, "%s of %d\n", msg, KR_TIMEOUT_LIMIT);
				kr_request_set_extended_error(req, KNOT_EDNS_EDE_NREACH_AUTH, "QLPL");
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

static int worker_submit(struct session2 *session, struct comm_info *comm, knot_pkt_t *pkt)
{
	if (!session || !pkt || session->closing)
		return kr_error(EINVAL);

	const bool is_query = pkt->size > KNOT_WIRE_OFFSET_FLAGS1
				&& knot_wire_get_qr(pkt->wire) == 0;
	const bool is_outgoing = session->outgoing;

	int ret = 0;
	if (is_query == is_outgoing)
		ret = KNOT_ENOENT;

	// For responses from upstream, try to find associated task and query.
	// In case of errors, at least try to guess.
	struct qr_task *task = NULL;
	bool task_matched_id = false;
	if (is_outgoing && pkt->size >= 2) {
		const uint16_t id = knot_wire_get_id(pkt->wire);
		task = session2_tasklist_del_msgid(session, id);
		task_matched_id = task != NULL;
		if (task_matched_id) // Note receive time for RTT calculation
			task->recv_time = kr_now();
		if (!task_matched_id) {
			ret = KNOT_ENOENT;
			VERBOSE_MSG(NULL, "=> DNS message with mismatching ID %d\n",
					(int)id);
		}
	}
	if (!task && is_outgoing && session->stream) {
		// Source address of the reply got somewhat validated,
		// so we try to at least guess which query, for error reporting.
		task = session2_tasklist_get_first(session);
	}
	struct kr_query *qry = NULL;
	if (task)
		qry = array_tail(task->ctx->req.rplan.pending);

	// Parse the packet, unless it's useless anyway.
	if (ret == 0) {
		ret = knot_pkt_parse(pkt, 0);
		if (ret == KNOT_ETRAIL && is_outgoing
				&& !kr_fails_assert(pkt->parsed < pkt->size)) {
			// We deal with this later, so that RCODE takes priority.
			ret = 0;
		}
		if (ret && kr_log_is_debug_qry(WORKER, qry)) {
			VERBOSE_MSG(qry, "=> DNS message failed to parse, %s\n",
					knot_strerror(ret));
		}
	}

	/* Badly formed query when using DoH leads to a Bad Request */
	if (session->custom_emalf_handling && !is_outgoing && ret) {
		session2_event(session, PROTOLAYER_EVENT_MALFORMED, NULL);
		return ret;
	}

	const struct sockaddr *addr = comm ? comm->src_addr : NULL;

	/* Ignore badly formed queries. */
	if (ret) {
		if (is_outgoing && qry) // unusuable response from somewhat validated IP
			qry->server_selection.error(qry, task->transport, KR_SELECTION_MALFORMED);
		if (!is_outgoing)
			the_worker->stats.dropped += 1;
		if (task_matched_id) // notify task that answer won't be coming anymore
			qr_task_step(task, addr, NULL);
		return kr_error(EILSEQ);
	}

	/* Start new task on listening sockets,
	 * or resume if this is subrequest */
	if (!is_outgoing) { /* request from a client */
		struct request_ctx *ctx =
			request_create(session, comm, knot_wire_get_id(pkt->wire));
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

		if (session->stream && qr_task_register(task, session)) {
			return kr_error(ENOMEM);
		}
	} else { /* response from upstream */
		if (task == NULL) {
			return kr_error(ENOENT);
		}
		if (kr_fails_assert(!session->closing))
			return kr_error(EINVAL);
	}
	if (kr_fails_assert(!session->closing))
		return kr_error(EINVAL);

	/* Packet was successfully parsed.
	 * Task was created (found). */
	session2_touch(session);

	/* Consume input and produce next message */
	return qr_task_step(task, addr, pkt);
}

static int trie_add_tcp_session(trie_t *trie, const struct sockaddr *addr,
                                struct session2 *session)
{
	if (kr_fails_assert(trie && addr))
		return kr_error(EINVAL);
	struct kr_sockaddr_key_storage key;
	ssize_t keylen = kr_sockaddr_key(&key, addr);
	if (keylen < 0)
		return keylen;
	trie_val_t *val = trie_get_ins(trie, key.bytes, keylen);
	if (*val != NULL)
		return kr_error(EEXIST);
	*val = session;
	return kr_ok();
}

static int trie_del_tcp_session(trie_t *trie, const struct sockaddr *addr)
{
	if (kr_fails_assert(trie && addr))
		return kr_error(EINVAL);
	struct kr_sockaddr_key_storage key;
	ssize_t keylen = kr_sockaddr_key(&key, addr);
	if (keylen < 0)
		return keylen;
	int ret = trie_del(trie, key.bytes, keylen, NULL);
	return ret ? kr_error(ENOENT) : kr_ok();
}

static struct session2 *trie_find_tcp_session(trie_t *trie,
                                             const struct sockaddr *addr)
{
	if (kr_fails_assert(trie && addr))
		return NULL;
	struct kr_sockaddr_key_storage key;
	ssize_t keylen = kr_sockaddr_key(&key, addr);
	if (keylen < 0)
		return NULL;
	trie_val_t *val = trie_get_try(trie, key.bytes, keylen);
	return val ? *val : NULL;
}

static int worker_add_tcp_connected(const struct sockaddr* addr, struct session2 *session)
{
	return trie_add_tcp_session(the_worker->tcp_connected, addr, session);
}

static int worker_del_tcp_connected(const struct sockaddr* addr)
{
	return trie_del_tcp_session(the_worker->tcp_connected, addr);
}

static struct session2* worker_find_tcp_connected(const struct sockaddr* addr)
{
	return trie_find_tcp_session(the_worker->tcp_connected, addr);
}

static int worker_add_tcp_waiting(const struct sockaddr* addr,
				  struct session2 *session)
{
	return trie_add_tcp_session(the_worker->tcp_waiting, addr, session);
}

static int worker_del_tcp_waiting(const struct sockaddr* addr)
{
	return trie_del_tcp_session(the_worker->tcp_waiting, addr);
}

static struct session2* worker_find_tcp_waiting(const struct sockaddr* addr)
{
	return trie_find_tcp_session(the_worker->tcp_waiting, addr);
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
	knot_rrset_t *opt = knot_rrset_copy(the_resolver->downstream_opt_rr, NULL);
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
	if (kr_fails_assert(the_worker && query))
		return NULL;


	struct request_ctx *ctx = request_create(NULL, NULL, the_worker->next_request_uid);
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

	the_worker->next_request_uid += 1;
	if (the_worker->next_request_uid == 0)
		the_worker->next_request_uid = UINT16_MAX + 1;

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

struct kr_transport *worker_task_get_transport(struct qr_task *task)
{
	return task->transport;
}

struct session2 *worker_request_get_source_session(const struct kr_request *req)
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
	if (q)
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
static int worker_reserve(void)
{
	the_worker->tcp_connected = trie_create(NULL);
	the_worker->tcp_waiting = trie_create(NULL);
	the_worker->subreq_out = trie_create(NULL);

	mm_ctx_mempool(&the_worker->pkt_pool, 4 * sizeof(knot_pkt_t));

	return kr_ok();
}

void worker_deinit(void)
{
	if (kr_fails_assert(the_worker))
		return;
	trie_free(the_worker->tcp_connected);
	trie_free(the_worker->tcp_waiting);
	trie_free(the_worker->subreq_out);
	the_worker->subreq_out = NULL;

	for (int i = 0; i < the_worker->doh_qry_headers.len; i++)
		free((void *)the_worker->doh_qry_headers.at[i]);
	array_clear(the_worker->doh_qry_headers);

	mp_delete(the_worker->pkt_pool.ctx);
	the_worker->pkt_pool.ctx = NULL;

	the_worker = NULL;
}

static inline knot_pkt_t *produce_packet(uint8_t *buf, size_t buf_len)
{
	return knot_pkt_new(buf, buf_len, &the_worker->pkt_pool);
}

static enum protolayer_event_cb_result pl_dns_dgram_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if (event != PROTOLAYER_EVENT_GENERAL_TIMEOUT)
		return PROTOLAYER_EVENT_PROPAGATE;

	if (session2_tasklist_get_len(session) != 1 ||
			!session2_waitinglist_is_empty(session))
		return PROTOLAYER_EVENT_PROPAGATE;

	session2_timer_stop(session);

	struct qr_task *task = session2_tasklist_get_first(session);
	if (!task)
		return PROTOLAYER_EVENT_PROPAGATE;

	if (task->leading && task->pending_count > 0) {
		struct kr_query *qry = array_tail(task->ctx->req.rplan.pending);
		qry->server_selection.error(qry, task->transport, KR_SELECTION_QUERY_TIMEOUT);
	}

	task->timeouts += 1;
	the_worker->stats.timeout += 1;
	qr_task_step(task, NULL, NULL);

	return PROTOLAYER_EVENT_PROPAGATE;
}

static size_t pl_dns_dgram_wire_buf_overhead(bool outgoing)
{
	if (outgoing) {
		if (the_resolver->upstream_opt_rr)
			return knot_edns_get_payload(the_resolver->upstream_opt_rr);
	} else {
		if (the_resolver->downstream_opt_rr)
			return knot_edns_get_payload(the_resolver->downstream_opt_rr);
	}
	return KNOT_WIRE_MAX_PKTSIZE;
}

static enum protolayer_iter_cb_result pl_dns_dgram_unwrap(
		void *sess_data, void *iter_data, struct protolayer_iter_ctx *ctx)
{
	struct session2 *session = ctx->session;

	if (ctx->payload.type == PROTOLAYER_PAYLOAD_IOVEC) {
		int ret = kr_ok();
		for (int i = 0; i < ctx->payload.iovec.cnt; i++) {
			const struct iovec *iov = &ctx->payload.iovec.iov[i];
			if (iov->iov_len > MAX_DGRAM_LEN) {
				session2_penalize(session);
				ret = kr_error(EFBIG);
				break;
			}

			knot_pkt_t *pkt = produce_packet(
					iov->iov_base, iov->iov_len);
			if (!pkt) {
				ret = KNOT_EMALF;
				break;
			}

			ret = worker_submit(session, ctx->comm, pkt);
			if (ret)
				break;
		}

		mp_flush(the_worker->pkt_pool.ctx);
		return protolayer_break(ctx, ret);
	} else if (ctx->payload.type == PROTOLAYER_PAYLOAD_BUFFER) {
		if (ctx->payload.buffer.len > MAX_DGRAM_LEN) {
			session2_penalize(session);
			return protolayer_break(ctx, kr_error(EFBIG));
		}
		knot_pkt_t *pkt = produce_packet(
				ctx->payload.buffer.buf,
				ctx->payload.buffer.len);
		if (!pkt)
			return protolayer_break(ctx, KNOT_EMALF);

		int ret = worker_submit(session, ctx->comm, pkt);
		mp_flush(the_worker->pkt_pool.ctx);
		return protolayer_break(ctx, ret);
	} else if (ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF) {
		const size_t msg_len = wire_buf_data_length(ctx->payload.wire_buf);
		if (msg_len > MAX_DGRAM_LEN) {
			session2_penalize(session);
			return protolayer_break(ctx, kr_error(EFBIG));
		}

		knot_pkt_t *pkt = produce_packet(
				wire_buf_data(ctx->payload.wire_buf),
				msg_len);
		if (!pkt)
			return protolayer_break(ctx, KNOT_EMALF);

		int ret = worker_submit(session, ctx->comm, pkt);
		wire_buf_reset(ctx->payload.wire_buf);
		mp_flush(the_worker->pkt_pool.ctx);
		return protolayer_break(ctx, ret);
	} else {
		kr_assert(false && "Invalid payload");
		return protolayer_break(ctx, kr_error(EINVAL));
	}
}

static int pl_dns_stream_sess_init(struct session2 *session,
                                   void *sess_data, void *param)
{
	/* _UNSIZED_STREAM and _MULTI_STREAM - don't forget to split if needed
	 * at some point */
	session->stream = true;
	return kr_ok();
}

static int pl_dns_single_stream_sess_init(struct session2 *session,
                                          void *sess_data, void *param)
{
	session->stream = true;
	struct pl_dns_stream_sess_data *stream = sess_data;
	stream->single = true;
	return kr_ok();
}

static enum protolayer_event_cb_result pl_dns_stream_resolution_timeout(
		struct session2 *s)
{
	if (kr_fails_assert(!s->closing))
		return PROTOLAYER_EVENT_PROPAGATE;

	if (!session2_tasklist_is_empty(s)) {
		int finalized = session2_tasklist_finalize_expired(s);
		the_worker->stats.timeout += finalized;
		/* session2_tasklist_finalize_expired() may call worker_task_finalize().
		 * If session is a source session and there were IO errors,
		 * worker_task_finalize() can finalize all tasks and close session. */
		if (s->closing)
			return PROTOLAYER_EVENT_PROPAGATE;
	}

	if (!session2_tasklist_is_empty(s)) {
		session2_timer_stop(s);
		session2_timer_start(s,
				PROTOLAYER_EVENT_GENERAL_TIMEOUT,
				KR_RESOLVE_TIME_LIMIT / 2,
				KR_RESOLVE_TIME_LIMIT / 2);
	} else {
		/* Normally it should not happen,
		 * but better to check if there anything in this list. */
		if (!session2_waitinglist_is_empty(s)) {
			defer_sample_state_t defer_prev_sample_state;
			defer_sample_start(&defer_prev_sample_state);
			do {
				struct qr_task *t = session2_waitinglist_pop(s, false);
				worker_task_finalize(t, KR_STATE_FAIL);
				worker_task_unref(t);
				the_worker->stats.timeout += 1;
				if (s->closing)
					return PROTOLAYER_EVENT_PROPAGATE;
				defer_sample_restart();
			} while (!session2_waitinglist_is_empty(s));
			defer_sample_stop(&defer_prev_sample_state, true);
		}
		uint64_t idle_in_timeout = the_network->tcp.in_idle_timeout;
		uint64_t idle_time = kr_now() - s->last_activity;
		if (idle_time < idle_in_timeout) {
			idle_in_timeout -= idle_time;
			session2_timer_stop(s);
			session2_timer_start(s, PROTOLAYER_EVENT_GENERAL_TIMEOUT,
					idle_in_timeout, idle_in_timeout);
		} else {
			struct sockaddr *peer = session2_get_peer(s);
			char *peer_str = kr_straddr(peer);
			kr_log_debug(IO, "=> closing connection to '%s'\n",
				       peer_str ? peer_str : "");
			worker_del_tcp_waiting(peer);
			worker_del_tcp_connected(peer);
			session2_close(s);
		}
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_dns_stream_connected(
		struct session2 *session, struct pl_dns_stream_sess_data *stream)
{
	if (kr_fails_assert(!stream->connected))
		return PROTOLAYER_EVENT_PROPAGATE;

	stream->connected = true;

	struct sockaddr *peer = session2_get_peer(session);
	if (session->outgoing && worker_del_tcp_waiting(peer) != 0) {
		/* session isn't in list of waiting queries,
		 * something gone wrong */
		goto fail;
	}

	int err = worker_add_tcp_connected(peer, session);
	if (err) {
		/* Could not add session to the list of connected, something
		 * went wrong. */
		goto fail;
	}

	send_waiting(session);
	return PROTOLAYER_EVENT_PROPAGATE;

fail:
	session2_waitinglist_finalize(session, KR_STATE_FAIL);
	kr_assert(session2_tasklist_is_empty(session));
	session2_close(session);
	return PROTOLAYER_EVENT_CONSUME;
}

static enum protolayer_event_cb_result pl_dns_stream_connection_fail(
		struct session2 *session, enum kr_selection_error sel_err)
{
	session2_timer_stop(session);

	kr_assert(session2_tasklist_is_empty(session));

	struct sockaddr *peer = session2_get_peer(session);
	worker_del_tcp_waiting(peer);

	struct qr_task *task = session2_waitinglist_get(session);
	if (!task) {
		/* Normally shouldn't happen. */
		const char *peer_str = kr_straddr(peer);
		VERBOSE_MSG(NULL, "=> connection to '%s' failed, empty waitinglist\n",
			    peer_str ? peer_str : "");
		return PROTOLAYER_EVENT_PROPAGATE;
	}

	struct kr_query *qry = task_get_last_pending_query(task);
	if (kr_log_is_debug_qry(WORKER, qry)) {
		const char *peer_str = kr_straddr(peer);
		bool timeout = sel_err == KR_SELECTION_TCP_CONNECT_TIMEOUT;
		VERBOSE_MSG(qry, "=> connection to '%s' failed (%s)\n",
				peer_str ? peer_str : "",
				timeout ? "timeout" : "error");
	}

	if (qry)
		qry->server_selection.error(qry, task->transport, sel_err);

	the_worker->stats.timeout += session2_waitinglist_get_len(session);
	session2_waitinglist_retry(session, true);
	kr_assert(session2_tasklist_is_empty(session));
	/* uv_cancel() doesn't support uv_connect_t request,
	 * so that we can't cancel it.
	 * There still exists possibility of successful connection
	 * for this request.
	 * So connection callback (on_connect()) must check
	 * if connection is in the list of waiting connection.
	 * If no, most likely this is timed out connection even if
	 * it was successful. */

	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_dns_stream_disconnected(
		struct session2 *session, struct pl_dns_stream_sess_data *stream)
{
	struct sockaddr *peer = session2_get_peer(session);
	worker_del_tcp_waiting(peer);
	worker_del_tcp_connected(peer);

	if (!stream->connected)
		return PROTOLAYER_EVENT_PROPAGATE;

	stream->connected = false;

	if (session2_is_empty(session))
		return PROTOLAYER_EVENT_PROPAGATE;

	defer_sample_state_t defer_prev_sample_state;
	const bool use_recursive_defer_sampling = session->outgoing; // make linter warning silent
	if (use_recursive_defer_sampling)
		defer_sample_start(&defer_prev_sample_state);

	while (!session2_waitinglist_is_empty(session)) {
		struct qr_task *task = session2_waitinglist_pop(session, false);
		kr_assert(task->refs > 1);
		session2_tasklist_del(session, task);
		if (session->outgoing) {
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
			defer_sample_restart();  // use_recursive_defer_sampling == true
		} else {
			kr_assert(task->ctx->source.session == session);
			task->ctx->source.session = NULL;
		}
		worker_task_unref(task);
	}
	while (!session2_tasklist_is_empty(session)) {
		struct qr_task *task = session2_tasklist_del_first(session, false);
		if (session->outgoing) {
			if (task->ctx->req.options.FORWARD) {
				struct kr_request *req = &task->ctx->req;
				struct kr_rplan *rplan = &req->rplan;
				struct kr_query *qry = array_tail(rplan->pending);
				qry->flags.TCP = false;
			}
			qr_task_step(task, NULL, NULL);
			defer_sample_restart();
		} else {
			kr_assert(task->ctx->source.session == session);
			task->ctx->source.session = NULL;
		}
		worker_task_unref(task);
	}

	if (use_recursive_defer_sampling)
		defer_sample_stop(&defer_prev_sample_state, true);

	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_dns_stream_eof(
		struct session2 *session, struct pl_dns_stream_sess_data *stream)
{
	if (!session2_is_empty(session)) {
		stream->half_closed = true;
		return PROTOLAYER_EVENT_CONSUME;
	}
	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_dns_stream_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if (session->closing)
		return PROTOLAYER_EVENT_PROPAGATE;

	struct pl_dns_stream_sess_data *stream = sess_data;

	switch (event) {
	case PROTOLAYER_EVENT_GENERAL_TIMEOUT:
		return pl_dns_stream_resolution_timeout(session);

	case PROTOLAYER_EVENT_CONNECT_TIMEOUT:
		return pl_dns_stream_connection_fail(session,
				KR_SELECTION_TCP_CONNECT_TIMEOUT);

	case PROTOLAYER_EVENT_CONNECT:
		return pl_dns_stream_connected(session, stream);

	case PROTOLAYER_EVENT_CONNECT_FAIL:;
		enum kr_selection_error err = (*baton)
			? *(enum kr_selection_error *)baton
			: KR_SELECTION_TCP_CONNECT_FAILED;
		return pl_dns_stream_connection_fail(session, err);

	case PROTOLAYER_EVENT_DISCONNECT:
	case PROTOLAYER_EVENT_CLOSE:
	case PROTOLAYER_EVENT_FORCE_CLOSE:
		return pl_dns_stream_disconnected(session, stream);

	case PROTOLAYER_EVENT_EOF:
		return pl_dns_stream_eof(session, stream);

	default:
		return PROTOLAYER_EVENT_PROPAGATE;
	}
}

static knot_pkt_t *stream_produce_packet(struct session2 *session,
                                         struct wire_buf *wb,
                                         bool *out_err)
{
	*out_err = false;
	if (wire_buf_data_length(wb) == 0) {
		wire_buf_reset(wb);
		return NULL;
	}
	if (wire_buf_data_length(wb) < sizeof(uint16_t)) {
		return NULL;
	}

	uint16_t msg_len = knot_wire_read_u16(wire_buf_data(wb));
	if (msg_len == 0) {
		*out_err = true;
		session2_penalize(session);
		return NULL;
	}
	if (msg_len >= wb->size) {
		*out_err = true;
		session2_penalize(session);
		return NULL;
	}
	if (wire_buf_data_length(wb) < msg_len + sizeof(uint16_t)) {
		return NULL;
	}

	uint8_t *wire = (uint8_t *)wire_buf_data(wb) + sizeof(uint16_t);

	session->was_useful = true;
	knot_pkt_t *pkt = produce_packet(wire, msg_len);
	*out_err = (pkt == NULL);
	return pkt;
}

static int stream_discard_packet(struct session2 *session,
                                 struct wire_buf *wb,
                                 const knot_pkt_t *pkt,
                                 bool *out_err)
{
	*out_err = true;

	if (kr_fails_assert(wire_buf_data_length(wb) >= sizeof(uint16_t))) {
		wire_buf_reset(wb);
		return kr_error(EINVAL);
	}

	size_t msg_size = knot_wire_read_u16(wire_buf_data(wb));
	uint8_t *wire = (uint8_t *)wire_buf_data(wb) + sizeof(uint16_t);
	if (kr_fails_assert(msg_size + sizeof(uint16_t) <= wire_buf_data_length(wb))) {
		/* TCP message length field is greater then
		 * number of bytes in buffer, must not happen. */
		wire_buf_reset(wb);
		return kr_error(EINVAL);
	}

	if (kr_fails_assert(wire == pkt->wire)) {
		/* packet wirebuf must be located at the beginning
		 * of the session wirebuf, must not happen. */
		wire_buf_reset(wb);
		return kr_error(EINVAL);
	}

	if (kr_fails_assert(msg_size >= pkt->size)) {
		wire_buf_reset(wb);
		return kr_error(EINVAL);
	}

	wire_buf_trim(wb, msg_size + sizeof(uint16_t));
	*out_err = false;

	if (wire_buf_data_length(wb) == 0) {
		wire_buf_reset(wb);
	} else if (wire_buf_data_length(wb) < KNOT_WIRE_HEADER_SIZE) {
		wire_buf_movestart(wb);
	}

	return kr_ok();
}

static enum protolayer_iter_cb_result pl_dns_stream_unwrap(
		void *sess_data, void *iter_data, struct protolayer_iter_ctx *ctx)
{
	if (kr_fails_assert(ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF)) {
		/* DNS stream only works with a wire buffer */
		return protolayer_break(ctx, kr_error(EINVAL));
	}

	int status = kr_ok();
	struct session2 *session = ctx->session;
	struct pl_dns_stream_sess_data *stream_sess = sess_data;
	struct wire_buf *wb = ctx->payload.wire_buf;

	if (wire_buf_data_length(wb) == 0)
		return protolayer_break(ctx, status);

	const uint32_t max_iters = (wire_buf_data_length(wb) /
		(KNOT_WIRE_HEADER_SIZE + KNOT_WIRE_QUESTION_MIN_SIZE)) + 1;
	int iters = 0;

	bool pkt_error = false;
	knot_pkt_t *pkt = NULL;
	while ((pkt = stream_produce_packet(session, wb, &pkt_error)) && iters < max_iters) {
		if (kr_fails_assert(!pkt_error)) {
			status = kr_error(EINVAL);
			goto exit;
		}
		if (stream_sess->single && stream_sess->produced) {
			if (kr_log_is_debug(WORKER, NULL)) {
				kr_log_debug(WORKER, "Unexpected extra data from %s\n",
						kr_straddr(ctx->comm->src_addr));
			}
			status = KNOT_EMALF;
			goto exit;
		}

		stream_sess->produced = true;
		int ret = worker_submit(session, ctx->comm, pkt);

		/* Errors from worker_submit() are intentionally *not* handled
		 * in order to ensure the entire wire buffer is processed. */
		if (ret == kr_ok()) {
			iters += 1;
		}
		if (stream_discard_packet(session, wb, pkt, &pkt_error) < 0) {
			/* Packet data isn't stored in memory as expected.
			 * something went wrong, normally should not happen. */
			break;
		}
	}

	/* worker_submit() may cause the session to close (e.g. due to IO
	 * write error when the packet triggers an immediate answer). This is
	 * an error state, as well as any wirebuf error. */
	if (session->closing || pkt_error)
		status = kr_error(EIO);

exit:
	wire_buf_movestart(wb);
	mp_flush(the_worker->pkt_pool.ctx);
	if (status < 0)
		session2_force_close(session);
	return protolayer_break(ctx, status);
}

struct sized_iovs {
	uint8_t nlen[2];
	struct iovec iovs[];
};

static enum protolayer_iter_cb_result pl_dns_stream_wrap(
		void *sess_data, void *iter_data, struct protolayer_iter_ctx *ctx)
{
	if (ctx->payload.type == PROTOLAYER_PAYLOAD_BUFFER) {
		if (kr_fails_assert(ctx->payload.buffer.len <= UINT16_MAX))
			return protolayer_break(ctx, kr_error(EMSGSIZE));

		const int iovcnt = 2;
		struct sized_iovs *siov = mm_alloc(&ctx->pool,
				sizeof(*siov) + iovcnt * sizeof(struct iovec));
		kr_require(siov);
		knot_wire_write_u16(siov->nlen, ctx->payload.buffer.len);
		siov->iovs[0] = (struct iovec){
			.iov_base = &siov->nlen,
			.iov_len = sizeof(siov->nlen)
		};
		siov->iovs[1] = (struct iovec){
			.iov_base = ctx->payload.buffer.buf,
			.iov_len = ctx->payload.buffer.len
		};

		ctx->payload = protolayer_payload_iovec(siov->iovs, iovcnt, false);
		return protolayer_continue(ctx);
	} else if (ctx->payload.type == PROTOLAYER_PAYLOAD_IOVEC) {
		const int iovcnt = 1 + ctx->payload.iovec.cnt;
		struct sized_iovs *siov = mm_alloc(&ctx->pool,
				sizeof(*siov) + iovcnt * sizeof(struct iovec));
		kr_require(siov);

		size_t total_len = 0;
		for (int i = 0; i < ctx->payload.iovec.cnt; i++) {
			const struct iovec *iov = &ctx->payload.iovec.iov[i];
			total_len += iov->iov_len;
			siov->iovs[i + 1] = *iov;
		}

		if (kr_fails_assert(total_len <= UINT16_MAX))
			return protolayer_break(ctx, kr_error(EMSGSIZE));
		knot_wire_write_u16(siov->nlen, total_len);
		siov->iovs[0] = (struct iovec){
			.iov_base = &siov->nlen,
			.iov_len = sizeof(siov->nlen)
		};

		ctx->payload = protolayer_payload_iovec(siov->iovs, iovcnt, false);
		return protolayer_continue(ctx);
	} else {
		kr_assert(false && "Invalid payload");
		return protolayer_break(ctx, kr_error(EINVAL));
	}
}

static void pl_dns_stream_request_init(struct session2 *session,
                                       struct kr_request *req,
                                       void *sess_data)
{
	req->qsource.comm_flags.tcp = true;
}

__attribute__((constructor))
static void worker_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_DNS_DGRAM] = (struct protolayer_globals){
		.wire_buf_overhead_cb = pl_dns_dgram_wire_buf_overhead,
		.wire_buf_max_overhead = KNOT_WIRE_MAX_PKTSIZE,
		.unwrap = pl_dns_dgram_unwrap,
		.event_unwrap = pl_dns_dgram_event_unwrap
	};
	protolayer_globals[PROTOLAYER_TYPE_DNS_UNSIZED_STREAM] = (struct protolayer_globals){
		.sess_size = sizeof(struct pl_dns_stream_sess_data),
		.wire_buf_overhead = KNOT_WIRE_MAX_PKTSIZE,
		.sess_init = pl_dns_stream_sess_init,
		.unwrap = pl_dns_dgram_unwrap,
		.event_unwrap = pl_dns_stream_event_unwrap,
		.request_init = pl_dns_stream_request_init
	};
	const struct protolayer_globals stream_common = {
		.sess_size = sizeof(struct pl_dns_stream_sess_data),
		.wire_buf_overhead = KNOT_WIRE_MAX_PKTSIZE,
		.sess_init = NULL, /* replaced in specific layers below */
		.unwrap = pl_dns_stream_unwrap,
		.wrap = pl_dns_stream_wrap,
		.event_unwrap = pl_dns_stream_event_unwrap,
		.request_init = pl_dns_stream_request_init
	};
	protolayer_globals[PROTOLAYER_TYPE_DNS_MULTI_STREAM] = stream_common;
	protolayer_globals[PROTOLAYER_TYPE_DNS_MULTI_STREAM].sess_init = pl_dns_stream_sess_init;
	protolayer_globals[PROTOLAYER_TYPE_DNS_SINGLE_STREAM] = stream_common;
	protolayer_globals[PROTOLAYER_TYPE_DNS_SINGLE_STREAM].sess_init = pl_dns_single_stream_sess_init;
}

int worker_init(void)
{
	if (kr_fails_assert(the_worker == NULL))
		return kr_error(EINVAL);
	kr_bindings_register(the_engine->L); // TODO move

	/* Create main worker. */
	the_worker = &the_worker_value;
	memset(the_worker, 0, sizeof(*the_worker));

	uv_loop_t *loop = uv_default_loop();
	the_worker->loop = loop;

	/* Register table for worker per-request variables */
	struct lua_State *L = the_engine->L;
	lua_newtable(L);
	lua_setfield(L, -2, "vars");
	lua_getfield(L, -1, "vars");
	the_worker->vars_table_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_pop(L, 1);

	the_worker->tcp_pipeline_max = MAX_PIPELINED;
	the_worker->out_addr4.sin_family = AF_UNSPEC;
	the_worker->out_addr6.sin6_family = AF_UNSPEC;

	array_init(the_worker->doh_qry_headers);

	int ret = worker_reserve();
	if (ret) return ret;
	the_worker->next_request_uid = UINT16_MAX + 1;

	/* Set some worker.* fields in Lua */
	lua_getglobal(L, "worker");
	pid_t pid = getpid();

	auto_free char *pid_str = NULL;
	const char *inst_name = getenv("SYSTEMD_INSTANCE");
	if (inst_name) {
		lua_pushstring(L, inst_name);
	} else {
		ret = asprintf(&pid_str, "%ld", (long)pid);
		kr_assert(ret > 0);
		lua_pushstring(L, pid_str);
	}
	lua_setfield(L, -2, "id");

	lua_pushnumber(L, pid);
	lua_setfield(L, -2, "pid");

	char cwd[PATH_MAX];
	get_workdir(cwd, sizeof(cwd));
	lua_pushstring(L, cwd);
	lua_setfield(L, -2, "cwd");

	loop->data = the_worker;
	/* ^^^^ Now this shouldn't be used anymore, but it's hard to be 100% sure. */
	return kr_ok();
}

#undef VERBOSE_MSG
