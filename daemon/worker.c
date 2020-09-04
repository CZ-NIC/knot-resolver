/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "kresconfig.h"
#include "daemon/worker.h"

#include <uv.h>
#include <lua.h>
#include <lauxlib.h>
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

#include "daemon/bindings/api.h"
#include "daemon/engine.h"
#include "daemon/io.h"
#include "daemon/session.h"
#include "daemon/tls.h"
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

#define VERBOSE_MSG(qry, ...) QRVERBOSE(qry, "wrkr", __VA_ARGS__)

/** Client request state. */
struct request_ctx
{
	struct kr_request req;

	struct {
		/** Requestor's address; separate because of UDP session "sharing". */
		union inaddr addr;
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
	do { \
		if (task) \
			assert((task)->refs > 0); \
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
static struct session* worker_find_tcp_connected(struct worker_ctx *worker,
						 const struct sockaddr *addr);
static int worker_add_tcp_waiting(struct worker_ctx *worker,
				  const struct sockaddr *addr,
				  struct session *session);
static struct session* worker_find_tcp_waiting(struct worker_ctx *worker,
					       const struct sockaddr *addr);
static void on_tcp_connect_timeout(uv_timer_t *timer);

struct worker_ctx the_worker_value; /**< Static allocation is suitable for the singleton. */
struct worker_ctx *the_worker = NULL;

/*! @internal Create a UDP/TCP handle for an outgoing AF_INET* connection.
 *  socktype is SOCK_* */
static uv_handle_t *ioreq_spawn(struct worker_ctx *worker,
				int socktype, sa_family_t family, bool has_tls)
{
	bool precond = (socktype == SOCK_DGRAM || socktype == SOCK_STREAM)
			&& (family == AF_INET  || family == AF_INET6);
	if (!precond) {
		assert(false);
		kr_log_verbose("[work] ioreq_spawn: pre-condition failed\n");
		return NULL;
	}

	/* Create connection for iterative query */
	uv_handle_t *handle = malloc(socktype == SOCK_DGRAM
					? sizeof(uv_udp_t) : sizeof(uv_tcp_t));
	if (!handle) {
		return NULL;
	}
	int ret = io_create(worker->loop, handle, socktype, family, has_tls);
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
					  struct session *session,
					  const struct sockaddr *peer,
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
	if (session) {
		assert(session_flags(session)->outgoing == false);
	}
	ctx->source.session = session;

	struct kr_request *req = &ctx->req;
	req->pool = pool;
	req->vars_ref = LUA_NOREF;
	req->uid = uid;
	if (session) {
		/* We assume the session will be alive during the whole life of the request. */
		req->qsource.dst_addr = session_get_sockname(session);
		req->qsource.flags.tcp = session_get_handle(session)->type == UV_TCP;
		req->qsource.flags.tls = session_flags(session)->has_tls;
		/* We need to store a copy of peer address. */
		memcpy(&ctx->source.addr.ip, peer, kr_sockaddr_len(peer));
		req->qsource.addr = &ctx->source.addr.ip;
	}

	worker->stats.rconcurrent += 1;

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
	if (knot_pkt_has_tsig(query)) {
		req->qsource.size += query->tsig_wire.len;
	}

	knot_pkt_t *answer = knot_pkt_new(NULL, answer_max, &req->pool);
	if (!answer) { /* Failed to allocate answer */
		return kr_error(ENOMEM);
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
	kr_resolve_begin(req, &engine->resolver, answer);
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
	worker->stats.rconcurrent -= 1;
}

static struct qr_task *qr_task_create(struct request_ctx *ctx)
{
	/* Choose (initial) pktbuf size.  As it is now, pktbuf can be used
	 * for UDP answers from upstream *and* from cache
	 * and for sending non-UDP queries upstream (?) */
	uint16_t pktbuf_max = KR_EDNS_PAYLOAD;
	const knot_rrset_t *opt_our = ctx->worker->engine->resolver.opt_rr;
	if (opt_our) {
		pktbuf_max = MAX(pktbuf_max, knot_edns_get_payload(opt_our));
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
int qr_task_on_send(struct qr_task *task, uv_handle_t *handle, int status)
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
			const struct sockaddr *addr, knot_pkt_t *pkt)
{
	if (!session) {
		return qr_task_on_send(task, NULL, kr_error(EIO));
	}

	int ret = 0;
	struct request_ctx *ctx = task->ctx;

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

static struct kr_query *task_get_last_pending_query(struct qr_task *task)
{
	if (!task || task->ctx->req.rplan.pending.len == 0) {
		return NULL;
	}

	return array_tail(task->ctx->req.rplan.pending);
}

static int session_tls_hs_cb(struct session *session, int status)
{
	assert(session_flags(session)->outgoing);
	struct sockaddr *peer = session_get_peer(session);
	int deletion_res = worker_del_tcp_waiting(the_worker, peer);
	int ret = kr_ok();

	if (status) {
		struct qr_task *task = session_waitinglist_get(session);
		if (task) {
			struct kr_qflags *options = &task->ctx->req.options;
			unsigned score = options->FORWARD || options->STUB ? KR_NS_FWD_DEAD : KR_NS_DEAD;
			kr_nsrep_update_rtt(NULL, peer, score,
					    the_worker->engine->resolver.cache_rtt,
					    KR_NS_UPDATE_NORESET);
		}
#ifndef NDEBUG
		else {
			/* Task isn't in the list of tasks
			 * waiting for connection to upstream.
			 * So that it MUST be unsuccessful rehandshake.
			 * Check it. */
			assert(deletion_res != 0);
			const char *key = tcpsess_key(peer);
			assert(key);
			assert(map_contains(&the_worker->tcp_connected, key) != 0);
		}
#endif
		return ret;
	}

	/* handshake was completed successfully */
	struct tls_client_ctx *tls_client_ctx = session_tls_get_client_ctx(session);
	tls_client_param_t *tls_params = tls_client_ctx->params;
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
		 * 2) or successful handshake with session, which was timeouted
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
	assert(worker);
	uv_stream_t *handle = req->handle;
	struct session *session = handle->data;
	struct sockaddr *peer = session_get_peer(session);
	free(req);

	assert(session_flags(session)->outgoing);

	if (session_flags(session)->closing) {
		worker_del_tcp_waiting(worker, peer);
		assert(session_is_empty(session));
		return;
	}

	/* Check if the connection is in the waiting list.
	 * If no, most likely this is timeouted connection
	 * which was removed from waiting list by
	 * on_tcp_connect_timeout() callback. */
	struct session *s = worker_find_tcp_waiting(worker, peer);
	if (!s || s != session) {
		/* session isn't on the waiting list.
		 * it's timeouted session. */
		if (VERBOSE_STATUS) {
			const char *peer_str = kr_straddr(peer);
			kr_log_verbose( "[wrkr]=> connected to '%s', but session "
					"is already timeouted, close\n",
					peer_str ? peer_str : "");
		}
		assert(session_tasklist_is_empty(session));
		session_waitinglist_retry(session, false);
		session_close(session);
		return;
	}

	s = worker_find_tcp_connected(worker, peer);
	if (s) {
		/* session already in the connected list.
		 * Something went wrong, it can be due to races when kresd has tried
		 * to reconnect to upstream after unsuccessful attempt. */
		if (VERBOSE_STATUS) {
			const char *peer_str = kr_straddr(peer);
			kr_log_verbose( "[wrkr]=> connected to '%s', but peer "
					"is already connected, close\n",
					peer_str ? peer_str : "");
		}
		assert(session_tasklist_is_empty(session));
		session_waitinglist_retry(session, false);
		session_close(session);
		return;
	}

	if (status != 0) {
		if (VERBOSE_STATUS) {
			const char *peer_str = kr_straddr(peer);
			kr_log_verbose( "[wrkr]=> connection to '%s' failed (%s), flagged as 'bad'\n",
					peer_str ? peer_str : "", uv_strerror(status));
		}
		worker_del_tcp_waiting(worker, peer);
		struct qr_task *task = session_waitinglist_get(session);
		if (task && status != UV_ETIMEDOUT) {
			/* Penalize upstream.
			 * In case of UV_ETIMEDOUT upstream has been
			 * already penalized in on_tcp_connect_timeout() */
			struct kr_qflags *options = &task->ctx->req.options;
			unsigned score = options->FORWARD || options->STUB ? KR_NS_FWD_DEAD : KR_NS_DEAD;
			kr_nsrep_update_rtt(NULL, peer, score,
					    worker->engine->resolver.cache_rtt,
					    KR_NS_UPDATE_NORESET);
		}
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

	if (VERBOSE_STATUS) {
		const char *peer_str = kr_straddr(peer);
		kr_log_verbose( "[wrkr]=> connected to '%s'\n", peer_str ? peer_str : "");
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
	assert(worker);

	assert (session_tasklist_is_empty(session));

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
	WITH_VERBOSE (qry) {
		const char *peer_str = kr_straddr(peer);
		VERBOSE_MSG(qry, "=> connection to '%s' failed (internal timeout)\n",
			    peer_str ? peer_str : "");
	}

	unsigned score = qry->flags.FORWARD || qry->flags.STUB ? KR_NS_FWD_DEAD : KR_NS_DEAD;
	kr_nsrep_update_rtt(NULL, peer, score,
			    worker->engine->resolver.cache_rtt,
			    KR_NS_UPDATE_NORESET);

	worker->stats.timeout += session_waitinglist_get_len(session);
	session_waitinglist_retry(session, true);
	assert (session_tasklist_is_empty(session));
	/* uv_cancel() doesn't support uv_connect_t request,
	 * so that we can't cancel it.
	 * There still exists possibility of successful connection
	 * for this request.
	 * So connection callback (on_connect()) must check
	 * if connection is in the list of waiting connection.
	 * If no, most likely this is timeouted connection even if
	 * it was successful. */
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
				char *addr_str = kr_straddr(choice);
				VERBOSE_MSG(qry, "=> server: '%s' flagged as 'bad'\n", addr_str ? addr_str : "");
			}
			unsigned score = qry->flags.FORWARD || qry->flags.STUB ? KR_NS_FWD_DEAD : KR_NS_DEAD;
			kr_nsrep_update_rtt(&qry->ns, choice, score,
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
		/* Checkout answer before sending it */
		struct request_ctx *ctx = task->ctx;
		if (kr_resolve_checkout(&ctx->req, NULL, (struct sockaddr *)choice, SOCK_DGRAM, task->pktbuf) != 0) {
			return ret;
		}
		ret = ioreq_spawn(ctx->worker, SOCK_DGRAM, choice->sin6_family, false);
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
		struct kr_qflags *options = &task->ctx->req.options;
		uint64_t timeout = options->FORWARD || options->STUB ? KR_NS_FWD_TIMEOUT / 2 :
				   KR_CONN_RTT_MAX - task->pending_count * KR_CONN_RETRY;
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

	if (session_flags(source_session)->closing ||
	    ctx->source.addr.ip.sa_family == AF_UNSPEC)
		return kr_error(EINVAL);

	/* Reference task as the callback handler can close it */
	qr_task_ref(task);

	/* Send back answer */
	int ret;
	const uv_handle_t *src_handle = session_get_handle(source_session);
	if (src_handle->type != UV_UDP && src_handle->type != UV_TCP) {
		assert(false);
		ret = kr_error(EINVAL);
	} else if (src_handle->type == UV_UDP && ENABLE_SENDMMSG) {
		int fd;
		ret = uv_fileno(src_handle, &fd);
		assert(!ret);
		if (ret == 0) {
			udp_queue_push(fd, &ctx->req, task);
		}
	} else {
		ret = qr_task_send(task, source_session, &ctx->source.addr.ip, ctx->req.answer);
	}

	if (ret != kr_ok()) {
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

	if (ret != kr_ok() || state != KR_STATE_DONE)
		return kr_error(EIO);
	return kr_ok();
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

static int tcp_task_waiting_connection(struct session *session, struct qr_task *task)
{
	assert(session_flags(session)->outgoing);
	if (session_flags(session)->closing) {
		/* Something went wrong. Better answer with KR_STATE_FAIL.
		 * TODO: normally should not happen,
		 * consider possibility to transform this into
		 * assert(!session_flags(session)->closing). */
		return kr_error(EINVAL);
	}
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
	assert(session_flags(session)->outgoing);
	struct request_ctx *ctx = task->ctx;
	struct worker_ctx *worker = ctx->worker;

	if (session_flags(session)->closing) {
		/* Something went wrong. Better answer with KR_STATE_FAIL.
		 * TODO: normally should not happen,
		 * consider possibility to transform this into
		 * assert(!session_flags(session)->closing). */
		return kr_error(EINVAL);
	}

	/* If there are any unsent queries, send it first. */
	int ret = send_waiting(session);
	if (ret != 0) {
		return kr_error(EINVAL);
	}

	/* No unsent queries at that point. */
	if (session_tasklist_get_len(session) >= worker->tcp_pipeline_max) {
		/* Too many outstanding queries, answer with SERFVAIL, */
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
	bool has_tls = (tls_ctx != NULL);
	uv_handle_t *client = ioreq_spawn(worker, SOCK_STREAM, addr->sa_family, has_tls);
	if (!client) {
		tls_client_ctx_free(tls_ctx);
		free(conn);
		return kr_error(EINVAL);
	}
	struct session *session = client->data;
	assert(session_flags(session)->has_tls == has_tls);
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
	WITH_VERBOSE (qry) {
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
		unsigned score = qry->flags.FORWARD || qry->flags.STUB ? KR_NS_FWD_DEAD : KR_NS_DEAD;
		kr_nsrep_update_rtt(NULL, peer, score,
				    worker->engine->resolver.cache_rtt,
				    KR_NS_UPDATE_NORESET);
		WITH_VERBOSE (qry) {
			const char *peer_str = kr_straddr(peer);
			kr_log_verbose( "[wrkr]=> connect to '%s' failed (%s), flagged as 'bad'\n",
					peer_str ? peer_str : "", uv_strerror(ret));
		}
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
	assert(task->pending_count == 0);

	/* target */
	const struct sockaddr *addr = task->addrlist;
	if (addr->sa_family == AF_UNSPEC) {
		/* Target isn't defined. Finalize task with SERVFAIL.
		 * Although task->pending_count is zero, there are can be followers,
		 * so we need to call subreq_finalize() to handle them properly. */
		subreq_finalize(task, packet_source, packet);
		return qr_task_finalize(task, KR_STATE_FAIL);
	}
	/* Checkout task before connecting */
	struct request_ctx *ctx = task->ctx;
	if (kr_resolve_checkout(&ctx->req, NULL, (struct sockaddr *)addr,
				SOCK_STREAM, task->pktbuf) != 0) {
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
		return qr_task_finalize(task, KR_STATE_FAIL);
	}

	/* Consume input and produce next query */
	struct request_ctx *ctx = task->ctx;
	assert(ctx);
	struct kr_request *req = &ctx->req;
	struct worker_ctx *worker = ctx->worker;
	int sock_type = -1;
	task->addrlist = NULL;
	task->addrlist_count = 0;
	task->addrlist_turn = 0;

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

			#ifndef NOVERBOSELOG
			struct kr_rplan *rplan = &req->rplan;
			struct kr_query *last  = kr_rplan_last(rplan);
			if (task->iter_count > KR_ITER_LIMIT) {
				VERBOSE_MSG(last, "canceling query due to exceeded iteration count limit of %d\n", KR_ITER_LIMIT);
			}
			if (task->timeouts >= KR_TIMEOUT_LIMIT) {
				VERBOSE_MSG(last, "canceling query due to exceeded timeout retries limit of %d\n", KR_TIMEOUT_LIMIT);
			}
			#endif

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

	/* Upgrade to TLS if the upstream address is configured as DoT capable. */
	if (task->addrlist_count > 0 && kr_inaddr_port(task->addrlist) == KR_DNS_PORT) {
		/* TODO if there are multiple addresses (task->addrlist_count > 1)
		 * check all of them. */
		struct network *net = &worker->engine->net;
		/* task->addrlist has to contain TLS port before tls_client_param_get() call */
		kr_inaddr_set_port(task->addrlist, KR_DNS_TLS_PORT);
		tls_client_param_t *tls_entry =
			tls_client_param_get(net->tls_client_params, task->addrlist);
		if (tls_entry) {
			packet_source = NULL;
			sock_type = SOCK_STREAM;
			/* TODO in this case in tcp_task_make_connection() will be performed
			 * redundant map_get() call. */
		} else {
			/* The function is fairly cheap, so we just change there and back. */
			kr_inaddr_set_port(task->addrlist, KR_DNS_PORT);
		}
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

int worker_submit(struct session *session, const struct sockaddr *peer, knot_pkt_t *query)
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

	/* Parse packet */
	int ret = parse_packet(query);

	const bool is_query = (knot_wire_get_qr(query->wire) == 0);
	const bool is_outgoing = session_flags(session)->outgoing;
	/* Ignore badly formed queries. */
	if (!query ||
	    (ret != kr_ok() && ret != kr_error(EMSGSIZE)) ||
	    (is_query == is_outgoing)) {
		if (query && !is_outgoing) the_worker->stats.dropped += 1;
		return kr_error(EILSEQ);
	}

	/* Start new task on listening sockets,
	 * or resume if this is subrequest */
	struct qr_task *task = NULL;
	const struct sockaddr *addr = NULL;
	if (!is_outgoing) { /* request from a client */
		struct request_ctx *ctx = request_create(the_worker, session, peer,
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
		const uint16_t id = knot_wire_get_id(query->wire);
		task = session_tasklist_del_msgid(session, id);
		if (task == NULL) {
			VERBOSE_MSG(NULL, "=> ignoring packet with mismatching ID %d\n",
					(int)id);
			return kr_error(ENOENT);
		}
		assert(!session_flags(session)->closing);
		addr = peer;
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

int worker_del_tcp_waiting(struct worker_ctx *worker,
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

knot_pkt_t * worker_resolve_mk_pkt(const char *qname_str, uint16_t qtype, uint16_t qclass,
				   const struct kr_qflags *options)
{
	uint8_t qname[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(qname, qname_str, sizeof(qname)))
		return NULL;
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_EDNS_MAX_UDP_PAYLOAD, NULL);
	if (!pkt)
		return NULL;
	knot_pkt_put_question(pkt, qname, qclass, qtype);
	knot_wire_set_rd(pkt->wire);
	knot_wire_set_ad(pkt->wire);

	/* Add OPT RR, including wire format so modules can see both representations.
	 * knot_pkt_put() copies the outside; we need to duplicate the inside manually. */
	knot_rrset_t *opt = knot_rrset_copy(the_worker->engine->resolver.opt_rr, NULL);
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

struct qr_task *worker_resolve_start(knot_pkt_t *query, struct kr_qflags options)
{
	struct worker_ctx *worker = the_worker;
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

	worker->pkt_pool.ctx = mp_new (4 * sizeof(knot_pkt_t));
	worker->pkt_pool.alloc = (knot_mm_alloc_t) mp_alloc;

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
	assert(worker);
	if (worker->z_import != NULL) {
		zi_free(worker->z_import);
		worker->z_import = NULL;
	}
	map_clear(&worker->tcp_connected);
	map_clear(&worker->tcp_waiting);
	trie_free(worker->subreq_out);
	worker->subreq_out = NULL;

	reclaim_mp_freelist(&worker->pool_mp);
	mp_delete(worker->pkt_pool.ctx);
	worker->pkt_pool.ctx = NULL;

	the_worker = NULL;
}

int worker_init(struct engine *engine, int worker_id, int worker_count)
{
	assert(engine && engine->L);
	assert(the_worker == NULL);
	kr_bindings_register(engine->L);

	/* Create main worker. */
	struct worker_ctx *worker = &the_worker_value;
	memset(worker, 0, sizeof(*worker));
	worker->engine = engine;

	uv_loop_t *loop = uv_default_loop();
	worker->loop = loop;

	worker->id = worker_id;
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

	int ret = worker_reserve(worker, MP_FREELIST_SIZE);
	if (ret) return ret;
	worker->next_request_uid = UINT16_MAX + 1;

	/* Set some worker.* fields in Lua */
	lua_getglobal(engine->L, "worker");
	lua_pushnumber(engine->L, worker_id);
	lua_setfield(engine->L, -2, "id");
	lua_pushnumber(engine->L, getpid());
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
