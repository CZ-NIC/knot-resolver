/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "lib/utils.h"
#include "lib/layer.h"
#include "daemon/worker.h"
#include "daemon/engine.h"
#include "daemon/io.h"

/* @internal Union of various libuv objects for freelist. */
struct req
{
	union {
		/* Socket handles, these have session as their `handle->data` and own it. */
		uv_udp_t      udp;
		uv_tcp_t      tcp;
		/* I/O events, these have only a reference to the task they're operating on. */
		uv_udp_send_t send;
		uv_write_t    write;
		uv_connect_t  connect;
		/* Timer events */
		uv_timer_t    timer;
	} as;
};

/** @internal Debugging facility. */
#ifdef DEBUG
#define DEBUG_MSG(fmt...) printf("[daem] " fmt)
#else
#define DEBUG_MSG(fmt...)
#endif

/* Convenience macros */
#define qr_task_ref(task) \
	do { ++(task)->refs; } while(0)
#define qr_task_unref(task) \
	do { if (--(task)->refs == 0) { qr_task_free(task); } } while (0)
#define qr_valid_handle(task, checked) \
	(!uv_is_closing((checked)) || (task)->source.handle == (checked))

/* Forward decls */
static void qr_task_free(struct qr_task *task);
static int qr_task_step(struct qr_task *task, const struct sockaddr *packet_source, knot_pkt_t *packet);

/** @internal Get singleton worker. */
static inline struct worker_ctx *get_worker(void)
{
	return uv_default_loop()->data;
}

static inline struct req *req_borrow(struct worker_ctx *worker)
{
	struct req *req = NULL;
	if (worker->pool_ioreq.len > 0) {
		req = array_tail(worker->pool_ioreq);
		array_pop(worker->pool_ioreq);
		kr_asan_unpoison(req, sizeof(*req));
	} else {
		req = malloc(sizeof(*req));
	}
	return req;
}

static inline void req_release(struct worker_ctx *worker, struct req *req)
{
	if (!req || worker->pool_ioreq.len < 4 * MP_FREELIST_SIZE) {
		array_push(worker->pool_ioreq, req);
		kr_asan_poison(req, sizeof(*req));
	} else {
		free(req);
	}
}

/*! @internal Create a UDP/TCP handle */
static uv_handle_t *ioreq_spawn(struct qr_task *task, int socktype)
{
	if (task->pending_count >= MAX_PENDING) {
		return NULL;
	}
	/* Create connection for iterative query */
	uv_handle_t *handle = (uv_handle_t *)req_borrow(task->worker);
	if (!handle) {
		return NULL;
	}
	io_create(task->worker->loop, handle, socktype);
	/* Set current handle as a subrequest type. */
	struct session *session = handle->data;
	session->outgoing = true;
	int ret = array_push(session->tasks, task);
	if (ret < 0) {
		io_deinit(handle);
		req_release(task->worker, (struct req *)handle);
		return NULL;
	}
	qr_task_ref(task);
	/* Connect or issue query datagram */
	task->pending[task->pending_count] = handle;
	task->pending_count += 1;
	return handle;
}

static void ioreq_on_close(uv_handle_t *handle)
{
	struct worker_ctx *worker = get_worker();
	/* Handle-type events own a session, must close it. */
	struct session *session = handle->data;
	struct qr_task *task = session->tasks.at[0];
	io_deinit(handle);
	qr_task_unref(task);
	req_release(worker, (struct req *)handle);
}

static void ioreq_kill(uv_handle_t *req)
{
	assert(req);
	if (!uv_is_closing(req)) {
		uv_close(req, ioreq_on_close);
	}
}

static void ioreq_killall(struct qr_task *task)
{
	for (size_t i = 0; i < task->pending_count; ++i) {
		ioreq_kill(task->pending[i]);
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

static inline struct mempool *pool_borrow(struct worker_ctx *worker)
{
	/* Recycle available mempool if possible */
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

static inline void pool_release(struct worker_ctx *worker, struct mempool *mp)
{
	/* Return mempool to ring or free it if it's full */
	if (worker->pool_mp.len < MP_FREELIST_SIZE) {
		mp_flush(mp);
		array_push(worker->pool_mp, mp);
		mp_poison(mp, 1);
	} else {
		mp_delete(mp);
	}
}

/** @internal Get key from current outgoing subrequest. */
static int subreq_key(char *dst, knot_pkt_t *pkt)
{
	assert(pkt);
	return kr_rrkey(dst, knot_pkt_qname(pkt), knot_pkt_qtype(pkt), knot_pkt_qclass(pkt));
}

static struct qr_task *qr_task_create(struct worker_ctx *worker, uv_handle_t *handle, const struct sockaddr *addr)
{
	/* How much can client handle? */
	struct engine *engine = worker->engine;
	size_t pktbuf_max = KR_EDNS_PAYLOAD;
	if (engine->resolver.opt_rr) {
		pktbuf_max = MAX(knot_edns_get_payload(engine->resolver.opt_rr), pktbuf_max);
	}

	/* Recycle available mempool if possible */
	knot_mm_t pool = {
		.ctx = pool_borrow(worker),
		.alloc = (knot_mm_alloc_t) mp_alloc
	};

	/* Create resolution task */
	struct qr_task *task = mm_alloc(&pool, sizeof(*task));
	if (!task) {
		mp_delete(pool.ctx);
		return NULL;
	}
	/* Create packet buffers for answer and subrequests */
	task->req.pool = pool;
	knot_pkt_t *pktbuf = knot_pkt_new(NULL, pktbuf_max, &task->req.pool);
	if (!pktbuf) {
		mp_delete(pool.ctx);
		return NULL;
	}
	pktbuf->size = 0;
	task->req.answer = NULL;
	task->pktbuf = pktbuf;
	array_init(task->waiting);
	task->addrlist = NULL;
	task->pending_count = 0;
	task->bytes_remaining = 0;
	task->iter_count = 0;
	task->timeouts = 0;
	task->refs = 1;
	task->finished = false;
	task->leading = false;
	task->worker = worker;
	task->session = NULL;
	task->source.handle = handle;
	task->timeout = NULL;
	task->on_complete = NULL;
	task->req.qsource.key = NULL;
	task->req.qsource.addr = NULL;
	/* Remember query source addr */
	if (addr) {
		size_t addr_len = sizeof(struct sockaddr_in);
		if (addr->sa_family == AF_INET6)
			addr_len = sizeof(struct sockaddr_in6);
		memcpy(&task->source.addr, addr, addr_len);
		task->req.qsource.addr = (const struct sockaddr *)&task->source.addr;
	} else {
		task->source.addr.ip4.sin_family = AF_UNSPEC;
	}
	worker->stats.concurrent += 1;
	return task;
}

/* This is called when the task refcount is zero, free memory. */
static void qr_task_free(struct qr_task *task)
{
	struct session *session = task->session;
	if (session) {
		/* Walk the session task list and remove itself. */
		for (size_t i = 0; i < session->tasks.len; ++i) {
			if (session->tasks.at[i] == task) {
				array_del(session->tasks, i);
				break;		
			}
		}
		/* Start reading again if the session is throttled and
		 * the number of outgoing requests is below watermark. */
		uv_handle_t *handle = task->source.handle;
		if (handle && session->tasks.len < task->worker->tcp_pipeline_max/2) {
			if (!uv_is_closing(handle) && session->throttled) {
				io_start_read(handle);
				session->throttled = false;
			}
		}
	}
	/* Update stats */
	struct worker_ctx *worker = task->worker;
	worker->stats.concurrent -= 1;
	/* Return mempool to ring or free it if it's full */
	pool_release(worker, task->req.pool.ctx);
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
}

static int qr_task_start(struct qr_task *task, knot_pkt_t *query)
{
	assert(task && query);
	size_t answer_max = KNOT_WIRE_MIN_PKTSIZE;
	if (!task->source.handle || task->source.handle->type == UV_TCP) {
		answer_max = KNOT_WIRE_MAX_PKTSIZE;
	} else if (knot_pkt_has_edns(query)) { /* EDNS */
		answer_max = MAX(knot_edns_get_payload(query->opt_rr), KNOT_WIRE_MIN_PKTSIZE);
	}

	knot_pkt_t *answer = knot_pkt_new(NULL, answer_max, &task->req.pool);
	if (!answer) {
		return kr_error(ENOMEM);
	}
	task->req.answer = answer;

	/* Remember query source TSIG key */
	if (query->tsig_rr) {
		task->req.qsource.key = knot_rrset_copy(query->tsig_rr, &task->req.pool);
	}

	/* Start resolution */
	struct worker_ctx *worker = task->worker;
	struct engine *engine = worker->engine;
	kr_resolve_begin(&task->req, &engine->resolver, answer);
	worker->stats.queries += 1;
	/* Throttle outbound queries only when high pressure */
	if (worker->stats.concurrent < QUERY_RATE_THRESHOLD) {
		task->req.options |= QUERY_NO_THROTTLE;
	}
	/* Track outstanding inbound queries as well for deduplication. */
	char key[KR_RRKEY_LEN];
	if (subreq_key(key, query) > 0) {
		map_set(&task->worker->outstanding, key, task);
	}
	return 0;
}

/*@ Register qr_task within session. */
static int qr_task_register(struct qr_task *task, struct session *session)
{
	int ret = array_reserve(session->tasks, session->tasks.len + 1);
	if (ret != 0) {
		return kr_error(ENOMEM);
	}
	array_push(session->tasks, task);
	task->session = session;
	/* Soft-limit on parallel queries, there is no "slow down" RCODE
	 * that we could use to signalize to client, but we can stop reading,
	 * an in effect shrink TCP window size. To get more precise throttling,
	 * we would need to copy remainder of the unread buffer and reassemble
	 * when resuming reading. This is NYI.  */
	if (session->tasks.len >= task->worker->tcp_pipeline_max) {
		uv_handle_t *handle = task->source.handle;
		if (handle && !session->throttled && !uv_is_closing(handle)) {
			io_stop_read(handle);
			session->throttled = true;
		}
	}
	return 0;
}

static void qr_task_complete(struct qr_task *task)
{
	struct worker_ctx *worker = task->worker;
	/* Kill pending I/O requests */
	ioreq_killall(task);
	assert(task->waiting.len == 0);
	assert(task->leading == false);
	/* Run the completion callback. */
	if (task->on_complete) {
		task->on_complete(worker, &task->req, task->baton);
	}
	char key[KR_RRKEY_LEN];
	/* Clear outstanding query. */
	int ret = subreq_key(key, task->req.answer);
	if (ret > 0) {
		map_del(&task->worker->outstanding, key);
	}
	/* Release primary reference to task. */
	qr_task_unref(task);
}

/* This is called when we send subrequest / answer */
static int qr_task_on_send(struct qr_task *task, uv_handle_t *handle, int status)
{
	if (!task->finished) {
		if (status == 0 && handle) {
			io_start_read(handle); /* Start reading new query */
		}
	} else {
		assert(task->timeout == NULL);
		qr_task_complete(task);
	}
	return status;
}

static void on_send(uv_udp_send_t *req, int status)
{
	struct worker_ctx *worker = get_worker();
	struct qr_task *task = req->data;
	if (qr_valid_handle(task, (uv_handle_t *)req->handle)) {
		qr_task_on_send(task, (uv_handle_t *)req->handle, status);
	}
	qr_task_unref(task);
	req_release(worker, (struct req *)req);
}

static void on_write(uv_write_t *req, int status)
{
	struct worker_ctx *worker = get_worker();
	struct qr_task *task = req->data;
	if (qr_valid_handle(task, (uv_handle_t *)req->handle)) {
		qr_task_on_send(task, (uv_handle_t *)req->handle, status);
	}
	qr_task_unref(task);
	req_release(worker, (struct req *)req);
}

static int qr_task_send(struct qr_task *task, uv_handle_t *handle, struct sockaddr *addr, knot_pkt_t *pkt)
{
	if (!handle) {
		return qr_task_on_send(task, handle, kr_error(EIO));
	}
	struct req *send_req = req_borrow(task->worker);
	if (!send_req) {
		return qr_task_on_send(task, handle, kr_error(ENOMEM));
	}

	/* Send using given protocol */
	int ret = 0;
	if (handle->type == UV_UDP) {
		uv_buf_t buf = { (char *)pkt->wire, pkt->size };
		send_req->as.send.data = task;
		ret = uv_udp_send(&send_req->as.send, (uv_udp_t *)handle, &buf, 1, addr, &on_send);
	} else {
		uint16_t pkt_size = htons(pkt->size);
		uv_buf_t buf[2] = {
			{ (char *)&pkt_size, sizeof(pkt_size) },
			{ (char *)pkt->wire, pkt->size }
		};
		send_req->as.write.data = task;
		ret = uv_write(&send_req->as.write, (uv_stream_t *)handle, buf, 2, &on_write);
	}
	if (ret == 0) {
		qr_task_ref(task); /* Pending ioreq on current task */
	} else {
		req_release(task->worker, send_req);
	}

	/* Update statistics */
	if (handle != task->source.handle && addr) {
		if (handle->type == UV_UDP)
			task->worker->stats.udp += 1;
		else
			task->worker->stats.tcp += 1;
		if (addr->sa_family == AF_INET6)
			task->worker->stats.ipv6 += 1;
		else
			task->worker->stats.ipv4 += 1;
	}
	return ret;
}

static void on_connect(uv_connect_t *req, int status)
{
	struct worker_ctx *worker = get_worker();
	struct qr_task *task = req->data;
	uv_stream_t *handle = req->handle;
	if (qr_valid_handle(task, (uv_handle_t *)req->handle)) {
		if (status == 0) {
			qr_task_send(task, (uv_handle_t *)handle, task->addrlist, task->pktbuf);
		} else {
			qr_task_step(task, task->addrlist, NULL);
		}
	}
	qr_task_unref(task);
	req_release(worker, (struct req *)req);
}

static void on_timer_close(uv_handle_t *handle)
{
	struct qr_task *task = handle->data;
	req_release(task->worker, (struct req *)handle);
	qr_task_unref(task);
}

/* This is called when I/O timeouts */
static void on_timeout(uv_timer_t *req)
{
	struct qr_task *task = req->data;

	/* Penalize all tried nameservers with a timeout. */
	struct worker_ctx *worker = task->worker;
	if (task->leading && task->pending_count > 0) {
		struct kr_query *qry = array_tail(task->req.rplan.pending);
		struct sockaddr_in6 *addrlist = (struct sockaddr_in6 *)task->addrlist;
		for (uint16_t i = 0; i < MIN(task->pending_count, task->addrlist_count); ++i) {
			struct sockaddr *choice = (struct sockaddr *)(&addrlist[i]);
			WITH_DEBUG {
				char addr_str[INET6_ADDRSTRLEN];
				inet_ntop(choice->sa_family, kr_inaddr(choice), addr_str, sizeof(addr_str));
				QRDEBUG(qry, "wrkr", "=> server: '%s' flagged as 'bad'\n", addr_str);
			}
			kr_nsrep_update_rtt(&qry->ns, choice, KR_NS_TIMEOUT,
					    worker->engine->resolver.cache_rtt, KR_NS_UPDATE);
		}
	}
	/* Release timer handle */
	task->timeout = NULL;
	req_release(worker, (struct req *)req);
	/* Interrupt current pending request. */
	task->timeouts += 1;
	worker->stats.timeout += 1;
	qr_task_step(task, NULL, NULL);
	qr_task_unref(task); /* Return borrowed task */
}

static bool retransmit(struct qr_task *task)
{
	if (task && task->addrlist && task->addrlist_count > 0) {
		uv_handle_t *subreq = ioreq_spawn(task, SOCK_DGRAM);
		if (subreq) { /* Create connection for iterative query */
			struct sockaddr_in6 *choice = &((struct sockaddr_in6 *)task->addrlist)[task->addrlist_turn];
			if (qr_task_send(task, subreq, (struct sockaddr *)choice, task->pktbuf) == 0) {
				task->addrlist_turn = (task->addrlist_turn + 1) % task->addrlist_count; /* Round robin */
				return true;
			}
		}
	}
	return false;
}

static void on_retransmit(uv_timer_t *req)
{
	uv_timer_stop(req);
	struct qr_task *task = req->data;
	if (!retransmit(req->data)) {
		/* Not possible to spawn request, start timeout timer with remaining deadline. */
		uint64_t timeout = KR_CONN_RTT_MAX - task->pending_count * KR_CONN_RETRY;
		uv_timer_start(req, on_timeout, timeout, 0);
	} else {
		uv_timer_start(req, on_retransmit, KR_CONN_RETRY, 0);
	}
}

static int timer_start(struct qr_task *task, uv_timer_cb cb, uint64_t timeout, uint64_t repeat)
{
	assert(task->timeout == NULL);
	struct worker_ctx *worker = task->worker;
	uv_timer_t *timer = (uv_timer_t *)req_borrow(worker);
	if (!timer) {
		return kr_error(ENOMEM);
	}
	uv_timer_init(worker->loop, timer);
	int ret = uv_timer_start(timer, cb, timeout, repeat);
	if (ret != 0) {
		uv_timer_stop(timer);
		req_release(worker, (struct req *)timer);
		return kr_error(ENOMEM);
	}
	timer->data = task;
	qr_task_ref(task);
	task->timeout = timer;
	return 0;
}

static void subreq_finalize(struct qr_task *task, const struct sockaddr *packet_source, knot_pkt_t *pkt)
{
	/* Close pending timer */
	if (task->timeout) {
		/* Timer was running so it holds reference to task, make sure the timer event
		 * never fires and release the reference on timer close instead. */
		uv_timer_stop(task->timeout);
		uv_close((uv_handle_t *)task->timeout, on_timer_close);
		task->timeout = NULL;
	}
	ioreq_killall(task);
	/* Clear from outgoing table. */
	if (!task->leading)
		return;
	char key[KR_RRKEY_LEN];
	int ret = subreq_key(key, task->pktbuf);
	if (ret > 0) {
		assert(map_get(&task->worker->outgoing, key) == task);
		map_del(&task->worker->outgoing, key);
	}
	/* Notify waiting tasks. */
	struct kr_query *leader_qry = array_tail(task->req.rplan.pending);
	for (size_t i = task->waiting.len; i --> 0;) {
		struct qr_task *follower = task->waiting.at[i];
		struct kr_query *qry = array_tail(follower->req.rplan.pending);
		/* Reuse MSGID and 0x20 secret */
		if (qry) {
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
	char key[KR_RRKEY_LEN];
	if (subreq_key(key, task->pktbuf) > 0) {
		assert(map_contains(&task->worker->outgoing, key) == false);
		map_set(&task->worker->outgoing, key, task);
		task->leading = true;
	}
}

static bool subreq_enqueue(struct qr_task *task)
{
	assert(task);
	char key[KR_RRKEY_LEN];
	if (subreq_key(key, task->pktbuf) > 0) {
		struct qr_task *leader = map_get(&task->worker->outgoing, key);
		if (leader) {
			/* Enqueue itself to leader for this subrequest. */
			int ret = array_reserve_mm(leader->waiting, leader->waiting.len + 1, kr_memreserve, &leader->req.pool);
			if (ret == 0) {
				array_push(leader->waiting, task);
				qr_task_ref(task);
				return true;
			}
		}
	}
	return false;
}

static int qr_task_finalize(struct qr_task *task, int state)
{
	assert(task && task->leading == false);
	kr_resolve_finish(&task->req, state);
	task->finished = true;
	/* Send back answer */
	(void) qr_task_send(task, task->source.handle, (struct sockaddr *)&task->source.addr, task->req.answer);
	return state == KNOT_STATE_DONE ? 0 : kr_error(EIO);
}

static int qr_task_step(struct qr_task *task, const struct sockaddr *packet_source, knot_pkt_t *packet)
{
	/* No more steps after we're finished. */
	if (!task || task->finished) {
		return kr_error(ESTALE);
	}
	/* Close pending I/O requests */
	subreq_finalize(task, packet_source, packet);
	/* Consume input and produce next query */
	int sock_type = -1;
	task->addrlist = NULL;
	task->addrlist_count = 0;
	task->addrlist_turn = 0;
	int state = kr_resolve_consume(&task->req, packet_source, packet);
	while (state == KNOT_STATE_PRODUCE) {
		state = kr_resolve_produce(&task->req, &task->addrlist, &sock_type, task->pktbuf);
		if (unlikely(++task->iter_count > KR_ITER_LIMIT || task->timeouts >= KR_TIMEOUT_LIMIT)) {
			return qr_task_finalize(task, KNOT_STATE_FAIL);
		}
	}

	/* We're done, no more iterations needed */
	if (state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
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
		if (retransmit(task)) {
			ret = timer_start(task, on_retransmit, KR_CONN_RETRY, 0);
		} else {
			return qr_task_step(task, NULL, NULL);
		}
		/* Announce and start subrequest.
		 * @note Only UDP can lead I/O as it doesn't touch 'task->pktbuf' for reassembly.
		 */
		subreq_lead(task);
	} else {
		uv_connect_t *conn = (uv_connect_t *)req_borrow(task->worker);
		if (!conn) {
			return qr_task_step(task, NULL, NULL);
		}
		uv_handle_t *client = ioreq_spawn(task, sock_type);
		if (!client) {
			req_release(task->worker, (struct req *)conn);
			return qr_task_step(task, NULL, NULL);
		}
		conn->data = task;
		if (uv_tcp_connect(conn, (uv_tcp_t *)client, task->addrlist, on_connect) != 0) {
			req_release(task->worker, (struct req *)conn);
			return qr_task_step(task, NULL, NULL);
		}
		qr_task_ref(task); /* Connect request borrows task */
		ret = timer_start(task, on_timeout, KR_CONN_RTT_MAX, 0);
	}

	/* Start next step with timeout, fatal if can't start a timer. */
	if (ret != 0) {
		subreq_finalize(task, packet_source, packet);
		return qr_task_finalize(task, KNOT_STATE_FAIL);
	}
	return 0;
}

static int parse_packet(knot_pkt_t *query)
{
	if (!query){
		return kr_error(EINVAL);
	}

	/* Parse query packet. */
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK) {
		return kr_error(EPROTO); /* Ignore malformed query. */
	}

	/* Check if at least header is parsed. */
	if (query->parsed < query->size) {
		return kr_error(EMSGSIZE);
	}

	return kr_ok();
}

int worker_submit(struct worker_ctx *worker, uv_handle_t *handle, knot_pkt_t *msg, const struct sockaddr* addr)
{
	if (!worker || !handle) {
		return kr_error(EINVAL);
	}

	struct session *session = handle->data;
	assert(session);

	/* Parse packet */
	int ret = parse_packet(msg);

	/* Start new task on listening sockets, or resume if this is subrequest */
	struct qr_task *task = NULL;
	if (!session->outgoing) {
		/* Ignore badly formed queries or responses. */
		if (!msg || ret != 0 || knot_wire_get_qr(msg->wire)) {
			if (msg) worker->stats.dropped += 1;
			return kr_error(EINVAL); /* Ignore. */
		}
		/* De-duplicate inbound requests.
		 * Many clients do frequent retransmits of the query
		 * in order to avoid network losses and get better service,
		 * but fail to work properly when resolver answers them all
		 * but some of them SERVFAIL because of the time limit and some
		 * of them succeed. It's also a good idea to avoid wasting time
		 * tracking pending tasks to solve the same thing. */
		char key[KR_RRKEY_LEN];
		if (subreq_key(key, msg) > 0) {
			struct qr_task *task = map_get(&worker->outstanding, key);
			if (task && task->source.handle == handle && task->req.qsource.addr &&
				addr->sa_family == task->source.addr.ip4.sin_family &&
				knot_wire_get_id(msg->wire) == knot_wire_get_id(task->req.answer->wire)) {
				/* Query probably matches, check if it comes from the same origin. */
				size_t addr_len = sizeof(struct sockaddr_in);
				if (addr->sa_family == AF_INET6)
					addr_len = sizeof(struct sockaddr_in6);
				if (memcmp(&task->source.addr, addr, addr_len) == 0) {
					return kr_error(EEXIST); /* Ignore query */
				}
			}
		}
		task = qr_task_create(worker, handle, addr);
		if (!task) {
			return kr_error(ENOMEM);
		}
		ret = qr_task_start(task, msg);
		if (ret != 0) {
			qr_task_free(task);
			return kr_error(ENOMEM);
		}
	} else {
		task = session->tasks.len > 0 ? array_tail(session->tasks) : NULL;
	}

	/* Consume input and produce next message */
	return qr_task_step(task, addr, msg);
}

/* Return DNS/TCP message size. */
static int msg_size(const uint8_t *msg)
{
		return wire_read_u16(msg);
}

/* If buffering, close last task as it isn't live yet. */
static void discard_buffered(struct session *session)
{
	if (session->buffering) {
		qr_task_free(session->buffering);
		session->buffering = NULL;
	}
}

int worker_end_tcp(struct worker_ctx *worker, uv_handle_t *handle)
{
	if (!worker || !handle) {
		return kr_error(EINVAL);
	}
	/* If this is subrequest, notify parent task with empty input
	 * because in this case session doesn't own tasks, it has just
	 * borrowed the task from parent session. */
	struct session *session = handle->data;
	if (session->outgoing) {
		worker_submit(worker, (uv_handle_t *)handle, NULL, NULL);	
	} else {
		discard_buffered(session);
	}
	return 0;
}

int worker_process_tcp(struct worker_ctx *worker, uv_handle_t *handle, const uint8_t *msg, ssize_t len)
{
	if (!worker || !handle) {
		return kr_error(EINVAL);
	}
	/* Connection error or forced disconnect */
	struct session *session = handle->data;
	if (len <= 0 || !msg) {
		/* If we have pending tasks, we must dissociate them from the
		 * connection so they don't try to access closed and freed handle.
		 * @warning Do not modify task if this is outgoing request as it is shared with originator.
		 */
		if (!session->outgoing) {
			for (size_t i = 0; i < session->tasks.len; ++i) {
				struct qr_task *task = session->tasks.at[i];
				task->session = NULL;
				task->source.handle = NULL;
			}
			session->tasks.len = 0;
		}
		return kr_error(ECONNRESET);
	}

	int submitted = 0;
	ssize_t nbytes = 0;
	struct qr_task *task = session->buffering;

	/* If this is a new query, create a new task that we can use
	 * to buffer incoming message until it's complete. */
	if (!session->outgoing) {
		if (!task) {
			task = qr_task_create(worker, handle, NULL);
			if (!task) {
				return kr_error(ENOMEM);
			}
			session->buffering = task;
		}
	} else {
		assert(session->tasks.len > 0);
		task = array_tail(session->tasks);
	}
	/* At this point session must have either created new task or it's already assigned. */
	assert(task);
	assert(len > 0);
	/* Start reading DNS/TCP message length */
	knot_pkt_t *pkt_buf = task->pktbuf;
	if (task->bytes_remaining == 0 && pkt_buf->size == 0) {
		knot_pkt_clear(pkt_buf);
		/* Read only one byte as TCP fragment may end at a 1B boundary
		 * which would lead to OOB read or improper reassembly length. */
		pkt_buf->size = 1;
		pkt_buf->wire[0] = msg[0];
		len -= 1;
		msg += 1;
		if (len == 0) {
			return 0;
		}
	}
	/* Finish reading DNS/TCP message length. */
	if (task->bytes_remaining == 0 && pkt_buf->size == 1) {
		pkt_buf->wire[1] = msg[0];
		nbytes = msg_size(pkt_buf->wire);
		len -= 1;
		msg += 1;
		/* Cut off fragment length and start reading DNS message. */
		pkt_buf->size = 0;
		task->bytes_remaining = nbytes;
	}
	/* Message is too long, can't process it. */
	ssize_t to_read = MIN(len, task->bytes_remaining);
	if (pkt_buf->size + to_read > pkt_buf->max_size) {
		pkt_buf->size = 0;
		task->bytes_remaining = 0;
		return kr_error(EMSGSIZE);
	}
	/* Buffer message and check if it's complete */
	memcpy(pkt_buf->wire + pkt_buf->size, msg, to_read);
	pkt_buf->size += to_read;
	if (to_read >= task->bytes_remaining) {
		task->bytes_remaining = 0;
		/* Parse the packet and start resolving complete query */
		int ret = parse_packet(pkt_buf);
		if (ret == 0 && !session->outgoing) {
			ret = qr_task_start(task, pkt_buf);
			if (ret != 0) {
				return ret;
			}
			ret = qr_task_register(task, session);
			if (ret != 0) {
				return ret;
			}
			/* Task is now registered in session, clear temporary. */
			session->buffering = NULL;
			submitted += 1;
		}
		/* Start only new queries, not subrequests that are already pending */
		if (ret == 0) {
			ret = qr_task_step(task, NULL, pkt_buf);
		}
		/* Process next message part in the stream if no error so far */
		if (ret != 0) {
			return ret;
		}
		if (len - to_read > 0 && !session->outgoing) {
			ret = worker_process_tcp(worker, handle, msg + to_read, len - to_read);
			if (ret < 0) {
				return ret;
			}
			submitted += ret;
		}
	} else {
		task->bytes_remaining -= to_read;	
	}
	return submitted;
}

int worker_resolve(struct worker_ctx *worker, knot_pkt_t *query, unsigned options, worker_cb_t on_complete, void *baton)
{
	if (!worker || !query) {
		return kr_error(EINVAL);
	}

	/* Create task */
	struct qr_task *task = qr_task_create(worker, NULL, NULL);
	if (!task) {
		return kr_error(ENOMEM);
	}
	task->baton = baton;
	task->on_complete = on_complete;
	task->req.options |= options;
	/* Start task */
	int ret = qr_task_start(task, query);
	if (ret != 0) {
		qr_task_unref(task);
		return ret;
	}
	return qr_task_step(task, NULL, query);
}

int worker_reserve(struct worker_ctx *worker, size_t ring_maxlen)
{
	array_init(worker->pool_mp);
	array_init(worker->pool_ioreq);
	array_init(worker->pool_sessions);
	if (array_reserve(worker->pool_mp, ring_maxlen) ||
		array_reserve(worker->pool_ioreq, ring_maxlen) ||
		array_reserve(worker->pool_sessions, ring_maxlen))
		return kr_error(ENOMEM);
	memset(&worker->pkt_pool, 0, sizeof(worker->pkt_pool));
	worker->pkt_pool.ctx = mp_new (4 * sizeof(knot_pkt_t));
	worker->pkt_pool.alloc = (knot_mm_alloc_t) mp_alloc;
	worker->outgoing = map_make();
	worker->outstanding = map_make();
	worker->tcp_pipeline_max = MAX_PIPELINED;
	return kr_ok();
}

#define reclaim_freelist(list, type, cb) \
	for (unsigned i = 0; i < list.len; ++i) { \
		type *elm = list.at[i]; \
		kr_asan_unpoison(elm, sizeof(type)); \
		cb(elm); \
	} \
	array_clear(list)

void worker_reclaim(struct worker_ctx *worker)
{
	reclaim_freelist(worker->pool_mp, struct mempool, mp_delete);
	reclaim_freelist(worker->pool_ioreq, struct req, free);
	reclaim_freelist(worker->pool_sessions, struct session, session_free);
	mp_delete(worker->pkt_pool.ctx);
	worker->pkt_pool.ctx = NULL;
	map_clear(&worker->outgoing);
	map_clear(&worker->outstanding);
}

#undef DEBUG_MSG
