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
#include <contrib/ucw/lib.h>
#include <contrib/ucw/mempool.h>
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
#include <malloc.h>
#endif

#include "daemon/worker.h"
#include "daemon/engine.h"
#include "daemon/io.h"

/* @internal IO request entry. */
struct ioreq
{
	union {
		uv_udp_t      udp;
		uv_tcp_t      tcp;
		uv_udp_send_t send;
		uv_write_t    write;
		uv_connect_t  connect;
	} as;
};

static inline struct ioreq *ioreq_take(struct worker_ctx *worker)
{
	struct ioreq *req = NULL;
	if (worker->ioreqs.len > 0) {
		req = array_tail(worker->ioreqs);
		array_pop(worker->ioreqs);
	} else {
		req = malloc(sizeof(*req));
	}
	return req;
}

static inline void ioreq_release(struct worker_ctx *worker, struct ioreq *req)
{
	if (!req || worker->ioreqs.len < 4 * MP_FREELIST_SIZE) {
		array_push(worker->ioreqs, req);
	} else {
		free(req);
	}
}

/** @internal Query resolution task. */
struct qr_task
{
	struct kr_request req;
	struct worker_ctx *worker;
	knot_pkt_t *pktbuf;
	uv_req_t *ioreq;
	uv_handle_t *iohandle;
	uv_timer_t timeout;
	worker_cb_t on_complete;
	void *baton;
	struct {
		union {
			struct sockaddr_in ip4;
			struct sockaddr_in6 ip6;
		} addr;
		uv_handle_t *handle;
	} source;
	uint16_t iter_count;
	uint16_t flags;
};

/* Forward decls */
static int qr_task_step(struct qr_task *task, knot_pkt_t *packet);

/** @internal Get singleton worker. */
static inline struct worker_ctx *get_worker(void)
{
	return uv_default_loop()->data;
}

static struct qr_task *qr_task_create(struct worker_ctx *worker, uv_handle_t *handle, knot_pkt_t *query, const struct sockaddr *addr)
{
	/* How much can client handle? */
	size_t answer_max = KNOT_WIRE_MIN_PKTSIZE;
	size_t pktbuf_max = KR_EDNS_PAYLOAD;
	if (!addr && handle) { /* TCP */
		answer_max = KNOT_WIRE_MAX_PKTSIZE;
		pktbuf_max = KNOT_WIRE_MAX_PKTSIZE;
	} else if (knot_pkt_has_edns(query)) { /* EDNS */
		answer_max = MAX(knot_edns_get_payload(query->opt_rr), KNOT_WIRE_MIN_PKTSIZE);
	}

	/* Recycle available mempool if possible */
	mm_ctx_t pool = {
		.ctx = NULL,
		.alloc = (mm_alloc_t) mp_alloc
	};
	if (worker->pools.len > 0) {
		pool.ctx = array_tail(worker->pools);
		array_pop(worker->pools);
	} else { /* No mempool on the freelist, create new one */
		pool.ctx = mp_new (4 * CPU_PAGE_SIZE);
	}

	/* Create resolution task */
	struct engine *engine = worker->engine;
	struct qr_task *task = mm_alloc(&pool, sizeof(*task));
	if (!task) {
		mp_delete(pool.ctx);
		return NULL;
	}
	/* Create packet buffers for answer and subrequests */
	task->req.pool = pool;
	knot_pkt_t *pktbuf = knot_pkt_new(NULL, pktbuf_max, &task->req.pool);
	knot_pkt_t *answer = knot_pkt_new(NULL, answer_max, &task->req.pool);
	if (!pktbuf || !answer) {
		mp_delete(pool.ctx);
		return NULL;
	}
	task->req.answer = answer;
	task->pktbuf = pktbuf;
	task->ioreq = NULL;
	task->iohandle = NULL;
	task->iter_count = 0;
	task->flags = 0;
	task->worker = worker;
	task->source.handle = handle;
	uv_timer_init(worker->loop, &task->timeout);
	task->timeout.data = task;
	task->on_complete = NULL;
	/* Remember query source addr */
	if (addr) {
		memcpy(&task->source.addr, addr, sockaddr_len(addr));
		task->req.qsource.addr = (const struct sockaddr *)&task->source.addr;
	} else {
		task->source.addr.ip4.sin_family = AF_UNSPEC;
	}
	/* Remember query source TSIG key */
	if (query->tsig_rr) {
		task->req.qsource.key = knot_rrset_copy(query->tsig_rr, &task->req.pool);
	}

	/* Start resolution */
	kr_resolve_begin(&task->req, &engine->resolver, answer);
	worker->stats.concurrent += 1;
	return task;
}

static void qr_task_free(uv_handle_t *handle)
{
	struct qr_task *task = handle->data;
	struct worker_ctx *worker = task->worker;
	/* Run the completion callback. */
	if (task->on_complete) {
		task->on_complete(worker, &task->req, task->baton);
	}
	/* Return handle to the event loop in case
	 * it was exclusively taken by this task. */
	if (task->source.handle && !uv_has_ref(task->source.handle)) {
		uv_ref(task->source.handle);
		io_start_read(task->source.handle);
	}
	/* Return mempool to ring or free it if it's full */
	void *mp_context = task->req.pool.ctx;
	if (worker->pools.len < MP_FREELIST_SIZE) {
		mp_flush(mp_context);
		array_push(worker->pools, mp_context);
	} else {
		mp_delete(mp_context);
	}
	/* Decommit memory every once in a while */
	static int mp_delete_count = 0;
	if (++mp_delete_count == 100000) {
		lua_gc(worker->engine->L, LUA_GCCOLLECT, 0);
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
		malloc_trim(0);
#endif
		mp_delete_count = 0;
	}

	/* Update stats */
	worker->stats.concurrent -= 1;
}

static void qr_task_timeout(uv_timer_t *req)
{
	struct qr_task *task = req->data;
	if (!uv_is_closing((uv_handle_t *)req)) {
		if (task->ioreq) { /* Invalidate pending IO request. */
			task->ioreq->data = NULL;
		}
		qr_task_step(task, NULL);
	}
}

static int qr_task_on_send(struct qr_task *task, uv_handle_t *handle, int status)
{
	if (task->req.state != KNOT_STATE_NOOP) {
		if (status == 0 && handle) {
			io_start_read(handle); /* Start reading answer */
		}
	} else { /* Finalize task */
		uv_timer_stop(&task->timeout);
		uv_close((uv_handle_t *)&task->timeout, qr_task_free);
	}
	return status;
}

static void on_close(uv_handle_t *handle)
{
	struct worker_ctx *worker = get_worker();
	ioreq_release(worker, (struct ioreq *)handle);
}

static void on_send(uv_udp_send_t *req, int status)
{
	struct worker_ctx *worker = get_worker();
	struct qr_task *task = req->data;
	if (task) {
		qr_task_on_send(task, (uv_handle_t *)req->handle, status);
		task->ioreq = NULL;
	}
	ioreq_release(worker, (struct ioreq *)req);
}

static void on_write(uv_write_t *req, int status)
{
	struct worker_ctx *worker = get_worker();
	struct qr_task *task = req->data;
	if (task) {
		qr_task_on_send(task, (uv_handle_t *)req->handle, status);
		task->ioreq = NULL;
	}
	ioreq_release(worker, (struct ioreq *)req);
}

static int qr_task_send(struct qr_task *task, uv_handle_t *handle, struct sockaddr *addr, knot_pkt_t *pkt)
{
	int ret = 0;
	if (!handle) {
		return qr_task_on_send(task, handle, kr_error(EIO));
	}
	struct ioreq *send_req = ioreq_take(task->worker);
	if (!send_req) {
		return qr_task_on_send(task, handle, kr_error(ENOMEM));
	}

	/* Send using given protocol */
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
		task->ioreq = (uv_req_t *)send_req;
	} else {
		ioreq_release(task->worker, send_req);
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
	if (task) {
		task->ioreq = NULL;
		if (status == 0) {
			struct sockaddr_in6 addr;
			int addrlen = sizeof(addr); /* Retrieve endpoint IP for statistics */
			uv_stream_t *handle = req->handle;
			uv_tcp_getpeername((uv_tcp_t *)handle, (struct sockaddr *)&addr, &addrlen);
			qr_task_send(task, (uv_handle_t *)handle, (struct sockaddr *)&addr, task->pktbuf);
		} else {
			qr_task_step(task, NULL);
		}
	}
	ioreq_release(worker, (struct ioreq *)req);
}

static int qr_task_finalize(struct qr_task *task, int state)
{
	kr_resolve_finish(&task->req, state);
	/* Send back answer */
	(void) qr_task_send(task, task->source.handle, (struct sockaddr *)&task->source.addr, task->req.answer);
	return state == KNOT_STATE_DONE ? 0 : kr_error(EIO);
}

static int qr_task_step(struct qr_task *task, knot_pkt_t *packet)
{
	/* Close subrequest handle. */
	uv_timer_stop(&task->timeout);
	if (task->iohandle && !uv_is_closing(task->iohandle)) {
		io_stop_read(task->iohandle);
		uv_close(task->iohandle, on_close);
		task->iohandle = NULL;
	}

	/* Consume input and produce next query */
	int sock_type = -1;
	struct sockaddr *addr = NULL;
	knot_pkt_t *pktbuf = task->pktbuf;
	int state = kr_resolve_consume(&task->req, NULL, packet);
	while (state == KNOT_STATE_PRODUCE) {
		state = kr_resolve_produce(&task->req, &addr, &sock_type, pktbuf);
		if (unlikely(++task->iter_count > KR_ITER_LIMIT)) {
			return qr_task_finalize(task, KNOT_STATE_FAIL);
		}
	}

	/* We're done, no more iterations needed */
	if (state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
		return qr_task_finalize(task, state);
	} else if (!addr || sock_type < 0) {
		return qr_task_step(task, NULL);
	}

	/* Create connection for iterative query */
	uv_handle_t *subreq = (uv_handle_t *)ioreq_take(task->worker);
	if (!subreq) {
		return qr_task_finalize(task, KNOT_STATE_FAIL);
	}
	io_create(task->worker->loop, subreq, sock_type);
	subreq->data = task;

	/* Connect or issue query datagram */
	task->iohandle = subreq;
	if (sock_type == SOCK_DGRAM) {
		if (qr_task_send(task, subreq, addr, pktbuf) != 0) {
			return qr_task_step(task, NULL);
		}
	} else {
		struct ioreq *conn_req = ioreq_take(task->worker);
		if (!conn_req) {
			return qr_task_step(task, NULL);
		}
		conn_req->as.connect.data = task;
		task->ioreq = (uv_req_t *)conn_req;
		if (uv_tcp_connect(&conn_req->as.connect, (uv_tcp_t *)subreq, addr, on_connect) != 0) {
			ioreq_release(task->worker, conn_req);
			return qr_task_step(task, NULL);
		}
	}

	/* Start next step with timeout */
	uv_timer_start(&task->timeout, qr_task_timeout, KR_CONN_RTT_MAX, 0);
	return kr_ok();
}

static int parse_query(knot_pkt_t *query)
{
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

int worker_exec(struct worker_ctx *worker, uv_handle_t *handle, knot_pkt_t *query, const struct sockaddr* addr)
{
	if (!worker) {
		return kr_error(EINVAL);
	}

	/* Parse query */
	int ret = parse_query(query);

	/* Start new task on master sockets, or resume existing */
	struct qr_task *task = handle->data;
	bool is_master_socket = (!task);
	if (is_master_socket) {
		/* Ignore badly formed queries or responses. */
		if (ret != 0 || knot_wire_get_qr(query->wire)) {
			return kr_error(EINVAL); /* Ignore. */
		}
		task = qr_task_create(worker, handle, query, addr);
		if (!task) {
			return kr_error(ENOMEM);
		}
	}

	/* Consume input and produce next query */
	return qr_task_step(task, query);
}

int worker_resolve(struct worker_ctx *worker, knot_pkt_t *query, unsigned options, worker_cb_t on_complete, void *baton)
{
	if (!worker || !query) {
		return kr_error(EINVAL);
	}

	/* Create task */
	struct qr_task *task = qr_task_create(worker, NULL, query, NULL);
	if (!task) {
		return kr_error(ENOMEM);
	}
	task->baton = baton;
	task->on_complete = on_complete;
	task->req.options |= options;
	return qr_task_step(task, query);
}

int worker_reserve(struct worker_ctx *worker, size_t ring_maxlen)
{
	array_init(worker->pools);
	array_init(worker->ioreqs);
	array_reserve(worker->pools, ring_maxlen);
	array_reserve(worker->ioreqs, ring_maxlen);
	memset(&worker->pkt_pool, 0, sizeof(worker->pkt_pool));
	worker->pkt_pool.ctx = mp_new (4 * sizeof(knot_pkt_t));
	worker->pkt_pool.alloc = (mm_alloc_t) mp_alloc;
	return kr_ok();
}

#define reclaim_freelist(list, cb) \
	for (unsigned i = 0; i < list.len; ++i) { \
		cb(list.at[i]); \
	} \
	array_clear(list)

void worker_reclaim(struct worker_ctx *worker)
{
	reclaim_freelist(worker->pools, mp_delete);
	reclaim_freelist(worker->ioreqs, free);
	mp_delete(worker->pkt_pool.ctx);
	worker->pkt_pool.ctx = NULL;
}
