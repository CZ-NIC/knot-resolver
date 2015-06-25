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
#include <libknot/packet/pkt.h>
#include <libknot/internal/net.h>
#include <ucw/mempool.h>
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
#include <malloc.h>
#endif

#include "daemon/worker.h"
#include "daemon/engine.h"
#include "daemon/io.h"

/** @internal Query resolution task. */
struct qr_task
{
	struct kr_request req;
	struct worker_ctx *worker;
	knot_pkt_t *next_query;
	uv_handle_t *next_handle;
	uv_timer_t timeout;
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

static struct qr_task *qr_task_create(struct worker_ctx *worker, uv_handle_t *handle, knot_pkt_t *query, const struct sockaddr *addr)
{
	/* Recycle available mempool if possible */
	mm_ctx_t pool = {
		.ctx = NULL,
		.alloc = (mm_alloc_t) mp_alloc
	};
	if (worker->pools.len > 0) {
		pool.ctx = array_tail(worker->pools);
		array_pop(worker->pools);
	} else { /* No mempool on the freelist, create new one */
		pool.ctx = mp_new (16 * CPU_PAGE_SIZE);
	}

	/* Create worker task */
	struct engine *engine = worker->engine;
	struct qr_task *task = mm_alloc(&pool, sizeof(*task));
	memset(task, 0, sizeof(*task));
	if (!task) {
		mp_delete(pool.ctx);
		return NULL;
	}
	task->worker = worker;
	task->req.pool = pool;
	task->source.handle = handle;
	if (addr) {
		memcpy(&task->source.addr, addr, sockaddr_len(addr));
	}

	/* How much can client handle? */
	size_t answer_max = KNOT_WIRE_MIN_PKTSIZE;
	if (!addr) { /* TCP */
		answer_max = KNOT_WIRE_MAX_PKTSIZE;
	} else if (knot_pkt_has_edns(query)) { /* EDNS */
		answer_max = knot_edns_get_payload(query->opt_rr);
	}
	/* How much space do we need for intermediate packets? */
	size_t pktbuf_max = KNOT_EDNS_MAX_UDP_PAYLOAD;
	if (pktbuf_max < answer_max) {
		pktbuf_max = answer_max;
	}

	/* Create buffers */
	knot_pkt_t *pktbuf = knot_pkt_new(NULL, pktbuf_max, &task->req.pool);
	knot_pkt_t *answer = knot_pkt_new(NULL, answer_max, &task->req.pool);
	if (!pktbuf || !answer) {
		mp_delete(pool.ctx);
		return NULL;
	}
	task->req.answer = answer;
	task->next_query = pktbuf;

	/* Start resolution */
	uv_timer_init(handle->loop, &task->timeout);
	task->timeout.data = task;
	kr_resolve_begin(&task->req, &engine->resolver, answer);
	return task;
}

static void qr_task_free(uv_handle_t *handle)
{
	struct qr_task *task = handle->data;
	/* Return handle to the event loop in case
	 * it was exclusively taken by this task. */
	if (!uv_has_ref(task->source.handle)) {
		uv_ref(task->source.handle);
		io_start_read(task->source.handle);
	}
	/* Return mempool to ring or free it if it's full */
	struct worker_ctx *worker = task->worker;
	void *mp_context = task->req.pool.ctx;
	if (worker->pools.len < MP_FREELIST_SIZE) {
		mp_flush(mp_context);
		array_push(worker->pools, mp_context);
	} else {
		mp_delete(mp_context);
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
		/* Decommit memory every once in a while */
		static size_t mp_delete_count = 0;
		if (++mp_delete_count == 100 * MP_FREELIST_SIZE) {
			malloc_trim(0);
			mp_delete_count = 0;
		}
#endif
	}
}

static void qr_task_timeout(uv_timer_t *req)
{
	struct qr_task *task = req->data;
	if (task->next_handle) {
		qr_task_step(task, NULL);
	}
}

static int qr_task_on_send(struct qr_task *task, int status)
{
	if (task) {
		/* Start reading answer */
		if (task->req.overlay.state != KNOT_STATE_NOOP) {
			if (status == 0 && task->next_handle) {
				io_start_read(task->next_handle);
			}
		} else { /* Finalize task */
			uv_timer_stop(&task->timeout);
			uv_close((uv_handle_t *)&task->timeout, qr_task_free);
		}
	}
	return status;
}

static int qr_task_send(struct qr_task *task, uv_handle_t *handle, struct sockaddr *addr, knot_pkt_t *pkt)
{
	int ret = 0;
	if (handle->type == UV_UDP) {
		uv_buf_t buf = { (char *)pkt->wire, pkt->size };
		ret = uv_udp_try_send((uv_udp_t *)handle, &buf, 1, addr);
	} else {
		uint16_t pkt_size = htons(pkt->size);
		uv_buf_t buf[2] = {
			{ (char *)&pkt_size, sizeof(pkt_size) },
			{ (char *)pkt->wire, pkt->size }
		};
		ret = uv_try_write((uv_stream_t *)handle, buf, 2);
	}
	return qr_task_on_send(task, (ret >= 0) ? 0 : -1);
}

static void qr_task_on_connect(uv_connect_t *connect, int status)
{
	if (status == 0) {
		struct qr_task *task = connect->data;
		qr_task_send(task, (uv_handle_t *)connect->handle, NULL, task->next_query);
	}
	free(connect);
}

static int qr_task_finalize(struct qr_task *task, int state)
{
	kr_resolve_finish(&task->req, state);
	(void) qr_task_send(task, task->source.handle, (struct sockaddr *)&task->source.addr, task->req.answer);
	return state == KNOT_STATE_DONE ? 0 : kr_error(EIO);
}

static int qr_task_step(struct qr_task *task, knot_pkt_t *packet)
{
	/* Cancel timeout if active, close handle. */
	if (task->next_handle) {
		if (!uv_is_closing(task->next_handle)) {
			io_stop_read(task->next_handle);
			uv_close(task->next_handle, (uv_close_cb) free);
		}
		uv_timer_stop(&task->timeout);
		task->next_handle = NULL;
	}

	/* Consume input and produce next query */
	int sock_type = -1;
	struct sockaddr *addr = NULL;
	knot_pkt_t *next_query = task->next_query;
	int state = kr_resolve_consume(&task->req, packet);
	while (state == KNOT_STATE_PRODUCE) {
		state = kr_resolve_produce(&task->req, &addr, &sock_type, next_query);
		if (++task->iter_count > KR_ITER_LIMIT) {
			return qr_task_finalize(task, KNOT_STATE_FAIL);
		}
	}

	/* We're done, no more iterations needed */
	if (state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
		return qr_task_finalize(task, state);
	}

	/* Create connection for iterative query */
	uv_handle_t *source_handle = task->source.handle;
	task->next_handle = io_create(source_handle->loop, sock_type);
	if (task->next_handle == NULL) {
		return qr_task_finalize(task, KNOT_STATE_FAIL);
	}

	/* Connect or issue query datagram */
	task->next_handle->data = task;
	if (sock_type == SOCK_STREAM) {
		/* connect handle must be persistent even if the task mempool drops,
		 * as it is referenced internally in the libuv event loop */
		uv_connect_t *connect = malloc(sizeof(*connect));
		if (!connect || uv_tcp_connect(connect, (uv_tcp_t *)task->next_handle, addr, qr_task_on_connect) != 0) {
			free(connect);
			return qr_task_step(task, NULL);
		}
		connect->data = task;
	} else {
		if (qr_task_send(task, task->next_handle, addr, next_query) != 0) {
			return qr_task_step(task, NULL);
		}
	}

	/* Start next step with timeout */
	uv_timer_start(&task->timeout, qr_task_timeout, KR_CONN_RTT_MAX, 0);
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

int worker_reserve(struct worker_ctx *worker, size_t ring_maxlen)
{
	array_init(worker->pools);
	return array_reserve(worker->pools, ring_maxlen);
}

void worker_reclaim(struct worker_ctx *worker)
{
	mp_freelist_t *pools = &worker->pools;
	for (unsigned i = 0; i < pools->len; ++i) {
		mp_delete(pools->at[i]);
	}
	array_clear(*pools);
}
