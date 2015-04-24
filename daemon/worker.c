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
#include <libknot/internal/mempool.h>

#include "daemon/worker.h"
#include "daemon/engine.h"
#include "daemon/io.h"

/** @internal Query resolution task. */
struct qr_task
{
	struct kr_request req;
	knot_pkt_t *pending;
	uv_handle_t *handle;
};

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

	/* Accept only queries, no authoritative service. */
	if (knot_wire_get_qr(query->wire) || !knot_wire_get_rd(query->wire)) {
		return kr_error(EINVAL); /* Ignore. */
	}

	return kr_ok();
}

static struct qr_task *qr_task_create(struct worker_ctx *worker, uv_handle_t *handle)
{
	mm_ctx_t pool;
	mm_ctx_mempool(&pool, MM_DEFAULT_BLKSIZE);

	/* Create worker task */
	struct engine *engine = worker->engine;
	struct qr_task *task = mm_alloc(&pool, sizeof(*task));
	if (!task) {
		mp_delete(pool.ctx);
		return NULL;
	}
	task->req.pool = pool;
	task->handle = handle;

#warning TODO: devise a better scheme to manage answer buffer, it needs copy each time now
	/* Create buffers */
	knot_pkt_t *pending = knot_pkt_new(NULL, KNOT_WIRE_MIN_PKTSIZE, &task->req.pool);
	knot_pkt_t *answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, &task->req.pool);
	if (!pending || !answer) {
		mp_delete(pool.ctx);
		return NULL;
	}
	task->req.answer = answer;
	task->pending = pending;

	/* Start resolution */
	kr_resolve_begin(&task->req, &engine->resolver, answer);
	return task;
}

static int qr_task_finalize(struct qr_task *task, knot_pkt_t *dst, int state)
{
	knot_pkt_t *answer = task->req.answer;
	kr_resolve_finish(&task->req, state);
	memcpy(dst->wire, answer->wire, answer->size);
	dst->size = answer->size;
#warning TODO: send answer asynchronously
	mp_delete(task->req.pool.ctx);
	return state == KNOT_STATE_DONE ? 0 : kr_error(EIO);
}

static void qr_task_on_connect(uv_connect_t *connect, int status)
{
#warning TODO: if not connected, retry
#warning TODO: if connected, send pending query
}

int worker_exec(struct worker_ctx *worker, uv_handle_t *handle, knot_pkt_t *answer, knot_pkt_t *query)
{
	if (!worker) {
		return kr_error(EINVAL);
	}

	/* Parse query */
	int ret = parse_query(query);
	if (ret != 0) {
		return ret;
	}

	/* Get pending request or start new */
	struct qr_task *task = handle->data;
	if (!task) {
		task = qr_task_create(worker, handle);
		if (!task) {
			return kr_error(ENOMEM);
		}
	}

	/* Consume input and produce next query */
	int proto = 0;
	struct sockaddr *addr = NULL;
#warning TODO: it shouldnt be needed to provide NULL answer if I/O fails
	int state = kr_resolve_consume(&task->req, query);
	while (state == KNOT_STATE_PRODUCE) {
		state = kr_resolve_produce(&task->req, &addr, &proto, task->pending);
	}
	if (state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
		return qr_task_finalize(task, answer, state);
	}

	/* Create connection for iterative query */
	uv_handle_t *next_handle = io_create(handle->loop, proto);
#warning TODO: improve error checking	
	next_handle->data = task;
	if (proto == SOCK_STREAM) {
		uv_connect_t *connect = io_connect(next_handle, addr, qr_task_on_connect);
		if (!connect) {
#warning TODO: close next_handle			
			return kr_error(ENOMEM);
		}
	} else {
		/* Fake connection as libuv doesn't support connected UDP */
		uv_connect_t fake_connect;
		fake_connect.handle = (uv_stream_t *)next_handle;
		qr_task_on_connect(&fake_connect, 0);
	}

	return kr_ok();
}
