#include <uv.h>

#include <libknot/packet/pkt.h>
#include <libknot/internal/net.h>
#include <libknot/errcode.h>

#include "daemon/worker.h"
#include "daemon/layer/query.h"

static void buf_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	struct worker_ctx *worker = handle->data;
	buf->base = mm_alloc(worker->pool, suggested_size);
	buf->len = suggested_size;
}

static void buf_free(uv_handle_t* handle, const uv_buf_t* buf)
{
	struct worker_ctx *worker = handle->data;
	mm_free(worker->pool, buf->base);
}

static void worker_send(uv_udp_t *handle, knot_pkt_t *answer, const struct sockaddr *addr)
{
	uv_buf_t sendbuf = uv_buf_init((char *)answer->wire, answer->size);
	uv_udp_try_send(handle, &sendbuf, 1, addr);
}

static void worker_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags)
{
	struct worker_ctx *worker = handle->data;
	assert(worker->pool);

	if (nread < KNOT_WIRE_HEADER_SIZE) {
		buf_free((uv_handle_t *)handle, buf);
		return;
	}

	/* Parse query packet. */
	knot_pkt_t *query = knot_pkt_new((uint8_t *)buf->base, nread, worker->pool);
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK) {
		knot_pkt_free(&query);
		buf_free((uv_handle_t *)handle, buf);
		return; /* Ignore malformed query. */
	}

	/* Process query packet. */
	knot_layer_t proc;
	memset(&proc, 0, sizeof(knot_layer_t));
	proc.mm = worker->pool;
	knot_layer_begin(&proc, LAYER_QUERY, &worker->resolve);
	int state = knot_layer_in(&proc, query);

	/* Build an answer. */
	knot_pkt_t *answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, worker->pool);
	while (state == KNOT_NS_PROC_FULL) {
		knot_pkt_init_response(answer, query);
		state = knot_layer_out(&proc, answer);
		if (answer->size > 0) {
			worker_send(handle, answer, addr);
		}
	}

	/* Cleanup. */
	knot_layer_finish(&proc);
	buf_free((uv_handle_t *)handle, buf);
	knot_pkt_free(&query);
	knot_pkt_free(&answer);
}

void worker_init(struct worker_ctx *worker, mm_ctx_t *mm)
{
	memset(worker, 0, sizeof(struct worker_ctx));
	worker->pool = mm;

	kr_context_init(&worker->resolve, mm);
}

void worker_deinit(struct worker_ctx *worker)
{
	kr_context_deinit(&worker->resolve);
}

void worker_start(uv_udp_t *handle, struct worker_ctx *worker)
{

	handle->data = worker;
	uv_udp_recv_start(handle, &buf_alloc, &worker_recv);
}

void worker_stop(uv_udp_t *handle)
{
	uv_udp_recv_stop(handle);
}
