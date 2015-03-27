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

#include <libknot/errcode.h>

#include "daemon/udp.h"
#include "daemon/worker.h"

static void buf_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	struct worker_ctx *worker = handle->data;
	buf->base = mm_alloc(worker->mm, suggested_size);
	buf->len = suggested_size;
}

static void buf_free(uv_handle_t* handle, const uv_buf_t* buf)
{
	struct worker_ctx *worker = handle->data;
	mm_free(worker->mm, buf->base);
}

static void udp_send(uv_udp_t *handle, knot_pkt_t *answer, const struct sockaddr *addr)
{
	uv_buf_t sendbuf = uv_buf_init((char *)answer->wire, answer->size);
	uv_udp_try_send(handle, &sendbuf, 1, addr);
}

static void udp_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                     const struct sockaddr *addr, unsigned flags)
{
	struct worker_ctx *worker = handle->data;

	/* Check the incoming wire length. */
	if (nread < KNOT_WIRE_HEADER_SIZE) {
		buf_free((uv_handle_t *)handle, buf);
		return;
	}

	/* Create packets */
	knot_pkt_t *query = knot_pkt_new(buf->base, nread, worker->mm);
	knot_pkt_t *answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, worker->mm);

	/* Resolve */
	int ret = worker_exec(worker, answer, query);
	if (ret == KNOT_EOK && answer->size > 0) {
		udp_send(handle, answer, addr);
	}

	/* Cleanup */
	buf_free((uv_handle_t *)handle, buf);
	knot_pkt_free(&query);
	knot_pkt_free(&answer);
}

int udp_bind(uv_handle_t *handle, struct worker_ctx *worker, struct sockaddr *addr)
{
	uv_udp_t *sock = (uv_udp_t *)handle;

	int ret = uv_udp_bind(sock, addr, 0);
	if (ret != 0) {
		return KNOT_ERROR;
	}

	sock->data = worker;
	uv_udp_recv_start(sock, &buf_alloc, &udp_recv);
	return KNOT_EOK;
}

void udp_unbind(uv_handle_t *handle)
{
	uv_udp_recv_stop((uv_udp_t *)handle);
	uv_close(handle, NULL);
}
