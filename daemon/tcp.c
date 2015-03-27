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
#include <libknot/internal/utils.h>

#include "daemon/tcp.h"
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

static void tcp_send(uv_handle_t *handle, const knot_pkt_t *answer)
{
	uint16_t pkt_size = 0;
	uv_buf_t buf[2];
	buf[0].base = (char *)&pkt_size;
	buf[0].len  = sizeof(pkt_size);
	buf[1].base = (char *)answer->wire;
	buf[1].len  = answer->size;
	wire_write_u16((uint8_t *)buf[0].base, answer->size);

	uv_try_write((uv_stream_t *)handle, buf, 2);
}

static void tcp_recv(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
	struct worker_ctx *worker = handle->data;

	/* Check the incoming wire length (malformed, EOF or error). */
	if (nread < (ssize_t) sizeof(uint16_t)) {
		buf_free((uv_handle_t *)handle, buf);
		tcp_unbind((uv_handle_t *)handle);
		free(handle);
		return;
	}

	/* Set packet size */
	nread = wire_read_u16((const uint8_t *)buf->base);

	/* Create packets */
	knot_pkt_t *query = knot_pkt_new(buf->base + sizeof(uint16_t), nread, worker->mm);
	knot_pkt_t *answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, worker->mm);

	/* Resolve */
	int ret = worker_exec(worker, answer, query);
	if (ret == KNOT_EOK && answer->size > 0) {
		tcp_send((uv_handle_t *)handle, answer);
	}

	/* Cleanup */
	knot_pkt_free(&query);
	knot_pkt_free(&answer);
	buf_free((uv_handle_t *)handle, buf);
}

static void tcp_accept(uv_stream_t *server, int status)
{
	if (status != 0) {
		return;
	}

	uv_tcp_t *client = malloc(sizeof(uv_tcp_t));
	uv_tcp_init(server->loop, client);
	client->data = server->data;

	if (uv_accept(server, (uv_stream_t*)client) != 0) {
		uv_close((uv_handle_t*)client, NULL);
		free(client);
	}

	uv_read_start((uv_stream_t*)client, buf_alloc, tcp_recv);
}

int tcp_bind(uv_handle_t *handle, struct worker_ctx *worker, struct sockaddr *addr)
{
	uv_tcp_t *sock = (uv_tcp_t *)handle;

	int ret = uv_tcp_bind(sock, addr, 0);
	if (ret != 0) {
		return KNOT_ERROR;
	}

	ret = uv_listen((uv_stream_t *)sock, 128, tcp_accept);
	if (ret != 0) {
		return KNOT_ERROR;
	}

	sock->data = worker;
	return KNOT_EOK;
}

void tcp_unbind(uv_handle_t *handle)
{
	uv_udp_recv_stop((uv_udp_t *)handle);
	uv_close(handle, NULL);
}
