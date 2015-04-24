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

#include "daemon/io.h"
#include "daemon/network.h"
#include "daemon/worker.h"

#define ENDPOINT_BUFSIZE 512 /**< This is an artificial limit for DNS query. */

static void buf_get(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
#warning TODO: freelist from worker allocation
	buf->base = malloc(ENDPOINT_BUFSIZE);
	if (buf->base) {
		buf->len = ENDPOINT_BUFSIZE;
	} else {
		buf->len = 0;
	}
}

int udp_send(uv_udp_t *handle, knot_pkt_t *answer, const struct sockaddr *addr)
{
	uv_buf_t sendbuf = uv_buf_init((char *)answer->wire, answer->size);
	return uv_udp_try_send(handle, &sendbuf, 1, addr);
}

static void udp_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
	const struct sockaddr *addr, unsigned flags)
{
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;

	/* Check the incoming wire length. */
	if (nread < KNOT_WIRE_HEADER_SIZE) {
		return;
	}

	/* Create packets */
	knot_pkt_t *query = knot_pkt_new(buf->base, nread, worker->mm);
	knot_pkt_t *answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, worker->mm);

	/* Resolve */
	int ret = worker_exec(worker, (uv_handle_t *)handle, answer, query);
	if (ret == KNOT_EOK && answer->size > 0) {
		udp_send(handle, answer, addr);
	}

	/* Cleanup */
	knot_pkt_free(&query);
	knot_pkt_free(&answer);
	free(buf->base);
}

static uv_udp_t *udp_create(uv_loop_t *loop)
{
	uv_udp_t *handle = malloc(sizeof(uv_udp_t));
	if (!handle) {
		return handle;
	}

	uv_udp_init(loop, handle);

	return handle;
}

int udp_bind(struct endpoint *ep, struct sockaddr *addr)
{
	uv_udp_t *handle = &ep->udp;
	int ret = uv_udp_bind(handle, addr, 0);
	if (ret != 0) {
		return ret;
	}

	return uv_udp_recv_start(handle, &buf_get, &udp_recv);
}

void udp_unbind(struct endpoint *ep)
{
	uv_udp_t *handle = &ep->udp;
	uv_udp_recv_stop(handle);
	uv_close((uv_handle_t *)handle, NULL);
}

static void tcp_unbind_handle(uv_handle_t *handle)
{
	uv_read_stop((uv_stream_t *)handle);
}

static void tcp_send(uv_handle_t *handle, const knot_pkt_t *answer)
{
	uint16_t pkt_size = htons(answer->size);
	uv_buf_t buf[2];
	buf[0].base = (char *)&pkt_size;
	buf[0].len  = sizeof(pkt_size);
	buf[1].base = (char *)answer->wire;
	buf[1].len  = answer->size;

	uv_try_write((uv_stream_t *)handle, buf, 2);
}

static void tcp_recv(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;

	/* Check the incoming wire length (malformed, EOF or error). */
	if (nread < (ssize_t) sizeof(uint16_t)) {
		tcp_unbind_handle((uv_handle_t *)handle);
		uv_close((uv_handle_t *)handle, (uv_close_cb) free);
		return;
	}

	/* Set packet size */
	nread = wire_read_u16((const uint8_t *)buf->base);

	/* Create packets */
	knot_pkt_t *query = knot_pkt_new(buf->base + sizeof(uint16_t), nread, worker->mm);
	knot_pkt_t *answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, worker->mm);

	/* Resolve */
	int ret = worker_exec(worker, (uv_handle_t *)handle, answer, query);
	if (ret == KNOT_EOK && answer->size > 0) {
		tcp_send((uv_handle_t *)handle, answer);
	}

	/* Cleanup */
	knot_pkt_free(&query);
	knot_pkt_free(&answer);
	free(buf->base);
}

static uv_tcp_t *tcp_create(uv_loop_t *loop)
{
	uv_tcp_t *handle = malloc(sizeof(uv_tcp_t));
	if (!handle) {
		return handle;
	}

	uv_tcp_init(loop, handle);
	return handle;
}

static void tcp_accept(uv_stream_t *master, int status)
{
	if (status != 0) {
		return;
	}

	uv_tcp_t *client = tcp_create(master->loop);
	if (!client || uv_accept(master, (uv_stream_t*)client) != 0) {
		free(client);
		return;
	}

	uv_read_start((uv_stream_t*)client, buf_get, tcp_recv);
}

int tcp_bind(struct endpoint *ep, struct sockaddr *addr)
{
	uv_tcp_t *handle = &ep->tcp;
	int ret = uv_tcp_bind(handle, addr, 0);
	if (ret != 0) {
		return ret;
	}

	ret = uv_listen((uv_stream_t *)handle, 16, tcp_accept);
	if (ret != 0) {
		tcp_unbind(ep);
		return ret;
	}

	return 0;
}

void tcp_unbind(struct endpoint *ep)
{
	tcp_unbind_handle((uv_handle_t *)&ep->tcp);
	uv_close((uv_handle_t *)&ep->tcp, NULL);
}

uv_handle_t *io_create(uv_loop_t *loop, int type)
{
	uv_handle_t *handle = NULL;
	if (type == SOCK_DGRAM) {
		handle = (uv_handle_t *)udp_create(loop);
		if (handle) {
			uv_udp_recv_start((uv_udp_t *)handle, &buf_get, &udp_recv);
		}

	} else {
		handle = (uv_handle_t *)tcp_create(loop);
		if (handle) {
			uv_read_start((uv_stream_t*)handle, buf_get, tcp_recv);
		}
	}
	return handle;
}

uv_connect_t *io_connect(uv_handle_t *handle, struct sockaddr *addr, uv_connect_cb on_connect)
{
	uv_connect_t* connect = malloc(sizeof(uv_connect_t));
	if (uv_tcp_connect(connect, (uv_tcp_t *)handle, addr, on_connect) != 0) {
		free(connect);
		return NULL;
	}
	return connect;
}
