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

static void *handle_alloc(uv_loop_t *loop, size_t size)
{
	uv_handle_t *handle = malloc(size);
	if (handle) {
		memset(handle, 0, size);
	}
	return handle;
}

static void handle_free(uv_handle_t *handle)
{
	free(handle);
}

static void handle_getbuf(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	/* Worker has single buffer which is reused for all incoming
	 * datagrams / stream reads, the content of the buffer is
	 * guaranteed to be unchanged only for the duration of
	 * udp_read() and tcp_read().
	 */
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;
	buf->base = (char *)worker->wire_buf;
	buf->len = sizeof(worker->wire_buf);
}

void udp_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
	const struct sockaddr *addr, unsigned flags)
{
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;
	if (nread <= 0) {
		worker_exec(worker, (uv_handle_t *)handle, NULL, addr);
		return;
	}

	knot_pkt_t *query = knot_pkt_new(buf->base, nread, worker->mm);
	query->max_size = sizeof(worker->wire_buf);
	worker_exec(worker, (uv_handle_t *)handle, query, addr);
	knot_pkt_free(&query);
}

int udp_bind(struct endpoint *ep, struct sockaddr *addr)
{
	uv_udp_t *handle = &ep->udp;
	unsigned flags = UV_UDP_REUSEADDR;
	if (addr->sa_family == AF_INET6) {
		flags |= UV_UDP_IPV6ONLY;
	}
	int ret = uv_udp_bind(handle, addr, flags);
	if (ret != 0) {
		return ret;
	}

	handle->data = NULL;
	return io_start_read((uv_handle_t *)handle);
}

void udp_unbind(struct endpoint *ep)
{
	uv_udp_t *handle = &ep->udp;
	uv_close((uv_handle_t *)handle, NULL);
}

static void tcp_recv(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;

	/* Check for originator connection close */
	if (nread <= 0 && handle->data == 0) {
		io_close((uv_handle_t *)handle);
		return;
	} else if (nread < 2) {
		/* Not enough bytes to read length */
		worker_exec(worker, (uv_handle_t *)handle, NULL, NULL);
		return;
	}

	/** @todo This is not going to work if the packet is fragmented in the stream ! */
	uint16_t nbytes = wire_read_u16((const uint8_t *)buf->base);
	if (nbytes + 2 < nread) {
		worker_exec(worker, (uv_handle_t *)handle, NULL, NULL);
		return;
	}

	knot_pkt_t *query = knot_pkt_new(buf->base + 2, nbytes, worker->mm);
	query->max_size = sizeof(worker->wire_buf);
	int ret = worker_exec(worker, (uv_handle_t *)handle, query, NULL);
	if (ret == 0) {
		/* Push - pull, stop reading from this handle until
		 * the task is finished. Since the handle has no track of the
		 * pending tasks, it might be freed before the task finishes
		 * leading various errors. */
		uv_unref((uv_handle_t *)handle);
		io_stop_read((uv_handle_t *)handle);
	}
	knot_pkt_free(&query);
}

static void tcp_accept(uv_stream_t *master, int status)
{
	if (status != 0) {
		return;
	}

	uv_stream_t *client = (uv_stream_t *)io_create(master->loop, SOCK_STREAM);
	if (!client || uv_accept(master, client) != 0) {
		handle_free((uv_handle_t *)client);
		return;
	}

	io_start_read((uv_handle_t *)client);
}

int tcp_bind(struct endpoint *ep, struct sockaddr *addr)
{
	uv_tcp_t *handle = &ep->tcp;
	unsigned flags = UV_UDP_REUSEADDR;
	if (addr->sa_family == AF_INET6) {
		flags |= UV_UDP_IPV6ONLY;
	}
	int ret = uv_tcp_bind(handle, addr, flags);
	if (ret != 0) {
		return ret;
	}

	ret = uv_listen((uv_stream_t *)handle, 16, tcp_accept);
	if (ret != 0) {
		tcp_unbind(ep);
		return ret;
	}

	handle->data = NULL;
	return 0;
}

void tcp_unbind(struct endpoint *ep)
{
	uv_close((uv_handle_t *)&ep->tcp, NULL);
}

uv_handle_t *io_create(uv_loop_t *loop, int type)
{
	if (type == SOCK_DGRAM) {
		uv_udp_t *handle = handle_alloc(loop, sizeof(*handle));
		if (handle) {
			uv_udp_init(loop, handle);
		}
		return (uv_handle_t *)handle;
	} else {
		uv_tcp_t *handle = handle_alloc(loop, sizeof(*handle));
		if (handle) {
			uv_tcp_init(loop, handle);
		}
		return (uv_handle_t *)handle;
	}
}

void io_close(uv_handle_t *handle)
{
	uv_close(handle, (uv_close_cb) handle_free);
}

int io_start_read(uv_handle_t *handle)
{
	if (handle->type == UV_UDP) {
		return uv_udp_recv_start((uv_udp_t *)handle, &handle_getbuf, &udp_recv);
	} else {
		return uv_read_start((uv_stream_t *)handle, &handle_getbuf, &tcp_recv);
	}
}

int io_stop_read(uv_handle_t *handle)
{
	if (handle->type == UV_UDP) {
		return uv_udp_recv_stop((uv_udp_t *)handle);
	} else {
		return uv_read_stop((uv_stream_t *)handle);
	}
}
