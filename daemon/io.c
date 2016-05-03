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

#include <string.h>
#include <libknot/errcode.h>
#include <contrib/ucw/lib.h>
#include <contrib/ucw/mempool.h>
#include <assert.h>

#include "daemon/io.h"
#include "daemon/network.h"
#include "daemon/worker.h"

#define negotiate_bufsize(func, handle, bufsize_want) do { \
    int bufsize = 0; func(handle, &bufsize); \
	if (bufsize < bufsize_want) { \
		bufsize = bufsize_want; \
		func(handle, &bufsize); \
	} \
} while (0)

static void check_bufsize(uv_handle_t* handle)
{
	/* We want to buffer at least N waves in advance.
	 * This is magic presuming we can pull in a whole recvmmsg width in one wave.
	 * Linux will double this the bufsize wanted.
	 */
	const int bufsize_want = RECVMMSG_BATCH * 65535 * 2;
	negotiate_bufsize(uv_recv_buffer_size, handle, bufsize_want);
	negotiate_bufsize(uv_send_buffer_size, handle, bufsize_want);
}

#undef negotiate_bufsize

static void session_clear(struct session *s)
{
	assert(s->is_subreq || s->tasks.len == 0);
	array_clear(s->tasks);
	memset(s, 0, sizeof(*s));
}

void session_free(struct session *s)
{
	session_clear(s);
	free(s);
}

struct session *session_new(void)
{
	return calloc(1, sizeof(struct session));
}

static struct session *session_borrow(struct worker_ctx *worker)
{
	struct session *s = NULL;
	if (worker->pool_sessions.len > 0) {
		s = array_tail(worker->pool_sessions);
		array_pop(worker->pool_sessions);
		kr_asan_unpoison(s, sizeof(*s));
	} else {
		s = session_new();
	}
	return s;
}

static void session_release(struct worker_ctx *worker, struct session *s)
{
	if (worker->pool_sessions.len < MP_FREELIST_SIZE) {
		session_clear(s);
		array_push(worker->pool_sessions, s);
		kr_asan_poison(s, sizeof(*s));
	} else {
		session_free(s);
	}
}

static uv_stream_t *handle_alloc(uv_loop_t *loop)
{
	uv_stream_t *handle = calloc(1, sizeof(*handle));
	if (!handle) {
		return NULL;
	}

	return handle;
}

static void handle_getbuf(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	/* Worker has single buffer which is reused for all incoming
	 * datagrams / stream reads, the content of the buffer is
	 * guaranteed to be unchanged only for the duration of
	 * udp_read() and tcp_read().
	 */
	struct session *session = handle->data;
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;
	buf->base = (char *)worker->wire_buf;
	/* Limit TCP stream buffer size to 4K for granularity in batches of incoming queries. */
	if (handle->type == UV_TCP) {
		buf->len = MIN(suggested_size, 4096);
	/* Regular buffer size for subrequests. */
	} else if (session->is_subreq) {
		buf->len = suggested_size;
	/* Use recvmmsg() on master sockets if possible. */
	} else {
		buf->len = sizeof(worker->wire_buf);
	}
}

void udp_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
	const struct sockaddr *addr, unsigned flags)
{
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;
	if (nread <= 0) {
		if (nread < 0) { /* Error response, notify resolver */
			worker_submit(worker, (uv_handle_t *)handle, NULL, addr);
		} /* nread == 0 is for freeing buffers, we don't need to do this */
		return;
	}

	knot_pkt_t *query = knot_pkt_new(buf->base, nread, &worker->pkt_pool);
	if (query) {
		query->max_size = KNOT_WIRE_MAX_PKTSIZE;
		worker_submit(worker, (uv_handle_t *)handle, query, addr);
	}
	mp_flush(worker->pkt_pool.ctx);
}

int udp_bind(uv_udp_t *handle, struct sockaddr *addr)
{
	unsigned flags = UV_UDP_REUSEADDR;
	if (addr->sa_family == AF_INET6) {
		flags |= UV_UDP_IPV6ONLY;
	}
	int ret = uv_udp_bind(handle, addr, flags);
	if (ret != 0) {
		return ret;
	}
	check_bufsize((uv_handle_t *)handle);
	/* Handle is already created, just create context. */
	handle->data = session_new();
	assert(handle->data);
	return io_start_read((uv_handle_t *)handle);
}

static void tcp_timeout(uv_handle_t *timer)
{
	uv_handle_t *handle = timer->data;
	uv_close(handle, io_free);
}

static void tcp_timeout_trigger(uv_timer_t *timer)
{
	uv_handle_t *handle = timer->data;
	struct session *session = handle->data;
	if (session->tasks.len > 0) {
		uv_timer_again(timer);
	} else {
		uv_close((uv_handle_t *)timer, tcp_timeout);
	}
}

static void tcp_recv(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
	uv_loop_t *loop = handle->loop;
	struct session *s = handle->data;
	struct worker_ctx *worker = loop->data;
	/* TCP pipelining is rather complicated and requires cooperation from the worker
	 * so the whole message reassembly and demuxing logic is inside worker */
	int ret = worker_process_tcp(worker, (uv_handle_t *)handle, (const uint8_t *)buf->base, nread);
	if (ret < 0) {
		worker_end_tcp(worker, (uv_handle_t *)handle);
		/* Exceeded per-connection quota for outstanding requests
		 * stop reading from stream and close after last message is processed. */
		if (!s->is_subreq && !uv_is_closing((uv_handle_t *)&s->timeout)) {
			uv_timer_stop(&s->timeout);
			if (s->tasks.len == 0) {
				uv_close((uv_handle_t *)&s->timeout, tcp_timeout);
			} else { /* If there are tasks running, defer until they finish. */
				uv_timer_start(&s->timeout, tcp_timeout_trigger, 1, KR_CONN_RTT_MAX/2);
			}
		}
	/* Connection spawned more than one request, reset its deadline for next query. */
	} else if (ret > 0 && !s->is_subreq) {
		uv_timer_again(&s->timeout);
	}
	mp_flush(worker->pkt_pool.ctx);
}

static void tcp_accept(uv_stream_t *master, int status)
{
	if (status != 0) {
		return;
	}
	uv_stream_t *client = handle_alloc(master->loop);
	if (!client) {
		return;
	}
	memset(client, 0, sizeof(*client));
	io_create(master->loop, (uv_handle_t *)client, SOCK_STREAM);
	if (uv_accept(master, client) != 0) {
		io_free((uv_handle_t *)client);
		return;
	}

	/* Set deadlines for TCP connection and start reading.
	 * It will re-check every half of a request time limit if the connection
	 * is idle and should be terminated, this is an educated guess. */
	struct session *session = client->data;
	uv_timer_t *timer = &session->timeout;
	uv_timer_init(master->loop, timer);
	timer->data = client;
	uv_timer_start(timer, tcp_timeout_trigger, KR_CONN_RTT_MAX/2, KR_CONN_RTT_MAX/2);
	io_start_read((uv_handle_t *)client);
}

static int set_tcp_option(uv_tcp_t *handle, int option, int val)
{
	uv_os_fd_t fd = 0;
	if (uv_fileno((uv_handle_t *)handle, &fd) == 0) {
		return setsockopt(fd, IPPROTO_TCP, option, &val, sizeof(val));
	}
	return 0; /* N/A */
}

static int _tcp_bind(uv_tcp_t *handle, struct sockaddr *addr, uv_connection_cb connection)
{
	unsigned flags = 0;
	if (addr->sa_family == AF_INET6) {
		flags |= UV_TCP_IPV6ONLY;
	}

	int ret = uv_tcp_bind(handle, addr, flags);
	if (ret != 0) {
		return ret;
	}

	/* TCP_DEFER_ACCEPT delays accepting connections until there is readable data. */
#ifdef TCP_DEFER_ACCEPT
	if (set_tcp_option(handle, TCP_DEFER_ACCEPT, KR_CONN_RTT_MAX/1000) != 0) {
		kr_log_info("[ io ] tcp_bind (defer_accept): %s\n", strerror(errno));
	}
#endif

	ret = uv_listen((uv_stream_t *)handle, 16, connection);
	if (ret != 0) {
		return ret;
	}

	/* TCP_FASTOPEN enables 1 RTT connection resumptions. */
#ifdef TCP_FASTOPEN
# ifdef __linux__
	(void) set_tcp_option(handle, TCP_FASTOPEN, 16); /* Accepts queue length hint */
# else
	(void) set_tcp_option(handle, TCP_FASTOPEN, 1);  /* Accepts on/off */
# endif
#endif

	handle->data = NULL;
	return 0;
}

int tcp_bind(uv_tcp_t *handle, struct sockaddr *addr)
{
	return _tcp_bind(handle, addr, tcp_accept);
}

void io_create(uv_loop_t *loop, uv_handle_t *handle, int type)
{
	if (type == SOCK_DGRAM) {
		uv_udp_init(loop, (uv_udp_t *)handle);
	} else {
		uv_tcp_init(loop, (uv_tcp_t *)handle);
		uv_tcp_nodelay((uv_tcp_t *)handle, 1);
	}

	struct worker_ctx *worker = loop->data;
	handle->data = session_borrow(worker);
	assert(handle->data);
}

void io_deinit(uv_handle_t *handle)
{
	if (!handle) {
		return;
	}
	uv_loop_t *loop = handle->loop;
	if (loop && loop->data) {
		struct worker_ctx *worker = loop->data;
		session_release(worker, handle->data);
	} else {
		session_free(handle->data);
	}
	handle->data = NULL;
}

void io_free(uv_handle_t *handle)
{
	if (!handle) {
		return;
	}
	io_deinit(handle);
	free(handle);
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
