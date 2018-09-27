/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <libknot/errcode.h>
#include <contrib/ucw/lib.h>
#include <contrib/ucw/mempool.h>
#include <assert.h>

#include "daemon/io.h"
#include "daemon/network.h"
#include "daemon/proxyprotocol.h"
#include "daemon/worker.h"
#include "daemon/tls.h"

#define negotiate_bufsize(func, handle, bufsize_want) do { \
    int bufsize = 0; func(handle, &bufsize); \
	if (bufsize < bufsize_want) { \
		bufsize = bufsize_want; \
		func(handle, &bufsize); \
	} \
} while (0)

void io_release(uv_handle_t *handle);

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
	assert(s->tasks.len == 0 && s->waiting.len == 0);
	array_clear(s->tasks);
	array_clear(s->waiting);
	tls_free(s->tls_ctx);
	tls_client_ctx_free(s->tls_client_ctx);
	memset(s, 0, sizeof(*s));
}

void session_free(struct session *s)
{
	if (s) {
		assert(s->tasks.len == 0 && s->waiting.len == 0);
		session_clear(s);
		free(s);
	}
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

static void session_release(struct worker_ctx *worker, uv_handle_t *handle)
{
	if (!worker || !handle) {
		return;
	}
	struct session *s = handle->data;
	if (!s) {
		return;
	}
	assert(s->waiting.len == 0 && s->tasks.len == 0);
	assert(s->buffering == NULL);
	if (!s->outgoing && handle->type == UV_TCP) {
		worker_end_tcp(worker, handle); /* to free the buffering task */
	}
	if (worker->pool_sessions.len < MP_FREELIST_SIZE) {
		session_clear(s);
		array_push(worker->pool_sessions, s);
		kr_asan_poison(s, sizeof(*s));
	} else {
		session_free(s);
	}
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
	} else if (session->outgoing) {
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
	struct session *s = handle->data;
	if (s->closing) {
		return;
	}
	if (nread <= 0) {
		if (nread < 0) { /* Error response, notify resolver */
			worker_submit(worker, (uv_handle_t *)handle, NULL, addr);
		} /* nread == 0 is for freeing buffers, we don't need to do this */
		return;
	}
	if (addr->sa_family == AF_UNSPEC) {
		return;
	}
	if (s->outgoing) {
		assert(s->peer.ip.sa_family != AF_UNSPEC);
		if (kr_sockaddr_cmp(&s->peer.ip, addr) != 0) {
			return;
		}
	} else if (proxy_protocol_parse((uv_handle_t *)handle, &nread,
			(uv_buf_t *)buf) != kr_ok()) {
		return;
	}

	knot_pkt_t *query = knot_pkt_new(buf->base, nread, &worker->pkt_pool);
	if (query) {
		query->max_size = KNOT_WIRE_MAX_PKTSIZE;
		worker_submit(worker, (uv_handle_t *)handle, query, addr);
	}
	mp_flush(worker->pkt_pool.ctx);
}

static int udp_bind_finalize(uv_handle_t *handle)
{
	check_bufsize(handle);
	/* Handle is already created, just create context. */
	struct session *session = session_new();
	assert(session);
	session->outgoing = false;
	session->handle = handle;
	handle->data = session;
	return io_start_read(handle);
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
	return udp_bind_finalize((uv_handle_t *)handle);
}

int udp_bindfd(uv_udp_t *handle, int fd)
{
	if (!handle) {
		return kr_error(EINVAL);
	}

	int ret = uv_udp_open(handle, (uv_os_sock_t) fd);
	if (ret != 0) {
		return ret;
	}
	return udp_bind_finalize((uv_handle_t *)handle);
}

static void tcp_timeout_trigger(uv_timer_t *timer)
{
	struct session *session = timer->data;

	assert(session->outgoing == false);
	if (session->tasks.len > 0) {
		uv_timer_again(timer);
	} else if (!session->closing) {
		uv_timer_stop(timer);
		worker_session_close(session);
	}
}

static void tcp_recv(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
	uv_loop_t *loop = handle->loop;
	struct session *s = handle->data;
	if (s->closing) {
		return;
	}
	/* nread might be 0, which does not indicate an error or EOF.
	 * This is equivalent to EAGAIN or EWOULDBLOCK under read(2). */
	if (nread == 0) {
		return;
	}
	if (nread == UV_EOF) {
		nread = 0;
	}

	if (!s->outgoing && proxy_protocol_parse((uv_handle_t *)handle, &nread,
			(uv_buf_t *)buf) != kr_ok()) {
		return;
	}

	struct worker_ctx *worker = loop->data;
	/* TCP pipelining is rather complicated and requires cooperation from the worker
	 * so the whole message reassembly and demuxing logic is inside worker */
	int ret = 0;
	if (s->has_tls) {
		ret = tls_process(worker, handle, (const uint8_t *)buf->base, nread);
	} else {
		ret = worker_process_tcp(worker, handle, (const uint8_t *)buf->base, nread);
	}
	if (ret < 0) {
		worker_end_tcp(worker, (uv_handle_t *)handle);
		/* Exceeded per-connection quota for outstanding requests
		 * stop reading from stream and close after last message is processed. */
		if (!s->outgoing && !uv_is_closing((uv_handle_t *)&s->timeout)) {
			uv_timer_stop(&s->timeout);
			if (s->tasks.len == 0) {
				worker_session_close(s);
			} else { /* If there are tasks running, defer until they finish. */
				uv_timer_start(&s->timeout, tcp_timeout_trigger,
					       MAX_TCP_INACTIVITY, MAX_TCP_INACTIVITY);
			}
		}
	/* Connection spawned at least one request, reset its deadline for next query.
	 * https://tools.ietf.org/html/rfc7766#section-6.2.3 */
	} else if (ret > 0 && !s->outgoing && !s->closing) {
		uv_timer_again(&s->timeout);
	}
	mp_flush(worker->pkt_pool.ctx);
}

static void _tcp_accept(uv_stream_t *master, int status, bool tls)
{
	if (status != 0) {
		return;
	}

	struct worker_ctx *worker = (struct worker_ctx *)master->loop->data;
	uv_stream_t *client = worker_iohandle_borrow(worker);
	if (!client) {
		return;
	}
	memset(client, 0, sizeof(*client));
	int res = io_create(master->loop, (uv_handle_t *)client, SOCK_STREAM, 0);
	if (res) {
		if (res == UV_EMFILE) {
			worker->too_many_open = true;
			worker->rconcurrent_highwatermark = worker->stats.rconcurrent;
		}
		worker_iohandle_release(worker, client);
		return;
	}

	/* struct session was allocated \ borrowed from memory pool. */
	struct session *session = client->data;
	assert(session->outgoing == false);

	if (uv_accept(master, client) != 0) {
		/* close session, close underlying uv handles and
	     * deallocate (or return to memory pool) memory. */
		worker_session_close(session);
		return;
	}

	/* Set deadlines for TCP connection and start reading.
	 * It will re-check every half of a request time limit if the connection
	 * is idle and should be terminated, this is an educated guess. */
	struct sockaddr *addr = &(session->peer.ip);
	int addr_len = sizeof(union inaddr);
	int ret = uv_tcp_getpeername((uv_tcp_t *)client, addr, &addr_len);
	if (ret || addr->sa_family == AF_UNSPEC) {
		worker_session_close(session);
		return;
	}

	const struct engine *engine = worker->engine;
	const struct network *net = &engine->net;
	uint64_t idle_in_timeout = net->tcp.in_idle_timeout;

	uint64_t timeout = KR_CONN_RTT_MAX / 2;
	session->has_tls = tls;
	if (tls) {
		timeout += TLS_MAX_HANDSHAKE_TIME;
		if (!session->tls_ctx) {
			session->tls_ctx = tls_new(master->loop->data);
			if (!session->tls_ctx) {
				worker_session_close(session);
				return;
			}
			session->tls_ctx->c.session = session;
			session->tls_ctx->c.handshake_state = TLS_HS_IN_PROGRESS;
		}
	}
	uv_timer_t *timer = &session->timeout;
	uv_timer_start(timer, tcp_timeout_trigger, timeout, idle_in_timeout);
	io_start_read((uv_handle_t *)client);
}

static void tcp_accept(uv_stream_t *master, int status)
{
	_tcp_accept(master, status, false);
}

static void tls_accept(uv_stream_t *master, int status)
{
	_tcp_accept(master, status, true);
}

static int set_tcp_option(uv_handle_t *handle, int option, int val)
{
	uv_os_fd_t fd = 0;
	if (uv_fileno(handle, &fd) == 0) {
		return setsockopt(fd, IPPROTO_TCP, option, &val, sizeof(val));
	}
	return 0; /* N/A */
}

static int tcp_bind_finalize(uv_handle_t *handle)
{
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

static int _tcp_bind(uv_tcp_t *handle, struct sockaddr *addr, uv_connection_cb connection, int tcp_backlog)
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
	if (set_tcp_option((uv_handle_t *)handle, TCP_DEFER_ACCEPT, KR_CONN_RTT_MAX/1000) != 0) {
		kr_log_info("[ io ] tcp_bind (defer_accept): %s\n", strerror(errno));
	}
#endif

	ret = uv_listen((uv_stream_t *)handle, tcp_backlog, connection);
	if (ret != 0) {
		return ret;
	}

	return tcp_bind_finalize((uv_handle_t *)handle);
}

int tcp_bind(uv_tcp_t *handle, struct sockaddr *addr, int tcp_backlog)
{
	return _tcp_bind(handle, addr, tcp_accept, tcp_backlog);
}

int tcp_bind_tls(uv_tcp_t *handle, struct sockaddr *addr, int tcp_backlog)
{
	return _tcp_bind(handle, addr, tls_accept, tcp_backlog);
}

static int _tcp_bindfd(uv_tcp_t *handle, int fd, uv_connection_cb connection, int tcp_backlog)
{
	if (!handle) {
		return kr_error(EINVAL);
	}

	int ret = uv_tcp_open(handle, (uv_os_sock_t) fd);
	if (ret != 0) {
		return ret;
	}

	ret = uv_listen((uv_stream_t *)handle, tcp_backlog, connection);
	if (ret != 0) {
		return ret;
	}
	return tcp_bind_finalize((uv_handle_t *)handle);
}

int tcp_bindfd(uv_tcp_t *handle, int fd, int tcp_backlog)
{
	return _tcp_bindfd(handle, fd, tcp_accept, tcp_backlog);
}

int tcp_bindfd_tls(uv_tcp_t *handle, int fd, int tcp_backlog)
{
	return _tcp_bindfd(handle, fd, tls_accept, tcp_backlog);
}

int io_create(uv_loop_t *loop, uv_handle_t *handle, int type, unsigned family)
{
	int ret = -1;
	if (type == SOCK_DGRAM) {
		ret = uv_udp_init(loop, (uv_udp_t *)handle);
	} else if (type == SOCK_STREAM) {
		ret = uv_tcp_init_ex(loop, (uv_tcp_t *)handle, family);
		uv_tcp_nodelay((uv_tcp_t *)handle, 1);
	}

	if (ret != 0) {
		return ret;
	}

	struct worker_ctx *worker = loop->data;
	struct session *session = session_borrow(worker);
	assert(session);
	session->handle = handle;
	handle->data = session;
	session->timeout.data = session;
	uv_timer_init(worker->loop, &session->timeout);
	return ret;
}

void io_deinit(uv_handle_t *handle)
{
	if (!handle) {
		return;
	}
	uv_loop_t *loop = handle->loop;
	if (loop && loop->data) {
		struct worker_ctx *worker = loop->data;
		session_release(worker, handle);
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

void io_release(uv_handle_t *handle)
{
	if (!handle) {
		return;
	}
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;
	io_deinit(handle);
	worker_iohandle_release(worker, handle);
}

int io_start_read(uv_handle_t *handle)
{
	switch (handle->type) {
	case UV_UDP:
		return uv_udp_recv_start((uv_udp_t *)handle, &handle_getbuf, &udp_recv);
	case UV_TCP:
		return uv_read_start((uv_stream_t *)handle, &handle_getbuf, &tcp_recv);
	default:
		assert(!EINVAL);
		return kr_error(EINVAL);
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
