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
#include "daemon/worker.h"
#include "daemon/tls.h"
#include "daemon/session.h"

#define negotiate_bufsize(func, handle, bufsize_want) do { \
    int bufsize = 0; func(handle, &bufsize); \
	if (bufsize < bufsize_want) { \
		bufsize = bufsize_want; \
		func(handle, &bufsize); \
	} \
} while (0)

static void check_bufsize(uv_handle_t* handle)
{
	return; /* TODO: resurrect after https://github.com/libuv/libuv/issues/419 */
	/* We want to buffer at least N waves in advance.
	 * This is magic presuming we can pull in a whole recvmmsg width in one wave.
	 * Linux will double this the bufsize wanted.
	 */
	const int bufsize_want = 2 * sizeof( ((struct worker_ctx *)NULL)->wire_buf ) ;
	negotiate_bufsize(uv_recv_buffer_size, handle, bufsize_want);
	negotiate_bufsize(uv_send_buffer_size, handle, bufsize_want);
}

#undef negotiate_bufsize

static void handle_getbuf(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	/* UDP sessions use worker buffer for wire data,
	 * TCP sessions use session buffer for wire data
	 * (see session_set_handle()).
	 * TLS sessions use buffer from TLS context.
	 * The content of the worker buffer is
	 * guaranteed to be unchanged only for the duration of
	 * udp_read() and tcp_read().
	 */
	struct session *s = handle->data;
	if (!session_flags(s)->has_tls) {
		buf->base = (char *) session_wirebuf_get_free_start(s);
		buf->len = session_wirebuf_get_free_size(s);
	} else {
		struct tls_common_ctx *ctx = session_tls_get_common_ctx(s);
		buf->base = (char *) ctx->recv_buf;
		buf->len = sizeof(ctx->recv_buf);
	}
}

void udp_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
	const struct sockaddr *addr, unsigned flags)
{
	uv_loop_t *loop = handle->loop;
	struct worker_ctx *worker = loop->data;
	struct session *s = handle->data;
	if (session_flags(s)->closing) {
		return;
	}
	if (nread <= 0) {
		if (nread < 0) { /* Error response, notify resolver */
			worker_submit(s, NULL);
		} /* nread == 0 is for freeing buffers, we don't need to do this */
		return;
	}
	if (addr->sa_family == AF_UNSPEC) {
		return;
	}
	struct sockaddr *peer = session_get_peer(s);
	if (session_flags(s)->outgoing) {
		assert(peer->sa_family != AF_UNSPEC);
		if (kr_sockaddr_cmp(peer, addr) != 0) {
			return;
		}
	} else {
		memcpy(peer, addr, kr_sockaddr_len(addr));
	}
	ssize_t consumed = session_wirebuf_consume(s, (const uint8_t *)buf->base,
						   nread);
	assert(consumed == nread); (void)consumed;
	session_wirebuf_process(s);
	session_wirebuf_discard(s);
	mp_flush(worker->pkt_pool.ctx);
}

static int udp_bind_finalize(uv_handle_t *handle)
{
	check_bufsize(handle);
	/* Handle is already created, just create context. */
	struct session *s = session_new(handle, false);
	assert(s);
	session_flags(s)->outgoing = false;
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

void tcp_timeout_trigger(uv_timer_t *timer)
{
	struct session *s = timer->data;

	assert(!session_flags(s)->closing);

	struct worker_ctx *worker = timer->loop->data;

	if (!session_tasklist_is_empty(s)) {
		int finalized = session_tasklist_finalize_expired(s);
		worker->stats.timeout += finalized;
		/* session_tasklist_finalize_expired() may call worker_task_finalize().
		 * If session is a source session and there were IO errors,
		 * worker_task_finalize() can filnalize all tasks and close session. */
		if (session_flags(s)->closing) {
			return;
		}

	}
	if (!session_tasklist_is_empty(s)) {
		uv_timer_stop(timer);
		session_timer_start(s, tcp_timeout_trigger,
				    KR_RESOLVE_TIME_LIMIT / 2,
				    KR_RESOLVE_TIME_LIMIT / 2);
	} else {
		/* Normally it should not happen,
		 * but better to check if there anything in this list. */
		while (!session_waitinglist_is_empty(s)) {
			struct qr_task *t = session_waitinglist_pop(s, false);
			worker_task_finalize(t, KR_STATE_FAIL);
			worker_task_unref(t);
			worker->stats.timeout += 1;
			if (session_flags(s)->closing) {
				return;
			}
		}
		const struct engine *engine = worker->engine;
		const struct network *net = &engine->net;
		uint64_t idle_in_timeout = net->tcp.in_idle_timeout;
		uint64_t last_activity = session_last_activity(s);
		uint64_t idle_time = kr_now() - last_activity;
		if (idle_time < idle_in_timeout) {
			idle_in_timeout -= idle_time;
			uv_timer_stop(timer);
			session_timer_start(s, tcp_timeout_trigger,
					    idle_in_timeout, idle_in_timeout);
		} else {
			struct sockaddr *peer = session_get_peer(s);
			char *peer_str = kr_straddr(peer);
			kr_log_verbose("[io] => closing connection to '%s'\n",
				       peer_str ? peer_str : "");
			if (session_flags(s)->outgoing) {
				worker_del_tcp_waiting(worker, peer);
				worker_del_tcp_connected(worker, peer);
			}
			session_close(s);
		}
	}
}

static void tcp_recv(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
	struct session *s = handle->data;
	assert(s && session_get_handle(s) == (uv_handle_t *)handle &&
	       handle->type == UV_TCP);	

	if (session_flags(s)->closing) {
		return;
	}

	/* nread might be 0, which does not indicate an error or EOF.
	 * This is equivalent to EAGAIN or EWOULDBLOCK under read(2). */
	if (nread == 0) {
		return;
	}

	if (nread < 0 || !buf->base) {
		if (kr_verbose_status) {
			struct sockaddr *peer = session_get_peer(s);
			char *peer_str = kr_straddr(peer);
			kr_log_verbose("[io] => connection to '%s' closed by peer (%s)\n",
				       peer_str ? peer_str : "",
				       uv_strerror(nread));
		}
		worker_end_tcp(s);
		return;
	}

	ssize_t consumed = 0;
	const uint8_t *data = (const uint8_t *)buf->base;
	ssize_t data_len = nread;
	if (session_flags(s)->has_tls) {
		/* buf->base points to start of the tls receive buffer.
		   Decode data free space in session wire buffer. */
		consumed = tls_process_input_data(s, (const uint8_t *)buf->base, nread);
		if (consumed <= 0) {
			return;
		}
		data = session_wirebuf_get_free_start(s);
		data_len = consumed;
	}

	/* data points to start of the free space in session wire buffer.
	   Simple increase internal counter. */
	consumed = session_wirebuf_consume(s, data, data_len);
	assert(consumed == data_len);

	int ret = session_wirebuf_process(s);
	if (ret < 0) {
		/* An error has occurred, close the session. */
		worker_end_tcp(s);
	}
	session_wirebuf_compress(s);
	struct worker_ctx *worker = handle->loop->data;
	mp_flush(worker->pkt_pool.ctx);
}

static void _tcp_accept(uv_stream_t *master, int status, bool tls)
{
 	if (status != 0) {
		return;
	}

	struct worker_ctx *worker = (struct worker_ctx *)master->loop->data;
	uv_tcp_t *client = malloc(sizeof(uv_tcp_t));
	if (!client) {
		return;
	}
	int res = io_create(master->loop, (uv_handle_t *)client,
			    SOCK_STREAM, AF_UNSPEC, tls);
	if (res) {
		if (res == UV_EMFILE) {
			worker->too_many_open = true;
			worker->rconcurrent_highwatermark = worker->stats.rconcurrent;
		}
		/* Since res isn't OK struct session wasn't allocated \ borrowed.
		 * We must release client handle only.
		 */
		free(client);
		return;
	}

	/* struct session was allocated \ borrowed from memory pool. */
	struct session *s = client->data;
	assert(session_flags(s)->outgoing == false);
	assert(session_flags(s)->has_tls == tls);

	if (uv_accept(master, (uv_stream_t *)client) != 0) {
		/* close session, close underlying uv handles and
		 * deallocate (or return to memory pool) memory. */
		session_close(s);
		return;
	}

	/* Set deadlines for TCP connection and start reading.
	 * It will re-check every half of a request time limit if the connection
	 * is idle and should be terminated, this is an educated guess. */
	struct sockaddr *peer = session_get_peer(s);
	int peer_len = sizeof(union inaddr);
	int ret = uv_tcp_getpeername(client, peer, &peer_len);
	if (ret || peer->sa_family == AF_UNSPEC) {
		session_close(s);
		return;
	}

	const struct engine *engine = worker->engine;
	const struct network *net = &engine->net;
	uint64_t idle_in_timeout = net->tcp.in_idle_timeout;

	uint64_t timeout = KR_CONN_RTT_MAX / 2;
	if (tls) {
		timeout += TLS_MAX_HANDSHAKE_TIME;
		struct tls_ctx_t *ctx = session_tls_get_server_ctx(s);
		if (!ctx) {
			ctx = tls_new(worker);
			if (!ctx) {
				session_close(s);
				return;
			}
			ctx->c.session = s;
			ctx->c.handshake_state = TLS_HS_IN_PROGRESS;
			session_tls_set_server_ctx(s, ctx);
		}
	}
	session_timer_start(s, tcp_timeout_trigger, timeout, idle_in_timeout);
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

int io_create(uv_loop_t *loop, uv_handle_t *handle, int type, unsigned family, bool has_tls)
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
	struct session *s = session_new(handle, has_tls);
	if (s == NULL) {
		ret = -1;
	}
	return ret;
}

void io_deinit(uv_handle_t *handle)
{
	if (!handle) {
		return;
	}
	session_free(handle->data);
	handle->data = NULL;
}

void io_free(uv_handle_t *handle)
{
	io_deinit(handle);
	free(handle);
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
