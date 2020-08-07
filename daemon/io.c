/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
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
#include "daemon/http.h"
#include "daemon/session.h"

#define negotiate_bufsize(func, handle, bufsize_want) do { \
    int bufsize = 0; (func)((handle), &bufsize); \
	if (bufsize < (bufsize_want)) { \
		bufsize = (bufsize_want); \
		(func)((handle), &bufsize); \
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
	struct session *s = handle->data;
	if (session_flags(s)->closing || nread <= 0 || addr->sa_family == AF_UNSPEC)
		return;

	if (session_flags(s)->outgoing) {
		const struct sockaddr *peer = session_get_peer(s);
		assert(peer->sa_family != AF_UNSPEC);
		if (kr_sockaddr_cmp(peer, addr) != 0) {
			kr_log_verbose("[io] <= ignoring UDP from unexpected address '%s'\n",
					kr_straddr(addr));
			return;
		}
	}
	ssize_t consumed = session_wirebuf_consume(s, (const uint8_t *)buf->base,
						   nread);
	assert(consumed == nread); (void)consumed;
	session_wirebuf_process(s, addr);
	session_wirebuf_discard(s);
	mp_flush(the_worker->pkt_pool.ctx);
}

static int family_to_freebind_option(sa_family_t sa_family, int *level, int *name)
{
	switch (sa_family) {
	case AF_INET:
		*level = IPPROTO_IP;
#if defined(IP_FREEBIND)
		*name = IP_FREEBIND;
#elif defined(IP_BINDANY)
		*name = IP_BINDANY;
#else
		return kr_error(ENOTSUP);
#endif
		break;
	case AF_INET6:
#if defined(IP_FREEBIND)
		*level = IPPROTO_IP;
		*name = IP_FREEBIND;
#elif defined(IPV6_BINDANY)
		*level = IPPROTO_IPV6;
		*name = IPV6_BINDANY;
#else
		return kr_error(ENOTSUP);
#endif
		break;
	default:
		return kr_error(ENOTSUP);
	}
	return kr_ok();
}

int io_bind(const struct sockaddr *addr, int type, const endpoint_flags_t *flags)
{
	const int fd = socket(addr->sa_family, type, 0);
	if (fd < 0) return kr_error(errno);

	int yes = 1;
	if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) {
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)))
			return kr_error(errno);

#ifdef SO_REUSEPORT_LB
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT_LB, &yes, sizeof(yes)))
			return kr_error(errno);
#elif defined(SO_REUSEPORT) && defined(__linux__) /* different meaning on (Free)BSD */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)))
			return kr_error(errno);
#endif

#ifdef IPV6_V6ONLY
		if (addr->sa_family == AF_INET6
		    && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)))
			return kr_error(errno);
#endif
		if (flags != NULL && flags->freebind) {
			int optlevel;
			int optname;
			int ret = family_to_freebind_option(addr->sa_family, &optlevel, &optname);
			if (ret) return kr_error(ret);
			if (setsockopt(fd, optlevel, optname, &yes, sizeof(yes)))
				return kr_error(errno);
		}
	}

	if (bind(fd, addr, kr_sockaddr_len(addr)))
		return kr_error(errno);

	return fd;
}

int io_listen_udp(uv_loop_t *loop, uv_udp_t *handle, int fd)
{
	if (!handle) {
		return kr_error(EINVAL);
	}
	int ret = uv_udp_init(loop, handle);
	if (ret) return ret;

	ret = uv_udp_open(handle, fd);
	if (ret) return ret;

	uv_handle_t *h = (uv_handle_t *)handle;
	check_bufsize(h);
	/* Handle is already created, just create context. */
	struct session *s = session_new(h, false, false);
	assert(s);
	session_flags(s)->outgoing = false;

	int socklen = sizeof(union inaddr);
	ret = uv_udp_getsockname(handle, session_get_sockname(s), &socklen);
	if (ret) {
		kr_log_error("ERROR: getsockname failed: %s\n", uv_strerror(ret));
		abort(); /* It might be nontrivial not to leak something here. */
	}

	return io_start_read(h);
}

void tcp_timeout_trigger(uv_timer_t *timer)
{
	struct session *s = timer->data;

	assert(!session_flags(s)->closing);

	if (!session_tasklist_is_empty(s)) {
		int finalized = session_tasklist_finalize_expired(s);
		the_worker->stats.timeout += finalized;
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
			the_worker->stats.timeout += 1;
			if (session_flags(s)->closing) {
				return;
			}
		}
		const struct network *net = &the_worker->engine->net;
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
				worker_del_tcp_waiting(the_worker, peer);
				worker_del_tcp_connected(the_worker, peer);
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
		if (consumed < 0) {
			if (kr_verbose_status) {
				struct sockaddr *peer = session_get_peer(s);
				char *peer_str = kr_straddr(peer);
				kr_log_verbose("[io] => connection to '%s': "
					       "error processing TLS data, close\n",
					       peer_str ? peer_str : "");
			}
			worker_end_tcp(s);
			return;
		} else if (consumed == 0) {
			return;
		}
		data = session_wirebuf_get_free_start(s);
		data_len = consumed;
	}
	if (session_flags(s)->has_http) {
		consumed = http_process_input_data(s, data, data_len);
		if (consumed < 0) {
			if (kr_verbose_status) {
				struct sockaddr *peer = session_get_peer(s);
				char *peer_str = kr_straddr(peer);
				kr_log_verbose("[io] => connection to '%s': "
				       "error processing HTTP data, close\n",
				       peer_str ? peer_str : "");
			}
			worker_end_tcp(s);
			return;
		} else if (consumed == 0) {
			return;
		}
		data = session_wirebuf_get_free_start(s);
		data_len = consumed;
	}

	/* data points to start of the free space in session wire buffer.
	   Simple increase internal counter. */
	consumed = session_wirebuf_consume(s, data, data_len);
	assert(consumed == data_len);

	int ret = session_wirebuf_process(s, session_get_peer(s));
	if (ret < 0) {
		/* An error has occurred, close the session. */
		worker_end_tcp(s);
	}
	session_wirebuf_compress(s);
	mp_flush(the_worker->pkt_pool.ctx);
}

static void on_write(uv_write_t *req, int status)
{
	struct qr_task *task = req->data;
	if (task) {
		uv_handle_t *h = (uv_handle_t *)req->handle;
		qr_task_on_send(task, h, status);
	}
	free(req);
}

static ssize_t tcp_send(const uint8_t *buffer, const size_t buffer_len, void *user_ctx)
{
	//TODO not complete, probably do not respect the sending policy in the software
	struct session *session = user_ctx;
	uv_handle_t *handle = session_get_handle(session);
	//const uint8_t *buffer_backup = (const uint8_t *)calloc(buffer_len, sizeof(*buffer));
	//if (!buffer_backup) {
	//	return kr_error(EIO);
	//}
	//memcpy(buffer_backup, buffer, buffer_len);

	uv_write_t *req = (uv_write_t *)calloc(1, sizeof(uv_write_t));
	if (!req) {
		return kr_error(EIO);
	}

	const uv_buf_t uv_buffer = {
		//.base = buffer_backup,
		.base = buffer,
		.len = buffer_len
	};
	uv_write(req, (uv_stream_t *)handle, &uv_buffer, 1, on_write);
	return buffer_len;
}

static ssize_t tls_send(const uint8_t *buffer, const size_t buffer_len, void *user_ctx)
{
	struct tls_ctx_t *ctx = user_ctx;
	ssize_t len = 0;
	if ((len = gnutls_record_send(ctx->c.tls_session, buffer, buffer_len)) < 0) {
		return kr_error(EIO);
	}
	return len;
}

static void _tcp_accept(uv_stream_t *master, int status, bool tls, bool http)
{
 	if (status != 0) {
		return;
	}

	struct worker_ctx *worker = the_worker;
	uv_tcp_t *client = malloc(sizeof(uv_tcp_t));
	if (!client) {
		return;
	}
	int res = io_create(master->loop, (uv_handle_t *)client,
			    SOCK_STREAM, AF_UNSPEC, tls, http);
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

	/* Get peer's and our address.  We apparently get specific sockname here
	 * even if we listened on a wildcard address. */
	struct sockaddr *sa = session_get_peer(s);
	int sa_len = sizeof(struct sockaddr_in6);
	int ret = uv_tcp_getpeername(client, sa, &sa_len);
	if (ret || sa->sa_family == AF_UNSPEC) {
		session_close(s);
		return;
	}
	sa = session_get_sockname(s);
	sa_len = sizeof(struct sockaddr_in6);
	ret = uv_tcp_getsockname(client, sa, &sa_len);
	if (ret || sa->sa_family == AF_UNSPEC) {
		session_close(s);
		return;
	}

	/* Set deadlines for TCP connection and start reading.
	 * It will re-check every half of a request time limit if the connection
	 * is idle and should be terminated, this is an educated guess. */

	const struct network *net = &worker->engine->net;
	uint64_t idle_in_timeout = net->tcp.in_idle_timeout;

	uint64_t timeout = KR_CONN_RTT_MAX / 2;
	if (tls) {
		timeout += TLS_MAX_HANDSHAKE_TIME;
		struct tls_ctx *ctx = session_tls_get_server_ctx(s);
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
	if (http) {
		struct http_ctx_t *ctx = session_http_get_server_ctx(s);
		if (!ctx) {
			ctx = http_new((tls) ? tls_send : tcp_send,
			               (tls) ? (void*)session_tls_get_server_ctx(s) : (void*)s
			);
			if (!ctx) {
				session_close(s);
				return;
			}

			struct tls_ctx_t *tls_ctx = session_tls_get_server_ctx(s);
			if (tls_ctx) {
				const gnutls_datum_t protos[] = {
					{(unsigned char *)"h2", 2}
				};
				ret = gnutls_alpn_set_protocols(tls_ctx->c.tls_session,
				                                protos, sizeof(protos)/sizeof(*protos),
												0);
				if (ret != GNUTLS_E_SUCCESS) {
					session_close(s);
					return;
				}
			}
			session_http_set_server_ctx(s, ctx);
		}
	}
	session_timer_start(s, tcp_timeout_trigger, timeout, idle_in_timeout);
	io_start_read((uv_handle_t *)client);
}

static void tcp_accept(uv_stream_t *master, int status)
{
	_tcp_accept(master, status, false, false);
}

static void tls_accept(uv_stream_t *master, int status)
{
	_tcp_accept(master, status, true, false);
}

static void http_accept(uv_stream_t *master, int status)
{
	_tcp_accept(master, status, false, true);
}

static void https_accept(uv_stream_t *master, int status)
{
	_tcp_accept(master, status, true, true);
}

int io_listen_tcp(uv_loop_t *loop, uv_tcp_t *handle, int fd, int tcp_backlog, bool has_tls, bool has_http)
{
	uv_connection_cb connection;
	if (has_tls && has_http) {
		connection = https_accept;
	} else if (has_tls) {
		connection = tls_accept;
	} else if (has_http) {
		connection = http_accept;
	} else {
		connection = tcp_accept;
	}

	if (!handle) {
		return kr_error(EINVAL);
	}
	int ret = uv_tcp_init(loop, handle);
	if (ret) return ret;

	ret = uv_tcp_open(handle, (uv_os_sock_t) fd);
	if (ret) return ret;

	int val; (void)val;
	/* TCP_DEFER_ACCEPT delays accepting connections until there is readable data. */
#ifdef TCP_DEFER_ACCEPT
	val = KR_CONN_RTT_MAX/1000;
	if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &val, sizeof(val))) {
		kr_log_error("[ io ] listen TCP (defer_accept): %s\n", strerror(errno));
	}
#endif

	ret = uv_listen((uv_stream_t *)handle, tcp_backlog, connection);
	if (ret != 0) {
		return ret;
	}

	/* TCP_FASTOPEN enables 1 RTT connection resumptions. */
#ifdef TCP_FASTOPEN
	#ifdef __linux__
	val = 16; /* Accepts queue length hint */
	#else
	val = 1; /* Accepts on/off */
	#endif
	if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &val, sizeof(val))) {
		kr_log_error("[ io ] listen TCP (fastopen): %s%s\n", strerror(errno),
			(errno != EPERM ? "" :
			 ".  This may be caused by TCP Fast Open being disabled in the OS."));
	}
#endif

	handle->data = NULL;
	return 0;
}

/**
 * TTY control: process input and free() the buffer.
 *
 * For parameters see http://docs.libuv.org/en/v1.x/stream.html#c.uv_read_cb
 *
 * - This is just basic read-eval-print; libedit is supported through kresc;
 */
void io_tty_process_input(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	char *commands = buf ? buf->base : NULL; /* To be free()d on return. */

	/* Set output streams */
	FILE *out = stdout;
	uv_os_fd_t stream_fd = 0;
	struct args *args = the_args;
	if (uv_fileno((uv_handle_t *)stream, &stream_fd)) {
		uv_close((uv_handle_t *)stream, (uv_close_cb) free);
		free(commands);
		return;
	}
	if (stream_fd != STDIN_FILENO) {
		if (nread < 0) { /* Close if disconnected */
			uv_close((uv_handle_t *)stream, (uv_close_cb) free);
		}
		if (nread <= 0) {
			free(commands);
			return;
		}
		uv_os_fd_t dup_fd = dup(stream_fd);
		if (dup_fd >= 0) {
			out = fdopen(dup_fd, "w");
		}
	}

	char *cmd = NULL;
	/* Execute */
	if (stream && commands && nread > 0) {
		/* Ensure commands is 0-terminated */
		if (commands[nread - 1] == '\n') {
			commands[nread - 1] = '\0';
		} else {
			if (nread >= buf->len) { /* only equality should be possible */
				char *newbuf = realloc(commands, nread + 1);
				if (!newbuf)
					goto finish;
				commands = newbuf;
			}
			commands[nread] = '\0';
		}

		const char *delim = args->quiet ? "" : "> ";

		/* No command, just new line */
		if (nread == 1 && args->tty_binary_output == false && commands[nread-1] == '\0') {
			if (stream_fd != STDIN_FILENO) {
				fprintf(out, "%s", delim);
			}
			if (stream_fd == STDIN_FILENO || VERBOSE_STATUS) {
				fprintf(stdout, "%s", delim);
			}
		}

		cmd = strtok(commands, "\n");
		while (cmd != NULL) {
			/* Pseudo-command for switching to "binary output"; */
			if (strcmp(cmd, "__binary") == 0) {
				args->tty_binary_output = true;
				cmd = strtok(NULL, "\n");
				continue;
			}

			lua_State *L = the_worker->engine->L;
			int ret = engine_cmd(L, cmd, false);
			const char *message = "";
			if (lua_gettop(L) > 0) {
				message = lua_tostring(L, -1);
			}

			/* Simpler output in binary mode */
			if (args->tty_binary_output) {
				size_t len_s = strlen(message);
				if (len_s > UINT32_MAX) {
					cmd = strtok(NULL, "\n");
					continue;
				}
				uint32_t len_n = htonl(len_s);
				fwrite(&len_n, sizeof(len_n), 1, out);
				fwrite(message, len_s, 1, out);
				lua_settop(L, 0);
				cmd = strtok(NULL, "\n");
				continue;
			}
			/* Log to remote socket if connected */
			if (stream_fd != STDIN_FILENO) {
				if (VERBOSE_STATUS)
					fprintf(stdout, "%s\n", cmd); /* Duplicate command to logs */
				if (message)
					fprintf(out, "%s", message); /* Duplicate output to sender */
				if (message || !args->quiet)
					fprintf(out, "\n");
				fprintf(out, "%s", delim);
			}
			if (stream_fd == STDIN_FILENO || VERBOSE_STATUS) {
				/* Log to standard streams */
				FILE *fp_out = ret ? stderr : stdout;
				if (message)
					fprintf(fp_out, "%s", message);
				if (message || !args->quiet)
					fprintf(fp_out, "\n");
				fprintf(fp_out, "%s", delim);
			}
			lua_settop(L, 0);
			cmd = strtok(NULL, "\n");
		}
	}
finish:
	free(commands);
	/* Close if redirected */
	if (stream_fd != STDIN_FILENO) {
		fclose(out);
	}
}

void io_tty_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf)
{
	buf->len = suggested;
	buf->base = malloc(suggested);
}

void io_tty_accept(uv_stream_t *master, int status)
{
	uv_tcp_t *client = malloc(sizeof(*client));
	struct args *args = the_args;
	if (client) {
		 uv_tcp_init(master->loop, client);
		 if (uv_accept(master, (uv_stream_t *)client) != 0) {
			free(client);
			return;
		 }
		 uv_read_start((uv_stream_t *)client, io_tty_alloc, io_tty_process_input);
		 /* Write command line */
		 if (!args->quiet) {
			uv_buf_t buf = { "> ", 2 };
			uv_try_write((uv_stream_t *)client, &buf, 1);
		 }
	}
}

int io_listen_pipe(uv_loop_t *loop, uv_pipe_t *handle, int fd)
{
	if (!handle) {
		return kr_error(EINVAL);
	}
	int ret = uv_pipe_init(loop, handle, 0);
	if (ret) return ret;

	ret = uv_pipe_open(handle, fd);
	if (ret) return ret;

	ret = uv_listen((uv_stream_t *)handle, 16, io_tty_accept);
	if (ret) return ret;

	handle->data = NULL;

	return 0;
}

int io_create(uv_loop_t *loop, uv_handle_t *handle, int type, unsigned family, bool has_tls, bool has_http)
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
	struct session *s = session_new(handle, has_tls, has_http);
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
	if (handle->data) {
		session_free(handle->data);
		handle->data = NULL;
	}
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
