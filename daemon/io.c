/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/io.h"

#include <assert.h>
#include <contrib/ucw/lib.h>
#include <contrib/ucw/mempool.h>
#include <libknot/errcode.h>
#include <string.h>
#include <sys/resource.h>

#if ENABLE_XDP
	#include <libknot/xdp/xdp.h>
	#include <net/if.h>
#endif

#include "daemon/network.h"
#include "daemon/worker.h"
#include "daemon/tls.h"
#include "daemon/http.h"
#include "daemon/session.h"
#include "contrib/cleanup.h"
#include "lib/utils.h"

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
       uint16_t id = buf->len >= 2 ? (((unsigned char)buf->base[0])<<8) + (unsigned char)buf->base[1] : 0;
       printf("udp_recv: recieved ID %d, %x\n", id, id);
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

		/* Linux 3.15 has IP_PMTUDISC_OMIT which makes sockets
		 * ignore PMTU information and send packets with DF=0.
		 * This mitigates DNS fragmentation attacks by preventing
		 * forged PMTU information.  FreeBSD already has same semantics
		 * without setting the option.
			https://gitlab.nic.cz/knot/knot-dns/-/issues/640
		 */
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_OMIT)
		int omit = IP_PMTUDISC_OMIT;
		if (type == SOCK_DGRAM && addr->sa_family == AF_INET
		    && setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &omit, sizeof(omit))) {
			kr_log_error(
				"[ io ] failed to disable Path MTU discovery for %s UDP: %s\n",
				kr_straddr(addr), strerror(errno));
		}
#endif
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
#if ENABLE_DOH2
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
#endif

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

#if ENABLE_DOH2
static ssize_t tls_send(const uint8_t *buf, const size_t len, struct session *session)
{
	struct tls_ctx *ctx = session_tls_get_server_ctx(session);
	ssize_t sent = 0;
	assert(ctx);

	sent = gnutls_record_send(ctx->c.tls_session, buf, len);
	if (sent < 0) {
		kr_log_verbose("[http] gnutls_record_send failed: %s (%zd)\n",
			       gnutls_strerror_name(sent), sent);
		return kr_error(EIO);
	}
	return sent;
}
#endif

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

			/* Configure ALPN. */
			gnutls_datum_t proto;
			if (!http) {
				proto.data = (unsigned char *)"dot";
				proto.size = 3;
			} else {
				proto.data = (unsigned char *)"h2";
				proto.size = 2;
			}
			unsigned int flags = 0;
#if GNUTLS_VERSION_NUMBER >= 0x030500
			/* Mandatory ALPN means the protocol must match if and
			 * only if ALPN extension is used by the client. */
			flags |= GNUTLS_ALPN_MANDATORY;
#endif
			ret = gnutls_alpn_set_protocols(ctx->c.tls_session, &proto, 1, flags);
			if (ret != GNUTLS_E_SUCCESS) {
				session_close(s);
				return;
			}

			session_tls_set_server_ctx(s, ctx);
		}
	}
#if ENABLE_DOH2
	if (http) {
		struct http_ctx *ctx = session_http_get_server_ctx(s);
		if (!ctx) {
			if (!tls) {  /* Plain HTTP is not supported. */
				session_close(s);
				return;
			}
			ctx = http_new(s, tls_send);
			if (!ctx) {
				session_close(s);
				return;
			}
			session_http_set_server_ctx(s, ctx);
		}
	}
#endif
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

#if ENABLE_DOH2
static void https_accept(uv_stream_t *master, int status)
{
	_tcp_accept(master, status, true, true);
}
#endif

int io_listen_tcp(uv_loop_t *loop, uv_tcp_t *handle, int fd, int tcp_backlog, bool has_tls, bool has_http)
{
	uv_connection_cb connection;

	if (!handle) {
		return kr_error(EINVAL);
	}
	int ret = uv_tcp_init(loop, handle);
	if (ret) return ret;

	if (has_tls && has_http) {
#if ENABLE_DOH2
		connection = https_accept;
#else
		kr_log_error("[ io ] kresd was compiled without libnghttp2 support\n");
		return kr_error(ENOPROTOOPT);
#endif
	} else if (has_tls) {
		connection = tls_accept;
	} else if (has_http) {
		return kr_error(EPROTONOSUPPORT);
	} else {
		connection = tcp_accept;
	}

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


enum io_stream_mode {
	io_mode_text = 0,
	io_mode_binary = 1,
};

struct io_stream_data {
	enum io_stream_mode mode;
	size_t blen; ///< length of `buf`
	char *buf;  ///< growing buffer residing on `pool` (mp_append_*)
	knot_mm_t *pool;
};

/**
 * TTY control: process input and free() the buffer.
 *
 * For parameters see http://docs.libuv.org/en/v1.x/stream.html#c.uv_read_cb
 *
 * - This is just basic read-eval-print; libedit is supported through kresc;
 */
void io_tty_process_input(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	auto_free char *commands = buf ? buf->base : NULL;

	/* Set output streams */
	FILE *out = stdout;
	uv_os_fd_t stream_fd = -1;
	struct args *args = the_args;
	struct io_stream_data *data = (struct io_stream_data*) stream->data;
	if (nread < 0 || uv_fileno((uv_handle_t *)stream, &stream_fd)) {
		mp_delete(data->pool->ctx);
		uv_close((uv_handle_t *)stream, (uv_close_cb) free);
		return;
	}
	if (nread <= 0) {
		return;
	}
	if (stream_fd != STDIN_FILENO) {
		uv_os_fd_t dup_fd = dup(stream_fd);
		if (dup_fd >= 0) {
			out = fdopen(dup_fd, "w");
		}
	}

	/** The current single command and the remaining command(s). */
	char *cmd, *cmd_next = NULL;
	bool incomplete_cmd = false;

	if (!(stream && commands && nread > 0)) {
		goto finish;
	}
	/* Execute */

	if (commands[nread - 1] != '\n') {
		incomplete_cmd = true;
	}
	/* Ensure commands is 0-terminated */
	if (nread >= buf->len) { /* only equality should be possible */
		char *newbuf = realloc(commands, nread + 1);
		if (!newbuf)
			goto finish;
		commands = newbuf;
	}
	commands[nread] = '\0';

	char *boundary = "\n\0";
	cmd = strtok(commands, "\n");
	/* strtok skip '\n' but we need process alone '\n' too */
	if (commands[0] == '\n') {
		cmd_next = cmd;
		cmd = boundary;
	} else {
		cmd_next = strtok(NULL, "\n");
	}

	/** Moving pointer to end of buffer with incomplete command. */
	char *pbuf = data->buf + data->blen;
	lua_State *L = the_worker->engine->L;
	while (cmd != NULL) {
		/* Last command is incomplete - save it and execute later */
		if (incomplete_cmd && cmd_next == NULL) {
			pbuf = mp_append_string(data->pool->ctx, pbuf, cmd);
			mp_append_char(data->pool->ctx, pbuf, '\0');
			data->buf = mp_ptr(data->pool->ctx);
			data->blen = data->blen + strlen(cmd);

			/* There is new incomplete command */
			if (commands[nread - 1] == '\n')
				incomplete_cmd = false;
			goto next_iter;
		}

		/* Process incomplete command from previously call */
		if (data->blen > 0) {
			if (commands[0] != '\n' && commands[0] != '\0') {
				pbuf = mp_append_string(data->pool->ctx, pbuf, cmd);
				mp_append_char(data->pool->ctx, pbuf, '\0');
				data->buf = mp_ptr(data->pool->ctx);
				cmd = data->buf;
			} else {
				cmd = data->buf;
			}
			data->blen = 0;
			pbuf = data->buf;
		}

		/* Pseudo-command for switching to "binary output"; */
		if (strcmp(cmd, "__binary") == 0) {
			data->mode = io_mode_binary;
			goto next_iter;
		}

		int ret = engine_cmd(L, cmd, false);
		const char *message = NULL;
		size_t len_s;
		if (lua_gettop(L) > 0) {
			message = lua_tolstring(L, -1, &len_s);
		}

		/* Simpler output in binary mode */
		if (data->mode == io_mode_binary) {
			/* Leader expects length field in all cases */
			if (!message || len_s > UINT32_MAX) {
				kr_log_error("[io] unrepresentable respose on control socket, "
						"sending back empty block (command '%s')\n", cmd);
				len_s = 0;
			}
			uint32_t len_n = htonl(len_s);
			fwrite(&len_n, sizeof(len_n), 1, out);
			if (len_s > 0)
				fwrite(message, len_s, 1, out);
			goto next_iter;
		}

		/* Log to remote socket if connected */
		const char *delim = args->quiet ? "" : "> ";
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
			if (message && !args->quiet)
				fprintf(fp_out, "\n");
			fprintf(fp_out, "%s", delim);
		}
	next_iter:
		lua_settop(L, 0); /* not required in some cases but harmless */
		cmd = cmd_next;
		cmd_next = strtok(NULL, "\n");
	}

finish:
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

struct io_stream_data *io_tty_alloc_data() {
	knot_mm_t *pool = mm_ctx_mempool2(MM_DEFAULT_BLKSIZE);
	if (!pool) {
		return NULL;
	}
	struct io_stream_data *data = mm_alloc(pool, sizeof(struct io_stream_data));

	data->buf = mp_start(pool->ctx, 512);
	data->mode = io_mode_text;
	data->blen = 0;
	data->pool = pool;

	return data;
}

void io_tty_accept(uv_stream_t *master, int status)
{
	struct io_stream_data *data = io_tty_alloc_data();
	/* We can't use any allocations after mp_start() and it's easier anyway. */
	uv_pipe_t *client = malloc(sizeof(*client));
	client->data = data;

	struct args *args = the_args;
	if (client && client->data) {
		 uv_pipe_init(master->loop, client, 0);
		 if (uv_accept(master, (uv_stream_t *)client) != 0) {
			mp_delete(data->pool->ctx);
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

#if ENABLE_XDP
static void xdp_rx(uv_poll_t* handle, int status, int events)
{
	const int XDP_RX_BATCH_SIZE = 64;
	if (status < 0) {
		kr_log_error("[xdp] poll status %d: %s\n", status, uv_strerror(status));
		return;
	}
	if (events != UV_READABLE) {
		kr_log_error("[xdp] poll unexpected events: %d\n", events);
		return;
	}

	xdp_handle_data_t *xhd = handle->data;
	assert(xhd && xhd->session && xhd->socket);
	uint32_t rcvd;
	knot_xdp_msg_t msgs[XDP_RX_BATCH_SIZE];
	int ret = knot_xdp_recv(xhd->socket, msgs, XDP_RX_BATCH_SIZE, &rcvd
			#if KNOT_VERSION_HEX >= 0x030100
			, NULL
			#endif
			);
	if (ret == KNOT_EOK) {
		kr_log_verbose("[xdp] poll triggered, processing a batch of %d packets\n",
			(int)rcvd);
	} else {
		kr_log_error("[xdp] knot_xdp_recv(): %d, %s\n", ret, knot_strerror(ret));
		assert(false); // ATM it can only be returned when called incorrectly
		return;
	}
	assert(rcvd <= XDP_RX_BATCH_SIZE);
	for (int i = 0; i < rcvd; ++i) {
		const knot_xdp_msg_t *msg = &msgs[i];
		assert(msg->payload.iov_len <= KNOT_WIRE_MAX_PKTSIZE);
		knot_pkt_t *kpkt = knot_pkt_new(msg->payload.iov_base, msg->payload.iov_len,
						&the_worker->pkt_pool);
		if (kpkt == NULL) {
			ret = kr_error(ENOMEM);
		} else {
			ret = worker_submit(xhd->session,
					(const struct sockaddr *)&msg->ip_from,
					(const struct sockaddr *)&msg->ip_to,
					msg->eth_from, msg->eth_to, kpkt);
		}
		if (ret)
			kr_log_verbose("[xdp] worker_submit() == %d: %s\n", ret, kr_strerror(ret));
		mp_flush(the_worker->pkt_pool.ctx);
	}
	knot_xdp_recv_finish(xhd->socket, msgs, rcvd);
}
/// Warn if the XDP program is running in emulated mode (XDP_SKB)
static void xdp_warn_mode(const char *ifname)
{
	assert(ifname);
	const unsigned if_index = if_nametoindex(ifname);
	if (!if_index) {
		kr_log_info("[xdp] warning: interface %s, unexpected error when converting its name: %s\n",
				ifname, strerror(errno));
		return;
	}

	const knot_xdp_mode_t mode = knot_eth_xdp_mode(if_index);
	switch (mode) {
	case KNOT_XDP_MODE_FULL:
		return;
	case KNOT_XDP_MODE_EMUL:
		kr_log_info("[xdp] warning: interface %s running only with XDP emulation\n",
				ifname);
		return;
	case KNOT_XDP_MODE_NONE: // enum warnings from compiler
		break;
	}
	kr_log_info("[xdp] warning: interface %s running in unexpected XDP mode %d\n",
			ifname, (int)mode);
}
int io_listen_xdp(uv_loop_t *loop, struct endpoint *ep, const char *ifname)
{
	if (!ep || !ep->handle) {
		return kr_error(EINVAL);
	}

	// RLIMIT_MEMLOCK often needs raising when operating on BPF
	static int ret_limit = 1;
	if (ret_limit == 1) {
		struct rlimit no_limit = { RLIM_INFINITY, RLIM_INFINITY };
		ret_limit = setrlimit(RLIMIT_MEMLOCK, &no_limit)
			? kr_error(errno) : 0;
	}
	if (ret_limit) return ret_limit;

	xdp_handle_data_t *xhd = malloc(sizeof(*xhd));
	if (!xhd) return kr_error(ENOMEM);

	const int port = ep->port ? ep->port : // all ports otherwise
			#if KNOT_VERSION_HEX >= 0x030100
				(KNOT_XDP_LISTEN_PORT_PASS | 0);
			#else
				KNOT_XDP_LISTEN_PORT_ALL;
			#endif
	xhd->socket = NULL; // needed for some reason
	int ret = knot_xdp_init(&xhd->socket, ifname, ep->nic_queue, port,
				KNOT_XDP_LOAD_BPF_MAYBE);
	if (!ret) xdp_warn_mode(ifname);

	if (!ret) ret = uv_idle_init(loop, &xhd->tx_waker);
	if (ret) {
		free(xhd);
		return kr_error(ret);
	}
	assert(xhd->socket);
	xhd->tx_waker.data = xhd->socket;

	ep->fd = knot_xdp_socket_fd(xhd->socket); // probably not useful
	ret = uv_poll_init(loop, (uv_poll_t *)ep->handle, ep->fd);
	if (ret) {
		knot_xdp_deinit(xhd->socket);
		free(xhd);
		return kr_error(ret);
	}

	// beware: this sets poll_handle->data
	xhd->session = session_new(ep->handle, false, false);
	assert(!session_flags(xhd->session)->outgoing);
	session_get_sockname(xhd->session)->sa_family = AF_XDP; // to have something in there

	ep->handle->data = xhd;
	ret = uv_poll_start((uv_poll_t *)ep->handle, UV_READABLE, xdp_rx);
	return ret;
}
#endif


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

static void io_deinit(uv_handle_t *handle)
{
	if (!handle || !handle->data) {
		return;
	}
	if (handle->type != UV_POLL) {
		session_free(handle->data);
	} else {
	#if ENABLE_XDP
		xdp_handle_data_t *xhd = handle->data;
		uv_idle_stop(&xhd->tx_waker);
		uv_close((uv_handle_t *)&xhd->tx_waker, NULL);
		session_free(xhd->session);
		knot_xdp_deinit(xhd->socket);
		free(xhd);
	#else
		assert(false);
	#endif
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
