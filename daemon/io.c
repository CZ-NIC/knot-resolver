/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/io.h"

#include <contrib/ucw/lib.h>
#include <contrib/ucw/mempool.h>
#include <libknot/errcode.h>
#include <string.h>
#include <sys/resource.h>

#if ENABLE_XDP
	#include <libknot/xdp/eth.h>
	#include <libknot/xdp/xdp.h>
	#include <net/if.h>
#endif

#include "daemon/network.h"
#include "daemon/worker.h"
#include "daemon/tls.h"
#include "daemon/session2.h"
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
	const int BUF_SIZE = 2 * RECVMMSG_BATCH * KNOT_WIRE_MAX_PKTSIZE;
	negotiate_bufsize(uv_recv_buffer_size, handle, BUF_SIZE);
	negotiate_bufsize(uv_send_buffer_size, handle, BUF_SIZE);
}

#undef negotiate_bufsize

static void handle_getbuf(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	struct session2 *s = handle->data;
	struct wire_buf *wb = &s->wire_buf;

	buf->base = wire_buf_free_space(wb);
	buf->len = wire_buf_free_space_length(wb);
}

static void udp_on_unwrapped(int status, struct session2 *session,
                             const struct comm_info *comm, void *baton)
{
	wire_buf_reset(&session->wire_buf);
}

void udp_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
	const struct sockaddr *comm_addr, unsigned flags)
{
	struct session2 *s = handle->data;
	if (s->closing || nread <= 0 || comm_addr->sa_family == AF_UNSPEC)
		return;

	if (!the_network->enable_connect_udp && s->outgoing) {
		const struct sockaddr *peer = session2_get_peer(s);
		if (kr_fails_assert(peer->sa_family != AF_UNSPEC))
			return;
		if (kr_sockaddr_cmp(peer, comm_addr) != 0) {
			kr_log_debug(IO, "<= ignoring UDP from unexpected address '%s'\n",
					kr_straddr(comm_addr));
			return;
		}
	}

	if (!s->outgoing && kr_inaddr_port(comm_addr) < the_network->min_udp_source_port) {
		kr_log_debug(IO, "<= ignoring UDP from suspicious port: '%s'\n",
				kr_straddr(comm_addr));
		return;
	}

	int ret = wire_buf_consume(&s->wire_buf, nread);
	if (ret) {
		wire_buf_reset(&s->wire_buf);
		return;
	}

	struct comm_info in_comm = {
		.comm_addr = comm_addr,
		.src_addr = comm_addr
	};
	session2_unwrap(s, protolayer_payload_wire_buf(&s->wire_buf, true),
			&in_comm, udp_on_unwrapped, NULL);
}

static int family_to_freebind_option(sa_family_t sa_family, int *level, int *name)
{
#define LOG_NO_FB kr_log_error(NETWORK, "your system does not support 'freebind', " \
				"please remove it from your configuration\n")
	switch (sa_family) {
	case AF_INET:  // NOLINT(bugprone-branch-clone): The branches are only cloned for specific macro configs
		*level = IPPROTO_IP;
#if defined(IP_FREEBIND)
		*name = IP_FREEBIND;
#elif defined(IP_BINDANY)
		*name = IP_BINDANY;
#else
		LOG_NO_FB;
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
		LOG_NO_FB;
		return kr_error(ENOTSUP);
#endif
		break;
	default:
		return kr_error(ENOTSUP);
	}
	return kr_ok();
}


static enum protolayer_event_cb_result pl_udp_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if (event == PROTOLAYER_EVENT_STATS_SEND_ERR) {
		the_worker->stats.err_udp += 1;
		return PROTOLAYER_EVENT_CONSUME;
	} else if (event == PROTOLAYER_EVENT_STATS_QRY_OUT) {
		the_worker->stats.udp += 1;
		return PROTOLAYER_EVENT_CONSUME;
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

static int pl_tcp_sess_init(struct session2 *session,
                            void *data, void *param)
{
	struct sockaddr *peer = session2_get_peer(session);
	session->comm_storage = (struct comm_info) {
		.comm_addr = peer,
		.src_addr = peer
	};
	return 0;
}

static enum protolayer_event_cb_result pl_tcp_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	switch (event) {
	case PROTOLAYER_EVENT_STATS_SEND_ERR:
		the_worker->stats.err_tcp += 1;
		return PROTOLAYER_EVENT_CONSUME;
	case PROTOLAYER_EVENT_STATS_QRY_OUT:
		the_worker->stats.tcp += 1;
		return PROTOLAYER_EVENT_CONSUME;
	case PROTOLAYER_EVENT_OS_BUFFER_FULL:
		session2_force_close(session);
		return PROTOLAYER_EVENT_CONSUME;
	default:
		return PROTOLAYER_EVENT_PROPAGATE;
	}

}

__attribute__((constructor))
static void io_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_UDP] = (struct protolayer_globals){
		.event_wrap = pl_udp_event_wrap,
	};

	protolayer_globals[PROTOLAYER_TYPE_TCP] = (struct protolayer_globals){
		.sess_init = pl_tcp_sess_init,
		.event_wrap = pl_tcp_event_wrap,
	};
}


int io_bind(const struct sockaddr *addr, int type, const endpoint_flags_t *flags)
{
	const int fd = socket(addr->sa_family, type, 0);
	if (fd < 0) return kr_error(errno);

	int yes = 1;
	if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) {
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) {
			close(fd);
			return kr_error(errno);
		}

#ifdef SO_REUSEPORT_LB
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT_LB, &yes, sizeof(yes))) {
			close(fd);
			return kr_error(errno);
		}
#elif defined(SO_REUSEPORT) && defined(__linux__) /* different meaning on (Free)BSD */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes))) {
			close(fd);
			return kr_error(errno);
		}
#endif

#ifdef IPV6_V6ONLY
		if (addr->sa_family == AF_INET6
		    && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes))) {
			close(fd);
			return kr_error(errno);
		}
#endif
		if (flags != NULL && flags->freebind) {
			int optlevel;
			int optname;
			int ret = family_to_freebind_option(addr->sa_family, &optlevel, &optname);
			if (ret) {
				close(fd);
				return kr_error(ret);
			}
			if (setsockopt(fd, optlevel, optname, &yes, sizeof(yes))) {
				close(fd);
				return kr_error(errno);
			}
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
			kr_log_error(IO,
				"failed to disable Path MTU discovery for %s UDP: %s\n",
				kr_straddr(addr), strerror(errno));
		}
#endif
	}

	if (bind(fd, addr, kr_sockaddr_len(addr))) {
		close(fd);
		return kr_error(errno);
	}

	return fd;
}

/// Optionally set a socket option and log error on failure.
static void set_so(int fd, int so_option, int value, const char *descr)
{
	if (!value) return;
	if (setsockopt(fd, SOL_SOCKET, so_option, &value, sizeof(value))) {
		kr_log_error(IO, "failed to set %s to %d: %s\n",
				descr, value, strerror(errno));
		// we treat this as non-critical failure
	}
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

	set_so(fd, SO_SNDBUF, the_network->listen_udp_buflens.snd, "UDP send buffer size");
	set_so(fd, SO_RCVBUF, the_network->listen_udp_buflens.rcv, "UDP receive buffer size");

	uv_handle_t *h = (uv_handle_t *)handle;
	check_bufsize(h);
	/* Handle is already created, just create context. */
	struct session2 *s = session2_new_io(h, KR_PROTO_UDP53, NULL, 0, false);
	kr_require(s);

	int socklen = sizeof(union kr_sockaddr);
	ret = uv_udp_getsockname(handle, &s->transport.io.sockname.ip, &socklen);
	if (ret) {
		kr_log_error(IO, "ERROR: getsockname failed: %s\n", uv_strerror(ret));
		abort(); /* It might be nontrivial not to leak something here. */
	}

	return io_start_read(h);
}


static void tcp_recv(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
	struct session2 *s = handle->data;
	if (kr_fails_assert(s && session2_get_handle(s) == (uv_handle_t *)handle && handle->type == UV_TCP))
		return;

	if (s->closing) {
		return;
	}

	/* nread might be 0, which does not indicate an error or EOF.
	 * This is equivalent to EAGAIN or EWOULDBLOCK under read(2). */
	if (nread == 0) {
		return;
	}

	if (nread == UV_ENOBUFS) {
		/* No space available in session buffer.
		 * The connection may be just waiting in defer.
		 * Ignore the error and keep the data in system queue for later reading or timeout. */
		if (kr_log_is_debug(IO, NULL)) {
			struct sockaddr *peer = session2_get_peer(s);
			char *peer_str = kr_straddr(peer);
			kr_log_debug(IO, "=> incoming data from '%s' waiting (%s)\n",
			         peer_str ? peer_str : "",
			         uv_strerror(nread));
		}
		return;
	}

	// allow deferring EOF for incoming connections to send answer even if half-closed
	if (!s->outgoing && (nread == UV_EOF)) {
		if (kr_log_is_debug(IO, NULL)) {
			struct sockaddr *peer = session2_get_peer(s);
			char *peer_str = kr_straddr(peer);
			kr_log_debug(IO, "=> connection to '%s' half-closed by peer (EOF)\n",
				       peer_str ? peer_str : "");
		}
		session2_event(s, PROTOLAYER_EVENT_EOF, NULL);
		return;
	}

	if (nread < 0 || !buf->base) {
		if (kr_log_is_debug(IO, NULL)) {
			struct sockaddr *peer = session2_get_peer(s);
			char *peer_str = kr_straddr(peer);
			kr_log_debug(IO, "=> connection to '%s' closed by peer (%s)\n",
				       peer_str ? peer_str : "",
				       uv_strerror(nread));
		}
		session2_penalize(s);
		session2_force_close(s);
		return;
	}

	if (kr_fails_assert(buf->base == wire_buf_free_space(&s->wire_buf))) {
		return;
	}

	int ret = wire_buf_consume(&s->wire_buf, nread);
	if (ret) {
		wire_buf_reset(&s->wire_buf);
		return;
	}

	session2_unwrap(s, protolayer_payload_wire_buf(&s->wire_buf, false),
			NULL, NULL, NULL);
}

static void tcp_accept_internal(uv_stream_t *master, int status, enum kr_proto grp)
{
	if (status != 0) {
		return;
	}

	struct session2 *s;
	int res = io_create(master->loop, &s, SOCK_STREAM, AF_UNSPEC, grp,
			NULL, 0, false);
	if (res) {
		if (res == UV_EMFILE) {
			the_worker->too_many_open = true;
			the_worker->rconcurrent_highwatermark = the_worker->stats.rconcurrent;
		}
		/* Since res isn't OK struct session wasn't allocated \ borrowed.
		 * We must release client handle only.
		 */
		return;
	}

	kr_require(s->outgoing == false);

	uv_tcp_t *client = (uv_tcp_t *)session2_get_handle(s);
	if (uv_accept(master, (uv_stream_t *)client) != 0) {
		/* close session, close underlying uv handles and
		 * deallocate (or return to memory pool) memory. */
		session2_close(s);
		return;
	}

	/* Get peer's and our address.  We apparently get specific sockname here
	 * even if we listened on a wildcard address. */
	struct sockaddr *sa = session2_get_peer(s);
	int sa_len = sizeof(struct sockaddr_in6);
	int ret = uv_tcp_getpeername(client, sa, &sa_len);
	if (ret || sa->sa_family == AF_UNSPEC) {
		session2_close(s);
		return;
	}
	sa = session2_get_sockname(s);
	sa_len = sizeof(struct sockaddr_in6);
	ret = uv_tcp_getsockname(client, sa, &sa_len);
	if (ret || sa->sa_family == AF_UNSPEC) {
		session2_close(s);
		return;
	}

	/* Set deadlines for TCP connection and start reading.
	 * It will re-check every half of a request time limit if the connection
	 * is idle and should be terminated, this is an educated guess. */

	uint64_t idle_in_timeout = the_network->tcp.in_idle_timeout;
	uint64_t timeout = KR_CONN_RTT_MAX / 2;
	session2_event(s, PROTOLAYER_EVENT_CONNECT, NULL);
	session2_timer_start(s, PROTOLAYER_EVENT_GENERAL_TIMEOUT,
			timeout, idle_in_timeout);
	io_start_read((uv_handle_t *)client);
}

static void tcp_accept(uv_stream_t *master, int status)
{
	tcp_accept_internal(master, status, KR_PROTO_TCP53);
}

static void tls_accept(uv_stream_t *master, int status)
{
	tcp_accept_internal(master, status, KR_PROTO_DOT);
}

#if ENABLE_DOH2
static void https_accept(uv_stream_t *master, int status)
{
	tcp_accept_internal(master, status, KR_PROTO_DOH);
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
		kr_log_error(IO, "kresd was compiled without libnghttp2 support\n");
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
		kr_log_error(IO, "listen TCP (defer_accept): %s\n", strerror(errno));
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
		kr_log_error(IO, "listen TCP (fastopen): %s%s\n", strerror(errno),
			(errno != EPERM ? "" :
			 ".  This may be caused by TCP Fast Open being disabled in the OS."));
	}
#endif

	/* These get inherited into the individual connections (on Linux at least). */
	set_so(fd, SO_SNDBUF, the_network->listen_tcp_buflens.snd, "TCP send buffer size");
	set_so(fd, SO_RCVBUF, the_network->listen_tcp_buflens.rcv, "TCP receive buffer size");
#ifdef TCP_USER_TIMEOUT
	val = the_network->tcp.user_timeout;
	if (val && setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &val, sizeof(val))) {
		kr_log_error(IO, "listen TCP (user_timeout): %s\n", strerror(errno));
	}
	// TODO: also for upstream connections, at least this one option?
#endif

	handle->data = NULL;
	return 0;
}


enum io_stream_mode {
	IO_MODE_TEXT   = 0,
	IO_MODE_BINARY = 1,
	IO_MODE_JSON   = 2,
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
 * - This is just basic read-eval-print; use rather kresctl with shell completion
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

	/* Avoid Null pointer */
	if (!out) {
		return;
	}

	/** The current single command and the remaining command(s). */
	char *cmd, *cmd_next = NULL;
	bool incomplete_cmd = false;

	if (!commands || nread <= 0) {
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
	lua_State *L = the_engine->L;
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
			data->mode = IO_MODE_BINARY;
			goto next_iter;
		}
		if (strcmp(cmd, "__json") == 0) {
			data->mode = IO_MODE_JSON;
			goto next_iter;
		}

		const bool cmd_failed = engine_cmd(L, cmd,
				(data->mode == IO_MODE_JSON)
					? ENGINE_EVAL_MODE_JSON
					: ENGINE_EVAL_MODE_LUA_TABLE);
		const char *message = NULL;
		size_t len_s;
		if (lua_gettop(L) > 0) {
			message = lua_tolstring(L, -1, &len_s);
		}

		switch (data->mode) {
		case IO_MODE_BINARY:
		case IO_MODE_JSON:
			/* Length-field-prepended mode */
			if (!message || len_s > UINT32_MAX) {
				kr_log_error(IO, "unrepresentable response on control socket, "
						"sending back empty block (command '%s')\n", cmd);
				len_s = 0;
			}
			uint32_t len_n = htonl(len_s);
			if (fwrite(&len_n, sizeof(len_n), 1, out) != 1)
				goto finish;
			if (len_s > 0) {
				if (fwrite(message, len_s, 1, out) != 1)
					goto finish;
			}
			break;
		case IO_MODE_TEXT:
			/* Human-readable and console-printable mode */
			if (message) {
				if (fprintf(out, "%s", message) < 0)
					goto finish;
			}
			if (message || !args->quiet) {
				if (fprintf(out, "\n") < 0)
					goto finish;
			}
			if (!args->quiet) {
				if (fprintf(out, "> ") < 0)
					goto finish;
			}
			break;
		}

		/* Duplicate command and output to logs */
		if (cmd_failed) {
			kr_log_warning(CONTROL, "> %s\n", cmd);
			if (message)
				kr_log_warning(CONTROL, "%s\n", message);
		} else {
			kr_log_debug(CONTROL, "> %s\n", cmd);
			if (message)
				kr_log_debug(CONTROL, "%s\n", message);
		}
	next_iter:
		lua_settop(L, 0); /* not required in some cases but harmless */
		cmd = cmd_next;
		cmd_next = strtok(NULL, "\n");
	}

finish:
	/* Close if redirected */
	if (stream_fd != STDIN_FILENO) {
		(void)fclose(out);
	}
	/* If a LMDB transaction got open, we can't leave it hanging.
	 * We accept the changes, if any. */
	kr_cache_commit(&the_resolver->cache);
	kr_rules_commit(true);
}

void io_tty_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf)
{
	buf->len = suggested;
	buf->base = malloc(suggested);
}

struct io_stream_data *io_tty_alloc_data(void) {
	knot_mm_t *pool = mm_ctx_mempool2(MM_DEFAULT_BLKSIZE);
	if (!pool) {
		return NULL;
	}
	struct io_stream_data *data = mm_alloc(pool, sizeof(struct io_stream_data));

	data->buf = mp_start(pool->ctx, 512);
	data->mode = IO_MODE_TEXT;
	data->blen = 0;
	data->pool = pool;

	return data;
}

void io_tty_accept(uv_stream_t *master, int status)
{
	/* We can't use any allocations after mp_start() and it's easier anyway. */
	uv_pipe_t *client = malloc(sizeof(*client));
	if (!client)
		return;

	struct io_stream_data *data = io_tty_alloc_data();
	if (!data) {
		free(client);
		return;
	}
	client->data = data;

	struct args *args = the_args;
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
		kr_log_error(XDP, "poll status %d: %s\n", status, uv_strerror(status));
		return;
	}
	if (events != UV_READABLE) {
		kr_log_error(XDP, "poll unexpected events: %d\n", events);
		return;
	}

	xdp_handle_data_t *xhd = handle->data;
	kr_require(xhd && xhd->session && xhd->socket);
	uint32_t rcvd;
	knot_xdp_msg_t msgs[XDP_RX_BATCH_SIZE];
	int ret = knot_xdp_recv(xhd->socket, msgs, XDP_RX_BATCH_SIZE, &rcvd, NULL);

	if (kr_fails_assert(ret == KNOT_EOK)) {
		/* ATM other error codes can only be returned when called incorrectly */
		kr_log_error(XDP, "knot_xdp_recv(): %d, %s\n", ret, knot_strerror(ret));
		return;
	}
	kr_log_debug(XDP, "poll triggered, processing a batch of %d packets\n", (int)rcvd);
	kr_require(rcvd <= XDP_RX_BATCH_SIZE);
	for (int i = 0; i < rcvd; ++i) {
		knot_xdp_msg_t *msg = &msgs[i];
		kr_require(msg->payload.iov_len <= KNOT_WIRE_MAX_PKTSIZE);
		struct comm_info comm = {
			.src_addr = (const struct sockaddr *)&msg->ip_from,
			.comm_addr = (const struct sockaddr *)&msg->ip_from,
			.dst_addr = (const struct sockaddr *)&msg->ip_to,
			.xdp = true
		};
		memcpy(comm.eth_from, msg->eth_from, sizeof(comm.eth_from));
		memcpy(comm.eth_to, msg->eth_to, sizeof(comm.eth_to));
		session2_unwrap(xhd->session,
				protolayer_payload_buffer(
					msg->payload.iov_base,
					msg->payload.iov_len, false),
				&comm, NULL, NULL);
		if (ret)
			kr_log_debug(XDP, "worker_submit() == %d: %s\n", ret, kr_strerror(ret));
		mp_flush(the_worker->pkt_pool.ctx);
	}
	knot_xdp_recv_finish(xhd->socket, msgs, rcvd);
}
/// Warn if the XDP program is running in emulated mode (XDP_SKB)
static void xdp_warn_mode(const char *ifname)
{
	if (kr_fails_assert(ifname))
		return;

	const unsigned if_index = if_nametoindex(ifname);
	if (!if_index) {
		kr_log_warning(XDP, "warning: interface %s, unexpected error when converting its name: %s\n",
				ifname, strerror(errno));
		return;
	}

	const knot_xdp_mode_t mode = knot_eth_xdp_mode(if_index);
	switch (mode) {
	case KNOT_XDP_MODE_FULL:
		return;
	case KNOT_XDP_MODE_EMUL:
		kr_log_warning(XDP, "warning: interface %s running only with XDP emulation\n",
				ifname);
		return;
	case KNOT_XDP_MODE_NONE: // enum warnings from compiler
		break;
	}
	kr_log_warning(XDP, "warning: interface %s running in unexpected XDP mode %d\n",
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

	xhd->socket = NULL; // needed for some reason
	queue_init(xhd->tx_waker_queue);

	// This call is a libknot version hell, unfortunately.
	int ret = knot_xdp_init(&xhd->socket, ifname, ep->nic_queue,
			KNOT_XDP_FILTER_UDP | (ep->port ? 0 : KNOT_XDP_FILTER_PASS),
			ep->port, 0/*quic_port*/,
			KNOT_XDP_LOAD_BPF_MAYBE,
			NULL/*xdp_config*/);

	if (!ret) xdp_warn_mode(ifname);

	if (!ret) ret = uv_idle_init(loop, &xhd->tx_waker);
	if (ret || kr_fails_assert(xhd->socket)) {
		free(xhd);
		return ret == 0 ? kr_error(EINVAL) : kr_error(ret);
	}
	xhd->tx_waker.data = xhd;

	ep->fd = knot_xdp_socket_fd(xhd->socket); // probably not useful
	ret = uv_poll_init(loop, (uv_poll_t *)ep->handle, ep->fd);
	if (ret) {
		knot_xdp_deinit(xhd->socket);
		free(xhd);
		return kr_error(ret);
	}

	xhd->session = session2_new_io(ep->handle, KR_PROTO_UDP53,
			NULL, 0, false);
	kr_require(xhd->session);
	session2_get_sockname(xhd->session)->sa_family = AF_XDP; // to have something in there

	ep->handle->data = xhd;
	ret = uv_poll_start((uv_poll_t *)ep->handle, UV_READABLE, xdp_rx);
	return ret;
}
#endif

int io_create(uv_loop_t *loop, struct session2 **out_session, int type,
              unsigned family, enum kr_proto grp,
              struct protolayer_data_param *layer_param,
              size_t layer_param_count, bool outgoing)
{
	*out_session = NULL;
	int ret = -1;
	uv_handle_t *handle;
	if (type == SOCK_DGRAM) {
		uv_udp_t *udp = malloc(sizeof(uv_udp_t));
		kr_require(udp);
		ret = uv_udp_init(loop, udp);

		handle = (uv_handle_t *)udp;
	} else if (type == SOCK_STREAM) {
		uv_tcp_t *tcp = malloc(sizeof(uv_tcp_t));
		kr_require(tcp);
		ret = uv_tcp_init_ex(loop, tcp, family);
		uv_tcp_nodelay(tcp, 1);

		handle = (uv_handle_t *)tcp;
	} else {
		kr_require(false && "io_create: invalid socket type");
	}
	if (ret != 0) {
		return ret;
	}
	struct session2 *s = session2_new_io(handle, grp, layer_param,
			layer_param_count, outgoing);
	if (s == NULL) {
		ret = -1;
	}

	*out_session = s;
	return ret;
}

static void io_deinit(uv_handle_t *handle)
{
	if (!handle || !handle->data) {
		return;
	}
	if (handle->type != UV_POLL) {
		session2_dec_refs(handle->data);
	} else {
	#if ENABLE_XDP
		xdp_handle_data_t *xhd = handle->data;
		uv_idle_stop(&xhd->tx_waker);
		uv_close((uv_handle_t *)&xhd->tx_waker, NULL);
		session2_dec_refs(xhd->session);
		knot_xdp_deinit(xhd->socket);
		queue_deinit(xhd->tx_waker_queue);
		free(xhd);
	#else
		kr_assert(false);
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
		kr_assert(false);
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
