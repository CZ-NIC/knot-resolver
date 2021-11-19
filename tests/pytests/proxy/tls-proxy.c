/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <gnutls/gnutls.h>
#include <uv.h>
#include "lib/generic/array.h"
#include "tls-proxy.h"

#define TLS_MAX_SEND_RETRIES 100
#define CLIENT_ANSWER_CHUNK_SIZE 8

#define MAX_CLIENT_PENDING_SIZE 4096

struct buf {
	size_t size;
	char buf[];
};

enum peer_state {
	STATE_NOT_CONNECTED,
	STATE_LISTENING,
	STATE_CONNECTED,
	STATE_CONNECT_IN_PROGRESS,
	STATE_CLOSING_IN_PROGRESS
};

enum handshake_state {
	TLS_HS_NOT_STARTED = 0,
	TLS_HS_EXPECTED,
	TLS_HS_REAUTH_EXPECTED,
	TLS_HS_IN_PROGRESS,
	TLS_HS_DONE,
	TLS_HS_CLOSING,
	TLS_HS_LAST
};

struct tls_ctx {
	gnutls_session_t session;
	enum handshake_state handshake_state;
	/* for reading from the network */
	const uint8_t *buf;
	ssize_t nread;
	ssize_t consumed;
	uint8_t recv_buf[4096];
};

struct peer {
	uv_tcp_t handle;
	enum peer_state state;
	struct sockaddr_storage addr;
	array_t(struct buf *) pending_buf;
	uint64_t connection_timestamp;
	struct tls_ctx *tls;
	struct peer *peer;
	int active_requests;
};

struct tls_proxy_ctx {
	const struct args *a;
	uv_loop_t *loop;
	gnutls_certificate_credentials_t tls_credentials;
        gnutls_priority_t tls_priority_cache;
	struct {
		uv_tcp_t handle;
		struct sockaddr_storage addr;
	} server;
	struct sockaddr_storage upstream_addr;
	array_t(struct peer *) client_list;
	char uv_wire_buf[65535 * 2];
	int conn_sequence;
};

static void read_from_upstream_cb(uv_stream_t *upstream, ssize_t nread, const uv_buf_t *buf);
static void read_from_client_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf);
static ssize_t proxy_gnutls_pull(gnutls_transport_ptr_t h, void *buf, size_t len);
static ssize_t proxy_gnutls_push(gnutls_transport_ptr_t h, const void *buf, size_t len);
static int tls_process_from_upstream(struct peer *upstream, const uint8_t *buf, ssize_t nread);
static int tls_process_from_client(struct peer *client, const uint8_t *buf, ssize_t nread);
static int write_to_upstream_pending(struct peer *peer);
static int write_to_client_pending(struct peer *peer);
static void on_client_close(uv_handle_t *handle);
static void on_upstream_close(uv_handle_t *handle);

static int gnutls_references = 0;

static const char * const tlsv12_priorities =
	"NORMAL:" /* GnuTLS defaults */
	"-VERS-TLS1.0:-VERS-TLS1.1:+VERS-TLS1.2:-VERS-TLS1.3:" /* TLS 1.2 only */
	"-VERS-SSL3.0:-ARCFOUR-128:-COMP-ALL:+COMP-NULL";

static const char * const tlsv13_priorities =
	"NORMAL:" /* GnuTLS defaults */
	"-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2:+VERS-TLS1.3:" /* TLS 1.3 only */
	"-VERS-SSL3.0:-ARCFOUR-128:-COMP-ALL:+COMP-NULL";

static struct tls_proxy_ctx *get_proxy(struct peer *peer)
{
	return (struct tls_proxy_ctx *)peer->handle.loop->data;
}

const void *ip_addr(const struct sockaddr *addr)
{
	if (!addr) {
		return NULL;
	}
	switch (addr->sa_family) {
	case AF_INET:  return (const void *)&(((const struct sockaddr_in *)addr)->sin_addr);
	case AF_INET6: return (const void *)&(((const struct sockaddr_in6 *)addr)->sin6_addr);
	default:       return NULL;
	}
}

uint16_t ip_addr_port(const struct sockaddr *addr)
{
	if (!addr) {
		return 0;
	}
	switch (addr->sa_family) {
	case AF_INET:  return ntohs(((const struct sockaddr_in *)addr)->sin_port);
	case AF_INET6: return ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
	default:       return 0;
	}
}

static int ip_addr_str(const struct sockaddr *addr, char *buf, size_t *buflen)
{
	int ret = 0;
	if (!addr || !buf || !buflen) {
		return EINVAL;
	}

	char str[INET6_ADDRSTRLEN + 6];
	if (!inet_ntop(addr->sa_family, ip_addr(addr), str, sizeof(str))) {
		return errno;
	}
	int len = strlen(str);
	str[len] = '#';
	snprintf(&str[len + 1], 6, "%hu", ip_addr_port(addr));
	len += 6;
	str[len] = 0;
	if (len >= *buflen) {
		ret = ENOSPC;
	} else {
		memcpy(buf, str, len + 1);
	}
	*buflen = len;
	return ret;
}

static inline char *ip_straddr(const struct sockaddr_storage *saddr_storage)
{
	assert(saddr_storage != NULL);
	const struct sockaddr *addr = (const struct sockaddr *)saddr_storage;
	/* We are the single-threaded application */
	static char str[INET6_ADDRSTRLEN + 6];
	size_t len = sizeof(str);
	int ret = ip_addr_str(addr, str, &len);
	return ret != 0 || len == 0 ? NULL : str;
}

static struct buf *alloc_io_buffer(size_t size)
{
	struct buf *buf = calloc(1, sizeof (struct buf) + size);
	buf->size = size;
	return buf;
}

static void free_io_buffer(struct buf *buf)
{
	if (!buf) {
		return;
	}
	free(buf);
}

static struct buf *get_first_pending_buf(struct peer *peer)
{
	struct buf *buf = NULL;
	if (peer->pending_buf.len > 0) {
		buf = peer->pending_buf.at[0];
	}
	return buf;
}

static struct buf *remove_first_pending_buf(struct peer *peer)
{
	if (peer->pending_buf.len == 0) {
		return NULL;
	}
	struct buf * buf = peer->pending_buf.at[0];
	for (int i = 1; i < peer->pending_buf.len; ++i) {
		peer->pending_buf.at[i - 1] = peer->pending_buf.at[i];
	}
	peer->pending_buf.len -= 1;
	return buf;
}

static void clear_pending_bufs(struct peer *peer)
{
	for (int i = 0; i < peer->pending_buf.len; ++i) {
		struct buf *b = peer->pending_buf.at[i];
		free_io_buffer(b);
	}
	peer->pending_buf.len = 0;
}

static void alloc_uv_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)handle->loop->data;
	buf->base = proxy->uv_wire_buf;
	buf->len = sizeof(proxy->uv_wire_buf);
}

static void on_client_close(uv_handle_t *handle)
{
	struct peer *client = (struct peer *)handle->data;
	struct peer *upstream = client->peer;
	fprintf(stdout, "[client] connection with '%s' closed\n", ip_straddr(&client->addr));
	assert(client->tls);
	gnutls_deinit(client->tls->session);
	client->tls->handshake_state = TLS_HS_NOT_STARTED;
	client->state = STATE_NOT_CONNECTED;
	if (upstream->state != STATE_NOT_CONNECTED) {
		if (upstream->state == STATE_CONNECTED) {
			fprintf(stdout, "[client] closing connection with upstream for '%s'\n",
				ip_straddr(&client->addr));
			upstream->state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)&upstream->handle, on_upstream_close);
		}
		return;
	}
	struct tls_proxy_ctx *proxy = get_proxy(client);
	for (size_t i = 0; i < proxy->client_list.len; ++i) {
		struct peer *client_i = proxy->client_list.at[i];
		if (client_i == client) {
			fprintf(stdout, "[client] connection structures deallocated for '%s'\n",
				ip_straddr(&client->addr));
			array_del(proxy->client_list, i);
			free(client->tls);
			free(client);
			break;
		}
	}
}

static void on_upstream_close(uv_handle_t *handle)
{
	struct peer *upstream = (struct peer *)handle->data;
	struct peer *client = upstream->peer;
	assert(upstream->tls == NULL);
	upstream->state = STATE_NOT_CONNECTED;
	fprintf(stdout, "[upstream] connection with upstream closed for client '%s'\n", ip_straddr(&client->addr));
	if (client->state != STATE_NOT_CONNECTED) {
		if (client->state == STATE_CONNECTED) {
			fprintf(stdout, "[upstream] closing connection to client '%s'\n",
				ip_straddr(&client->addr));
			client->state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)&client->handle, on_client_close);
		}
		return;
	}
	struct tls_proxy_ctx *proxy = get_proxy(upstream);
	for (size_t i = 0; i < proxy->client_list.len; ++i) {
		struct peer *client_i = proxy->client_list.at[i];
		if (client_i == client) {
			fprintf(stdout, "[upstream] connection structures deallocated for '%s'\n",
				ip_straddr(&client->addr));
			array_del(proxy->client_list, i);
			free(upstream);
			free(client->tls);
			free(client);
			break;
		}
	}
}

static void write_to_client_cb(uv_write_t *req, int status)
{
	struct peer *client = (struct peer *)req->handle->data;
	free(req);
	client->active_requests -= 1;
	if (status) {
		fprintf(stdout, "[client] error writing to client '%s': %s\n",
			ip_straddr(&client->addr), uv_strerror(status));
		clear_pending_bufs(client);
		if (client->state == STATE_CONNECTED) {
			client->state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)&client->handle, on_client_close);
			return;
		}
	}
	fprintf(stdout, "[client] successfully wrote to client '%s', pending len is %zd, active requests %i\n",
		ip_straddr(&client->addr), client->pending_buf.len, client->active_requests);
	if (client->state == STATE_CONNECTED &&
	    client->tls->handshake_state == TLS_HS_DONE) {
		struct tls_proxy_ctx *proxy = get_proxy(client);
		uint64_t elapsed = uv_now(proxy->loop) - client->connection_timestamp;
		if (!proxy->a->close_connection || elapsed < proxy->a->close_timeout) {
			write_to_client_pending(client);
		} else {
			clear_pending_bufs(client);
			client->state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)&client->handle, on_client_close);
			fprintf(stdout, "[client] closing connection to client '%s'\n", ip_straddr(&client->addr));
		}
	}
}

static void write_to_upstream_cb(uv_write_t *req, int status)
{
	struct peer *upstream = (struct peer *)req->handle->data;
	void *data = req->data;
	free(req);
	if (status) {
		fprintf(stdout, "[upstream] error writing to upstream: %s\n", uv_strerror(status));
		clear_pending_bufs(upstream);
		upstream->state = STATE_CLOSING_IN_PROGRESS;
		uv_close((uv_handle_t*)&upstream->handle, on_upstream_close);
		return;
	}
	if (data != NULL) {
		assert(upstream->pending_buf.len > 0);
		struct buf *buf = get_first_pending_buf(upstream);
		assert(data == (void *)buf->buf);
		fprintf(stdout, "[upstream] successfully wrote %zi bytes to upstream, pending len is %zd\n",
			buf->size, upstream->pending_buf.len);
		remove_first_pending_buf(upstream);
		free_io_buffer(buf);
	} else {
		fprintf(stdout, "[upstream] successfully wrote to upstream, pending len is %zd\n",
			upstream->pending_buf.len);
	}
	if (upstream->peer == NULL || upstream->peer->state != STATE_CONNECTED) {
		clear_pending_bufs(upstream);
	} else if (upstream->state == STATE_CONNECTED && upstream->pending_buf.len > 0) {
		write_to_upstream_pending(upstream);
	}
}

static void accept_connection_from_client(uv_stream_t *server)
{
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)server->loop->data;
	struct peer *client = calloc(1, sizeof(struct peer));
	uv_tcp_init(proxy->loop, &client->handle);
	uv_tcp_nodelay((uv_tcp_t *)&client->handle, 1);

	int err = uv_accept(server, (uv_stream_t*)&client->handle);
	if (err != 0) {
		fprintf(stdout, "[client] incoming connection - uv_accept() failed: (%d) %s\n",
			err, uv_strerror(err));
		proxy->conn_sequence = 0;
		return;
	}

	client->state = STATE_CONNECTED;
	array_init(client->pending_buf);
	client->handle.data = client;

	struct peer *upstream = calloc(1, sizeof(struct peer));
	uv_tcp_init(proxy->loop, &upstream->handle);
	uv_tcp_nodelay((uv_tcp_t *)&upstream->handle, 1);

	client->peer = upstream;

	array_init(upstream->pending_buf);
	upstream->state = STATE_NOT_CONNECTED;
	upstream->peer = client;
	upstream->handle.data = upstream;

	struct sockaddr *addr = (struct sockaddr *)&(client->addr);
	int addr_len = sizeof(client->addr);
	int ret = uv_tcp_getpeername(&client->handle, addr, &addr_len);
	if (ret || addr->sa_family == AF_UNSPEC) {
		client->state = STATE_CLOSING_IN_PROGRESS;
		uv_close((uv_handle_t*)&client->handle, on_client_close);
		fprintf(stdout, "[client] incoming connection - uv_tcp_getpeername() failed: (%d) %s\n",
			     err, uv_strerror(err));
		proxy->conn_sequence = 0;
		return;
	}
	memcpy(&upstream->addr, &proxy->upstream_addr, sizeof(struct sockaddr_storage));

	struct tls_ctx *tls = calloc(1, sizeof(struct tls_ctx));
	tls->handshake_state = TLS_HS_NOT_STARTED;

	client->tls = tls;
	const char *errpos = NULL;
	unsigned int gnutls_flags = GNUTLS_SERVER | GNUTLS_NONBLOCK;
#if GNUTLS_VERSION_NUMBER >= 0x030604
	if (proxy->a->tls_13) {
		gnutls_flags |= GNUTLS_POST_HANDSHAKE_AUTH;
	}
#endif
	err = gnutls_init(&tls->session, gnutls_flags);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf(stdout, "[client] gnutls_init() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
	}
        err = gnutls_priority_set(tls->session, proxy->tls_priority_cache);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf(stdout, "[client] gnutls_priority_set() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
	}

	const char *direct_priorities = proxy->a->tls_13 ? tlsv13_priorities : tlsv12_priorities;
	err = gnutls_priority_set_direct(tls->session, direct_priorities, &errpos);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf(stdout, "[client] setting priority '%s' failed at character %zd (...'%s') with %s (%d)\n",
			direct_priorities, errpos - direct_priorities, errpos,
			gnutls_strerror_name(err), err);
	}
	err = gnutls_credentials_set(tls->session, GNUTLS_CRD_CERTIFICATE, proxy->tls_credentials);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf(stdout, "[client] gnutls_credentials_set() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
	}
	if (proxy->a->tls_13) {
		gnutls_certificate_server_set_request(tls->session, GNUTLS_CERT_REQUEST);
	} else  {
		gnutls_certificate_server_set_request(tls->session, GNUTLS_CERT_IGNORE);
	}
	gnutls_handshake_set_timeout(tls->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	gnutls_transport_set_pull_function(tls->session, proxy_gnutls_pull);
	gnutls_transport_set_push_function(tls->session, proxy_gnutls_push);
	gnutls_transport_set_ptr(tls->session, client);

	tls->handshake_state = TLS_HS_IN_PROGRESS;

	client->connection_timestamp = uv_now(proxy->loop);
	proxy->conn_sequence += 1;
	array_push(proxy->client_list, client);

	fprintf(stdout, "[client] incoming connection from '%s'\n", ip_straddr(&client->addr));
	uv_read_start((uv_stream_t*)&client->handle, alloc_uv_buffer, read_from_client_cb);
}

static void dynamic_handle_close_cb(uv_handle_t *handle)
{
	free(handle);
}

static void delayed_accept_timer_cb(uv_timer_t *timer)
{
	uv_stream_t *server = (uv_stream_t *)timer->data;
	fprintf(stdout, "[client] delayed connection processing\n");
	accept_connection_from_client(server);
	uv_close((uv_handle_t *)timer, dynamic_handle_close_cb);
}

static void on_client_connection(uv_stream_t *server, int status)
{
	if (status < 0) {
		fprintf(stdout, "[client] incoming connection error: %s\n", uv_strerror(status));
		return;
	}
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)server->loop->data;
	proxy->conn_sequence += 1;
	if (proxy->a->max_conn_sequence > 0 &&
	    proxy->conn_sequence > proxy->a->max_conn_sequence) {
		fprintf(stdout, "[client] incoming connection, delaying\n");
		uv_timer_t *timer = (uv_timer_t*)malloc(sizeof *timer);
		uv_timer_init(uv_default_loop(), timer);
		timer->data = server;
		uv_timer_start(timer, delayed_accept_timer_cb, 10000, 0);
		proxy->conn_sequence = 0;
	} else {
		accept_connection_from_client(server);
	}
}

static void on_connect_to_upstream(uv_connect_t *req, int status)
{
	struct peer *upstream = (struct peer *)req->handle->data;
	free(req);
	if (status < 0) {
		fprintf(stdout, "[upstream] error connecting to upstream (%s): %s\n",
			ip_straddr(&upstream->addr),
			uv_strerror(status));
		clear_pending_bufs(upstream);
		upstream->state = STATE_CLOSING_IN_PROGRESS;
		uv_close((uv_handle_t*)&upstream->handle, on_upstream_close);
		return;
	}
	fprintf(stdout, "[upstream] connected to %s\n", ip_straddr(&upstream->addr));

	upstream->state = STATE_CONNECTED;
	uv_read_start((uv_stream_t*)&upstream->handle, alloc_uv_buffer, read_from_upstream_cb);
	if (upstream->pending_buf.len > 0) {
		write_to_upstream_pending(upstream);
	}
}

static void read_from_client_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
	if (nread == 0) {
		fprintf(stdout, "[client] reading %zd bytes\n", nread);
		return;
	}
	struct peer *client = (struct peer *)handle->data;
	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stdout, "[client] error reading from '%s': %s\n",
				ip_straddr(&client->addr),
				uv_err_name(nread));
		} else {
			fprintf(stdout, "[client] closing connection with '%s'\n",
				ip_straddr(&client->addr));
		}
		if (client->state == STATE_CONNECTED) {
			client->state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)handle, on_client_close);
		}
		return;
	}

	struct tls_proxy_ctx *proxy = get_proxy(client);
	if (proxy->a->accept_only) {
		fprintf(stdout, "[client] ignoring %zd bytes from '%s'\n", nread, ip_straddr(&client->addr));
		return;
	}
	fprintf(stdout, "[client] reading %zd bytes from '%s'\n", nread, ip_straddr(&client->addr));

	int res = tls_process_from_client(client, (const uint8_t *)buf->base, nread);
	if (res < 0) {
		if (client->state == STATE_CONNECTED) {
			client->state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)&client->handle, on_client_close);
		}
	}
}

static void read_from_upstream_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
	fprintf(stdout, "[upstream] reading %zd bytes\n", nread);
	if (nread == 0) {
		return;
	}
	struct peer *upstream = (struct peer *)handle->data;
	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stdout, "[upstream] error reading from upstream: %s\n", uv_err_name(nread));
		} else {
			fprintf(stdout, "[upstream] closing connection\n");
		}
		clear_pending_bufs(upstream);
		if (upstream->state == STATE_CONNECTED) {
			upstream->state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)&upstream->handle, on_upstream_close);
		}
		return;
	}
	int res = tls_process_from_upstream(upstream, (const uint8_t *)buf->base, nread);
	if (res < 0) {
		fprintf(stdout, "[upstream] error processing tls data to client\n");
		if (upstream->peer->state == STATE_CONNECTED) {
			upstream->peer->state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)&upstream->peer->handle, on_client_close);
		}
	}
}

static void push_to_upstream_pending(struct peer *upstream, const char *buf, size_t size)
{
	struct buf *b = alloc_io_buffer(size);
	memcpy(b->buf, buf, b->size);
	array_push(upstream->pending_buf, b);
}

static void push_to_client_pending(struct peer *client, const char *buf, size_t size)
{
	struct tls_proxy_ctx *proxy = get_proxy(client);
	while (size > 0) {
		int temp_size = size;
		if (proxy->a->rehandshake && temp_size > CLIENT_ANSWER_CHUNK_SIZE) {
			temp_size = CLIENT_ANSWER_CHUNK_SIZE;
		}
		struct buf *b = alloc_io_buffer(temp_size);
		memcpy(b->buf, buf, b->size);
		array_push(client->pending_buf, b);
		size -= temp_size;
		buf += temp_size;
	}
}

static int write_to_upstream_pending(struct peer *upstream)
{
	struct buf *buf = get_first_pending_buf(upstream);
	uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));
	uv_buf_t wrbuf = uv_buf_init(buf->buf, buf->size);
	req->data = buf->buf;
	fprintf(stdout, "[upstream] writing %zd bytes\n", buf->size);
	return uv_write(req, (uv_stream_t *)&upstream->handle, &wrbuf, 1, write_to_upstream_cb);
}

static ssize_t proxy_gnutls_pull(gnutls_transport_ptr_t h, void *buf, size_t len)
{
	struct peer *peer = (struct peer *)h;
	struct tls_ctx *t = peer->tls;

	fprintf(stdout, "[gnutls_pull] pulling %zd bytes\n", len);

	if (t->nread <= t->consumed) {
		errno = EAGAIN;
		fprintf(stdout, "[gnutls_pull] return EAGAIN\n");
		return -1;
	}

	ssize_t	avail = t->nread - t->consumed;
	ssize_t	transfer = (avail <= len ? avail : len);
	memcpy(buf, t->buf + t->consumed, transfer);
	t->consumed += transfer;
	return transfer;
}

ssize_t proxy_gnutls_push(gnutls_transport_ptr_t h, const void *buf, size_t len)
{
	struct peer *client = (struct peer *)h;
	fprintf(stdout, "[gnutls_push] writing %zd bytes\n", len);

	ssize_t ret = -1;
	const size_t req_size_aligned = ((sizeof(uv_write_t) / 16) + 1) * 16;
	char *common_buf = malloc(req_size_aligned + len);
	uv_write_t *req = (uv_write_t *) common_buf;
	char *data = common_buf + req_size_aligned;
	const uv_buf_t uv_buf[1] = {
		{ data, len }
	};
	memcpy(data, buf, len);
	int res = uv_write(req, (uv_stream_t *)&client->handle, uv_buf, 1, write_to_client_cb);
	if (res == 0) {
		ret = len;
		client->active_requests += 1;
	} else {
		free(common_buf);
		errno = EIO;
	}
	return ret;
}

static int write_to_client_pending(struct peer *client)
{
	if (client->pending_buf.len == 0) {
		return 0;
	}

	struct tls_proxy_ctx *proxy = get_proxy(client);
	struct buf *buf = get_first_pending_buf(client);
	fprintf(stdout, "[client] writing %zd bytes\n", buf->size);

	gnutls_session_t tls_session = client->tls->session;
	assert(client->tls->handshake_state != TLS_HS_IN_PROGRESS);

	char *data = buf->buf;
	size_t len = buf->size;

	ssize_t count = 0;
	ssize_t submitted = len;
	ssize_t retries = 0;
	do {
		count = gnutls_record_send(tls_session, data, len);
		if (count < 0) {
			if (gnutls_error_is_fatal(count)) {
				fprintf(stdout, "[client] gnutls_record_send failed: %s (%zd)\n",
					gnutls_strerror_name(count), count);
				return -1;
			}
			if (++retries > TLS_MAX_SEND_RETRIES) {
				fprintf(stdout, "[client] gnutls_record_send: too many sequential non-fatal errors (%zd), last error is: %s (%zd)\n",
					retries, gnutls_strerror_name(count), count);
				return -1;
			}
		} else if (count != 0) {
			data += count;
			len -= count;
			retries = 0;
		} else {
			if (++retries < TLS_MAX_SEND_RETRIES) {
				continue;
			}
			fprintf(stdout, "[client] gnutls_record_send: too many retries (%zd)\n",
				retries);
			fprintf(stdout, "[client] tls_push_to_client didn't send all data(%zd of %zd)\n",
				len, submitted);
			return -1;
		}
	} while (len > 0);

	remove_first_pending_buf(client);
	free_io_buffer(buf);

	fprintf(stdout, "[client] submitted %zd bytes\n", submitted);
	if (proxy->a->rehandshake) {
		int err = GNUTLS_E_SUCCESS;
#if GNUTLS_VERSION_NUMBER >= 0x030604
		if (proxy->a->tls_13) {
			int flags = gnutls_session_get_flags(tls_session);
			if ((flags & GNUTLS_SFLAGS_POST_HANDSHAKE_AUTH) == 0) {
				/* Client doesn't support post-handshake re-authentication,
				 * nothing to test here */
				fprintf(stdout, "[client] GNUTLS_SFLAGS_POST_HANDSHAKE_AUTH flag not detected\n");
				assert(false);
			}
			err = gnutls_reauth(tls_session, 0);
			if (err != GNUTLS_E_INTERRUPTED &&
			    err != GNUTLS_E_AGAIN &&
			    err != GNUTLS_E_GOT_APPLICATION_DATA) {
				fprintf(stdout, "[client] gnutls_reauth() failed: %s (%i)\n",
					gnutls_strerror_name(err), err);
			} else {
				fprintf(stdout, "[client] post-handshake authentication initiated\n");
			}
			client->tls->handshake_state = TLS_HS_REAUTH_EXPECTED;
		} else {
			assert (gnutls_safe_renegotiation_status(tls_session) != 0);
			err = gnutls_rehandshake(tls_session);
			if (err != GNUTLS_E_SUCCESS) {
				fprintf(stdout, "[client] gnutls_rehandshake() failed: %s (%i)\n",
					gnutls_strerror_name(err), err);
				assert(false);
			} else {
				fprintf(stdout, "[client] rehandshake started\n");
			}
			client->tls->handshake_state = TLS_HS_EXPECTED;
		}
#else
		assert (gnutls_safe_renegotiation_status(tls_session) != 0);
		err = gnutls_rehandshake(tls_session);
		if (err != GNUTLS_E_SUCCESS) {
			fprintf(stdout, "[client] gnutls_rehandshake() failed: %s (%i)\n",
				gnutls_strerror_name(err), err);
			assert(false);
		} else {
			fprintf(stdout, "[client] rehandshake started\n");
		}
		/* Prevent write-to-client callback from sending next pending chunk.
		* At the same time tls_process_from_client() must not call gnutls_handshake()
		* as there can be application data in this direction.  */
		client->tls->handshake_state = TLS_HS_EXPECTED;
#endif
	}
	return submitted;
}

static int tls_process_from_upstream(struct peer *upstream, const uint8_t *buf, ssize_t len)
{
	struct peer *client = upstream->peer;

	fprintf(stdout, "[upstream] pushing %zd bytes to client\n", len);

	ssize_t submitted = 0;
	if (client->state != STATE_CONNECTED) {
		return submitted;
	}

	bool list_was_empty = (client->pending_buf.len == 0);
	push_to_client_pending(client, (const char *)buf, len);
	submitted = len;
	if (client->tls->handshake_state == TLS_HS_DONE) {
		if (list_was_empty && client->pending_buf.len > 0) {
			int ret = write_to_client_pending(client);
			if (ret < 0) {
				submitted = -1;
			}
		}
	}

	return submitted;
}

int tls_process_handshake(struct peer *peer)
{
	struct tls_ctx *tls = peer->tls;
	int ret = 1;
	while (tls->handshake_state == TLS_HS_IN_PROGRESS) {
		fprintf(stdout, "[tls] TLS handshake in progress...\n");
		int err = gnutls_handshake(tls->session);
		if (err == GNUTLS_E_SUCCESS) {
			tls->handshake_state = TLS_HS_DONE;
			fprintf(stdout, "[tls] TLS handshake has completed\n");
			ret = 1;
			if (peer->pending_buf.len != 0) {
				write_to_client_pending(peer);
			}
		} else if (gnutls_error_is_fatal(err)) {
			fprintf(stdout, "[tls] gnutls_handshake failed: %s (%d)\n",
				gnutls_strerror_name(err), err);
			ret = -1;
			break;
		} else {
			fprintf(stdout, "[tls] gnutls_handshake nonfatal error: %s (%d)\n",
				gnutls_strerror_name(err), err);
			ret = 0;
			break;
		}
	}
	return ret;
}

#if GNUTLS_VERSION_NUMBER >= 0x030604
int tls_process_reauth(struct peer *peer)
{
	struct tls_ctx *tls = peer->tls;
	int ret = 1;
	while (tls->handshake_state == TLS_HS_REAUTH_EXPECTED) {
		fprintf(stdout, "[tls] TLS re-authentication in progress...\n");
		int err = gnutls_reauth(tls->session, 0);
		if (err == GNUTLS_E_SUCCESS) {
			tls->handshake_state = TLS_HS_DONE;
			fprintf(stdout, "[tls] TLS re-authentication has completed\n");
			ret = 1;
			if (peer->pending_buf.len != 0) {
				write_to_client_pending(peer);
			}
		} else if (err != GNUTLS_E_INTERRUPTED &&
			   err != GNUTLS_E_AGAIN &&
			   err != GNUTLS_E_GOT_APPLICATION_DATA) {
				/* these are listed as nonfatal errors there
				 * https://www.gnutls.org/manual/gnutls.html#gnutls_005freauth  */
				fprintf(stdout, "[tls] gnutls_reauth failed: %s (%d)\n",
				gnutls_strerror_name(err), err);
			ret = -1;
			break;
		} else {
			fprintf(stdout, "[tls] gnutls_reauth nonfatal error: %s (%d)\n",
				gnutls_strerror_name(err), err);
			ret = 0;
			break;
		}
	}
	return ret;
}
#endif

int tls_process_from_client(struct peer *client, const uint8_t *buf, ssize_t nread)
{
	struct tls_ctx *tls = client->tls;

	tls->buf = buf;
	tls->nread = nread >= 0 ? nread : 0;
	tls->consumed = 0;

	fprintf(stdout, "[client] tls_process: reading %zd bytes from client\n", nread);

	int ret = 0;
	if (tls->handshake_state == TLS_HS_REAUTH_EXPECTED) {
		ret = tls_process_reauth(client);
	} else {
		ret = tls_process_handshake(client);
	}
	if (ret <= 0) {
		return ret;
	}

	int submitted = 0;
	while (true) {
		ssize_t count = gnutls_record_recv(tls->session, tls->recv_buf, sizeof(tls->recv_buf));
		if (count == GNUTLS_E_AGAIN) {
			break;    /* No data available */
		} else if (count == GNUTLS_E_INTERRUPTED) {
			continue; /* Try reading again */
		} else if (count == GNUTLS_E_REHANDSHAKE) {
			tls->handshake_state = TLS_HS_IN_PROGRESS;
			ret = tls_process_handshake(client);
			if (ret < 0) { /* Critical error */
				return ret;
			}
			if (ret == 0) { /* Non fatal, most likely GNUTLS_E_AGAIN */
				break;
			}
			continue;
		}
#if GNUTLS_VERSION_NUMBER >= 0x030604
		else if (count == GNUTLS_E_REAUTH_REQUEST) {
			assert(false);
			tls->handshake_state = TLS_HS_IN_PROGRESS;
			ret = tls_process_reauth(client);
			if (ret < 0) { /* Critical error */
				return ret;
			}
			if (ret == 0) { /* Non fatal, most likely GNUTLS_E_AGAIN */
				break;
			}
			continue;
		}
#endif
		else if (count < 0) {
			fprintf(stdout, "[client] gnutls_record_recv failed: %s (%zd)\n",
				gnutls_strerror_name(count), count);
			assert(false);
			return -1;
		} else if (count == 0) {
			break;
		}
		struct peer *upstream = client->peer;
		if (upstream->state == STATE_CONNECTED) {
			bool upstream_pending_is_empty = (upstream->pending_buf.len == 0);
			push_to_upstream_pending(upstream, (const char *)tls->recv_buf, count);
			if (upstream_pending_is_empty) {
				write_to_upstream_pending(upstream);
			}
		} else if (upstream->state == STATE_NOT_CONNECTED) {
			uv_connect_t *conn = (uv_connect_t *) malloc(sizeof(uv_connect_t));
			upstream->state = STATE_CONNECT_IN_PROGRESS;
			fprintf(stdout, "[client] connecting to upstream '%s'\n", ip_straddr(&upstream->addr));
			uv_tcp_connect(conn, &upstream->handle, (struct sockaddr *)&upstream->addr,
				       on_connect_to_upstream);
			push_to_upstream_pending(upstream, (const char *)tls->recv_buf, count);
		} else if (upstream->state == STATE_CONNECT_IN_PROGRESS) {
			push_to_upstream_pending(upstream, (const char *)tls->recv_buf, count);
		}
		submitted += count;
	}
	return submitted;
}

struct tls_proxy_ctx *tls_proxy_allocate()
{
	return malloc(sizeof(struct tls_proxy_ctx));
}

int tls_proxy_init(struct tls_proxy_ctx *proxy, const struct args *a)
{
	const char *server_addr = a->local_addr;
	int server_port = a->local_port;
	const char *upstream_addr = a->upstream;
	int upstream_port = a->upstream_port;
	const char *cert_file = a->cert_file;
	const char *key_file = a->key_file;
	proxy->a = a;
	proxy->loop = uv_default_loop();
	uv_tcp_init(proxy->loop, &proxy->server.handle);
	int res = uv_ip4_addr(server_addr, server_port, (struct sockaddr_in *)&proxy->server.addr);
	if (res != 0) {
		res = uv_ip6_addr(server_addr, server_port, (struct sockaddr_in6 *)&proxy->server.addr);
		if (res != 0) {
			fprintf(stdout, "[proxy] tls_proxy_init: can't parse local address '%s'\n", server_addr);
			return -1;
		}
	}
	res = uv_ip4_addr(upstream_addr, upstream_port, (struct sockaddr_in *)&proxy->upstream_addr);
	if (res != 0) {
		res = uv_ip6_addr(upstream_addr, upstream_port, (struct sockaddr_in6 *)&proxy->upstream_addr);
		if (res != 0) {
			fprintf(stdout, "[proxy] tls_proxy_init: can't parse upstream address '%s'\n", upstream_addr);
			return -1;
		}
	}
	array_init(proxy->client_list);
	proxy->conn_sequence = 0;

	proxy->loop->data = proxy;

	int err = 0;
	if (gnutls_references == 0) {
		err = gnutls_global_init();
		if (err != GNUTLS_E_SUCCESS) {
			fprintf(stdout, "[proxy] gnutls_global_init() failed: (%d) %s\n",
				     err, gnutls_strerror_name(err));
			return -1;
		}
	}
	gnutls_references += 1;

	err = gnutls_certificate_allocate_credentials(&proxy->tls_credentials);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf(stdout, "[proxy] gnutls_certificate_allocate_credentials() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		return -1;
	}

	err = gnutls_certificate_set_x509_system_trust(proxy->tls_credentials);
	if (err <= 0) {
		fprintf(stdout, "[proxy] gnutls_certificate_set_x509_system_trust() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		return -1;
	}

	if (cert_file && key_file) {
		err = gnutls_certificate_set_x509_key_file(proxy->tls_credentials,
						     cert_file, key_file, GNUTLS_X509_FMT_PEM);
		if (err != GNUTLS_E_SUCCESS) {
			fprintf(stdout, "[proxy] gnutls_certificate_set_x509_key_file() failed: (%d) %s\n",
				     err, gnutls_strerror_name(err));
			return -1;
		}
	}

	err = gnutls_priority_init(&proxy->tls_priority_cache, NULL, NULL);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf(stdout, "[proxy] gnutls_priority_init() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		return -1;
	}

	return 0;
}

void tls_proxy_free(struct tls_proxy_ctx *proxy)
{
	if (!proxy) {
		return;
	}
	while (proxy->client_list.len > 0) {
		size_t last_index = proxy->client_list.len - 1;
		struct peer *client = proxy->client_list.at[last_index];
		clear_pending_bufs(client);
		clear_pending_bufs(client->peer);
		/* TODO correctly close all the uv_tcp_t */
		free(client->peer);
		free(client);
		array_del(proxy->client_list, last_index);
	}
	gnutls_certificate_free_credentials(proxy->tls_credentials);
        gnutls_priority_deinit(proxy->tls_priority_cache);
	free(proxy);

	gnutls_references -= 1;
	if (gnutls_references == 0) {
		gnutls_global_deinit();
	}
}

int tls_proxy_start_listen(struct tls_proxy_ctx *proxy)
{
	uv_tcp_bind(&proxy->server.handle, (const struct sockaddr*)&proxy->server.addr, 0);
	int ret = uv_listen((uv_stream_t*)&proxy->server.handle, 128, on_client_connection);
	return ret;
}

int tls_proxy_run(struct tls_proxy_ctx *proxy)
{
	return uv_run(proxy->loop, UV_RUN_DEFAULT);
}
