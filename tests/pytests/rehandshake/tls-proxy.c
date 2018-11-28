#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <gnutls/gnutls.h>
#include <uv.h>
#include "array.h"

#define TLS_MAX_SEND_RETRIES 100
#define CLIENT_ANSWER_CHUNK_SIZE 8
struct buf {
	char buf[16 * 1024];
	size_t size;
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
	TLS_HS_IN_PROGRESS,
	TLS_HS_DONE,
	TLS_HS_CLOSING,
	TLS_HS_LAST
};

struct tls_ctx {
	gnutls_session_t session;
	int handshake_state;
	gnutls_certificate_credentials_t credentials;
        gnutls_priority_t priority_cache;
	/* for reading from the network */
	const uint8_t *buf;
	ssize_t nread;
	ssize_t consumed;
	uint8_t recv_buf[4096];
};

struct tls_proxy_ctx {
	uv_loop_t *loop;
	uv_tcp_t server;
	uv_tcp_t client;
	uv_tcp_t upstream;
	struct sockaddr_storage server_addr;
	struct sockaddr_storage upstream_addr;
	struct sockaddr_storage client_addr;
	
	int server_state;
	int client_state;
	int upstream_state;

	array_t(struct buf *) buffer_pool;
	array_t(struct buf *) upstream_pending;
	array_t(struct buf *) client_pending;
	
	char io_buf[0xFFFF];
	struct tls_ctx tls;
};

static void read_from_upstream_cb(uv_stream_t *upstream, ssize_t nread, const uv_buf_t *buf);
static void read_from_client_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf);
static ssize_t proxy_gnutls_pull(gnutls_transport_ptr_t h, void *buf, size_t len);
static ssize_t proxy_gnutls_push(gnutls_transport_ptr_t h, const void *buf, size_t len);
static int tls_process_from_upstream(struct tls_proxy_ctx *proxy, const uint8_t *buf, ssize_t nread);
static int tls_process_from_client(struct tls_proxy_ctx *proxy, const uint8_t *buf, ssize_t nread);
static int write_to_upstream_pending(struct tls_proxy_ctx *proxy);
static int write_to_client_pending(struct tls_proxy_ctx *proxy);


static int gnutls_references = 0;

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
	snprintf(&str[len + 1], 6, "%uh", ip_addr_port(addr));
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

static inline char *ip_straddr(const struct sockaddr *addr)
{
	assert(addr != NULL);
	/* We are the sinle-threaded application */
	static char str[INET6_ADDRSTRLEN + 6];
	size_t len = sizeof(str);
	int ret = ip_addr_str(addr, str, &len);
	return ret != 0 || len == 0 ? NULL : str;
}

static struct buf *borrow_io_buffer(struct tls_proxy_ctx *proxy)
{
	struct buf *buf = NULL;
	if (proxy->buffer_pool.len > 0) {
		buf = array_tail(proxy->buffer_pool);
		array_pop(proxy->buffer_pool);
	} else {
		buf = calloc(1, sizeof (struct buf));
	}
	return buf;
}

static void release_io_buffer(struct tls_proxy_ctx *proxy, struct buf *buf)
{
	if (!buf) {
		return;
	}

	if (proxy->buffer_pool.len < 1000) {
		buf->size = 0;
		array_push(proxy->buffer_pool, buf);
	} else {
		free(buf);
	}
}

static struct buf *get_first_upstream_pending(struct tls_proxy_ctx *proxy)
{
	struct buf *buf = NULL;
	if (proxy->upstream_pending.len > 0) {
		buf = proxy->upstream_pending.at[0];
	}
	return buf;
}

static struct buf *get_first_client_pending(struct tls_proxy_ctx *proxy)
{
	struct buf *buf = NULL;
	if (proxy->client_pending.len > 0) {
		buf = proxy->client_pending.at[0];
	}
	return buf;
}

static void remove_first_upstream_pending(struct tls_proxy_ctx *proxy)
{
	for (int i = 1; i < proxy->upstream_pending.len; ++i) {
		proxy->upstream_pending.at[i - 1] = proxy->upstream_pending.at[i];
	}
	if (proxy->upstream_pending.len > 0) {
		proxy->upstream_pending.len -= 1;
	}
}

static void remove_first_client_pending(struct tls_proxy_ctx *proxy)
{
	for (int i = 1; i < proxy->client_pending.len; ++i) {
		proxy->client_pending.at[i - 1] = proxy->client_pending.at[i];
	}
	if (proxy->client_pending.len > 0) {
		proxy->client_pending.len -= 1;
	}
}

static void clear_upstream_pending(struct tls_proxy_ctx *proxy)
{
	for (int i = 0; i < proxy->upstream_pending.len; ++i) {
		struct buf *b = proxy->upstream_pending.at[i];
		release_io_buffer(proxy, b);
	}
	proxy->upstream_pending.len = 0;
}

static void clear_client_pending(struct tls_proxy_ctx *proxy)
{
	for (int i = 0; i < proxy->client_pending.len; ++i) {
		struct buf *b = proxy->client_pending.at[i];
		release_io_buffer(proxy, b);
	}
	proxy->client_pending.len = 0;
}

static void clear_buffer_pool(struct tls_proxy_ctx *proxy)
{
	for (int i = 0; i < proxy->buffer_pool.len; ++i) {
		struct buf *b = proxy->buffer_pool.at[i];
		free(b);
	}
	proxy->buffer_pool.len = 0;
}

static void alloc_uv_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)handle->loop->data;
	buf->base = proxy->io_buf;
	buf->len = sizeof(proxy->io_buf);
}

static void on_client_close(uv_handle_t *handle)
{
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)handle->loop->data;
	gnutls_deinit(proxy->tls.session);
	proxy->tls.handshake_state = TLS_HS_NOT_STARTED;
	proxy->client_state = STATE_NOT_CONNECTED;
}

static void on_dummmy_client_close(uv_handle_t *handle)
{
	free(handle);
}

static void on_upstream_close(uv_handle_t *handle)
{
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)handle->loop->data;
	proxy->upstream_state = STATE_NOT_CONNECTED;
}

static void write_to_client_cb(uv_write_t *req, int status)
{
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)req->handle->loop->data;
	free(req);
	if (status) {
		fprintf(stderr, "error writing to client: %s\n", uv_strerror(status));
		clear_client_pending(proxy);
		clear_upstream_pending(proxy);
		if (proxy->client_state == STATE_CONNECTED) {
			proxy->client_state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)&proxy->client, on_client_close);
			return;
		}
	}
	fprintf(stdout, "successfully wrote to client, pending len is %zd\n",
		proxy->client_pending.len);
	if (proxy->client_state == STATE_CONNECTED &&
	    proxy->tls.handshake_state == TLS_HS_DONE) {
		write_to_client_pending(proxy);
	}
}

static void write_to_upstream_cb(uv_write_t *req, int status)
{
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)req->handle->loop->data;
	if (status) {
		free(req);
		fprintf(stderr, "error writing to upstream: %s\n", uv_strerror(status));
		clear_upstream_pending(proxy);
		proxy->upstream_state = STATE_CLOSING_IN_PROGRESS;
		uv_close((uv_handle_t*)&proxy->upstream, on_upstream_close);
		return;
	}
	if (req->data != NULL) {
		assert(proxy->upstream_pending.len > 0);
		struct buf *buf = get_first_upstream_pending(proxy);
		assert(req->data == (void *)buf->buf);
		fprintf(stdout, "successfully wrote %zi bytes to upstream, pending len is %zd\n",
			buf->size, proxy->upstream_pending.len);
		remove_first_upstream_pending(proxy);
		release_io_buffer(proxy, buf);
	} else {
		fprintf(stdout, "successfully wrote bytes to upstream, pending len is %zd\n",
			proxy->upstream_pending.len);
	}
	if (proxy->upstream_state == STATE_CONNECTED &&
	    proxy->upstream_pending.len > 0) {
		write_to_upstream_pending(proxy);
	}
	free(req);
}

static void on_client_connection(uv_stream_t *server, int status)
{
	if (status < 0) {
		fprintf(stderr, "incoming connection error: %s\n", uv_strerror(status));
		return;
	}

	int err = 0;
	int ret = 0;
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)server->loop->data;
	if (proxy->client_state != STATE_NOT_CONNECTED) {
		fprintf(stderr, "incoming connection");
		uv_tcp_t *dummy_client = malloc(sizeof(uv_tcp_t));
		uv_tcp_init(proxy->loop, dummy_client);
		err = uv_accept(server, (uv_stream_t*)dummy_client);
		if (err == 0) {
			struct sockaddr dummy_addr;
			int dummy_addr_len = sizeof(dummy_addr);
			ret = uv_tcp_getpeername(dummy_client,
						 &dummy_addr,
						 &dummy_addr_len);
			if (ret == 0) {
				fprintf(stderr, " from %s", ip_straddr(&dummy_addr));
			}
			uv_close((uv_handle_t *)dummy_client, on_dummmy_client_close);
		} else {
			on_dummmy_client_close((uv_handle_t *)dummy_client);
		}
		fprintf(stderr, " - client already connected, rejecting\n");
		return;
	}

	uv_tcp_init(proxy->loop, &proxy->client);
	uv_tcp_nodelay((uv_tcp_t *)&proxy->client, 1);
	proxy->client_state = STATE_CONNECTED;
	err = uv_accept(server, (uv_stream_t*)&proxy->client);
	if (err != 0) {
		fprintf(stderr, "incoming connection - uv_accept() failed: (%d) %s\n",
			     err, uv_strerror(err));
		return;
	}

	struct sockaddr *addr = (struct sockaddr *)&(proxy->client_addr);
	int addr_len = sizeof(proxy->client_addr);
	ret = uv_tcp_getpeername(&proxy->client, addr, &addr_len);
	if (ret || addr->sa_family == AF_UNSPEC) {
		proxy->client_state = STATE_CLOSING_IN_PROGRESS;
		uv_close((uv_handle_t*)&proxy->client, on_client_close);
		fprintf(stderr, "incoming connection - uv_tcp_getpeername() failed: (%d) %s\n",
			     err, uv_strerror(err));
		return;
	}
	
	fprintf(stdout, "incoming connection from %s\n", ip_straddr(addr));
	
	uv_read_start((uv_stream_t*)&proxy->client, alloc_uv_buffer, read_from_client_cb);

	const char *errpos = NULL;
	struct tls_ctx *tls = &proxy->tls;
	assert (tls->handshake_state == TLS_HS_NOT_STARTED);
	err = gnutls_init(&tls->session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "gnutls_init() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
	}
        err = gnutls_priority_set(tls->session, tls->priority_cache);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "gnutls_priority_set() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
	}
	err = gnutls_credentials_set(tls->session, GNUTLS_CRD_CERTIFICATE, tls->credentials);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "gnutls_credentials_set() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
	}
	gnutls_certificate_server_set_request(tls->session, GNUTLS_CERT_IGNORE);
	gnutls_handshake_set_timeout(tls->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	gnutls_transport_set_pull_function(tls->session, proxy_gnutls_pull);
	gnutls_transport_set_push_function(tls->session, proxy_gnutls_push);
	gnutls_transport_set_ptr(tls->session, proxy);

	tls->handshake_state = TLS_HS_IN_PROGRESS;
}

static void on_connect_to_upstream(uv_connect_t *req, int status)
{
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)req->handle->loop->data;
	free(req);
	if (status < 0) {
		fprintf(stderr, "error connecting to upstream (%s): %s\n",
			ip_straddr((struct sockaddr *)&proxy->upstream_addr),
			uv_strerror(status));
		clear_upstream_pending(proxy);
		proxy->upstream_state = STATE_CLOSING_IN_PROGRESS;
		uv_close((uv_handle_t*)&proxy->upstream, on_upstream_close);
		return;
	}
	fprintf(stdout, "connected to %s\n", ip_straddr((struct sockaddr *)&proxy->upstream_addr));

	proxy->upstream_state = STATE_CONNECTED;
	uv_read_start((uv_stream_t*)&proxy->upstream, alloc_uv_buffer, read_from_upstream_cb);
	if (proxy->upstream_pending.len > 0) {
		write_to_upstream_pending(proxy);
	}
}

static void read_from_client_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
	fprintf(stdout, "reading %zd bytes from client\n", nread);
	if (nread == 0) {
		return;
	}
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)client->loop->data;
	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stderr, "error reading from client: %s\n", uv_err_name(nread));
		} else {
			fprintf(stdout, "client has closed the connection\n");
		}
		if (proxy->client_state == STATE_CONNECTED) {
			proxy->client_state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*) client, on_client_close);
		}
		return;
	}

	int res = tls_process_from_client(proxy, buf->base, nread);
	if (res < 0) {
		if (proxy->client_state == STATE_CONNECTED) {
			proxy->client_state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*) client, on_client_close);
		}
	}
}

static void read_from_upstream_cb(uv_stream_t *upstream, ssize_t nread, const uv_buf_t *buf)
{
	fprintf(stdout, "reading %zd bytes from upstream\n", nread);
	if (nread == 0) {
		return;
	}
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)upstream->loop->data;
	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stderr, "error reading from upstream: %s\n", uv_err_name(nread));
		} else {
			fprintf(stdout, "upstream has closed the connection\n");
		}
		clear_upstream_pending(proxy);
		if (proxy->upstream_state == STATE_CONNECTED) {
			proxy->upstream_state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)&proxy->upstream, on_upstream_close);
		}
		return;
	}
	int res = tls_process_from_upstream(proxy, buf->base, nread);
	if (res < 0) {
		fprintf(stderr, "error sending tls data to client\n");
		if (proxy->client_state == STATE_CONNECTED) {
			proxy->client_state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)&proxy->client, on_client_close);
		}
	}
}

static void push_to_upstream_pending(struct tls_proxy_ctx *proxy, const char *buf, size_t size)
{
	while (size > 0) {
		struct buf *b = borrow_io_buffer(proxy);
		b->size = size <= sizeof(b->buf) ? size : sizeof(b->buf);
		memcpy(b->buf, buf, b->size);
		array_push(proxy->upstream_pending, b);
		size -= b->size;
		buf += b->size;
	}
}

static void push_to_client_pending(struct tls_proxy_ctx *proxy, const char *buf, size_t size)
{
	while (size > 0) {
		struct buf *b = borrow_io_buffer(proxy);
		b->size = size <= sizeof(b->buf) ? size : sizeof(b->buf);
		if (b->size > CLIENT_ANSWER_CHUNK_SIZE) {
			b->size = CLIENT_ANSWER_CHUNK_SIZE;
		}
		memcpy(b->buf, buf, b->size);
		array_push(proxy->client_pending, b);
		size -= b->size;
		buf += b->size;
	}
}

static int write_to_upstream_pending(struct tls_proxy_ctx *proxy)
{
	struct buf *buf = get_first_upstream_pending(proxy);
	/* TODO avoid allocation */
	uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));
	uv_buf_t wrbuf = uv_buf_init(buf->buf, buf->size);
	req->data = buf->buf;
	fprintf(stdout, "writing %zd bytes to upstream\n", buf->size);
	return uv_write(req, (uv_stream_t *)&proxy->upstream, &wrbuf, 1, write_to_upstream_cb);
}

static ssize_t proxy_gnutls_pull(gnutls_transport_ptr_t h, void *buf, size_t len)
{
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)h;
	struct tls_ctx *t = &proxy->tls;

	fprintf(stdout, "\t gnutls: pulling %zd bytes from client\n", len);

	if (t->nread <= t->consumed) {
		errno = EAGAIN;
		fprintf(stdout, "\t gnutls: return EAGAIN\n");
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
	struct tls_proxy_ctx *proxy = (struct tls_proxy_ctx *)h;
	struct tls_ctx *t = &proxy->tls;
	fprintf(stdout, "\t gnutls: writing %zd bytes to client\n", len);

	ssize_t ret = -1;
	const size_t req_size_aligned = ((sizeof(uv_write_t) / 16) + 1) * 16;
	char *common_buf = malloc(req_size_aligned + len);
	uv_write_t *req = (uv_write_t *) common_buf;
	char *data = common_buf + req_size_aligned;
	const uv_buf_t uv_buf[1] = {
		{ data, len }
	};
	memcpy(data, buf, len);
	req->data = data;
	int res = uv_write(req, (uv_stream_t *)&proxy->client, uv_buf, 1, write_to_client_cb);
	if (res == 0) {
		ret = len;
	} else {
		free(common_buf);
		errno = EIO;
	}
	return ret;
}

static int write_to_client_pending(struct tls_proxy_ctx *proxy)
{
	if (proxy->client_pending.len == 0) {
		return 0;
	}

	struct buf *buf = get_first_client_pending(proxy);
	uv_buf_t wrbuf = uv_buf_init(buf->buf, buf->size);
	fprintf(stdout, "writing %zd bytes to client\n", buf->size);

	gnutls_session_t tls_session = proxy->tls.session;
	assert(proxy->tls.handshake_state != TLS_HS_IN_PROGRESS);
	assert(gnutls_record_check_corked(tls_session) == 0);

	char *data = buf->buf;
	size_t len = buf->size;

	ssize_t count = 0;
	ssize_t submitted = len;
	ssize_t retries = 0;
	do {
		count = gnutls_record_send(tls_session, data, len);
		if (count < 0) {
			if (gnutls_error_is_fatal(count)) {
				fprintf(stderr, "gnutls_record_send failed: %s (%zd)\n",
					gnutls_strerror_name(count), count);
				return -1;
			}
			if (++retries > TLS_MAX_SEND_RETRIES) {
				fprintf(stderr, "gnutls_record_send: too many sequential non-fatal errors (%zd), last error is: %s (%zd)\n",
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
			fprintf(stderr, "gnutls_record_send: too many retries (%zd)\n",
				retries);
			fprintf(stderr, "tls_push_to_client didn't send all data(%zd of %zd)\n",
				len, submitted);
			return -1;
		}
	} while (len > 0);

	remove_first_client_pending(proxy);
	release_io_buffer(proxy, buf);

	fprintf(stdout, "submitted %zd bytes to client\n", submitted);
	assert (gnutls_safe_renegotiation_status(tls_session) != 0);
	assert (gnutls_rehandshake(tls_session) == GNUTLS_E_SUCCESS);
	/* Prevent write-to-client callback from sending next pending chunk.
	 * At the same time tls_process_from_client() must not call gnutls_handshake()
	 * as there can be application data in this direction.  */
	proxy->tls.handshake_state = TLS_HS_EXPECTED;
	fprintf(stdout, "rehandshake started\n");
	return submitted;
}

static int tls_process_from_upstream(struct tls_proxy_ctx *proxy, const uint8_t *buf, ssize_t len)
{
	gnutls_session_t tls_session = proxy->tls.session;

	fprintf(stdout, "pushing %zd bytes to client\n", len);

	assert(gnutls_record_check_corked(tls_session) == 0);
	ssize_t submitted = 0;
	if (proxy->client_state != STATE_CONNECTED) {
		return submitted;
	}

	bool list_was_empty = (proxy->client_pending.len == 0);
	push_to_client_pending(proxy, buf, len);
	submitted = len;
	if (proxy->tls.handshake_state == TLS_HS_DONE) {
		if (list_was_empty && proxy->client_pending.len > 0) {
			int ret = write_to_client_pending(proxy);
			if (ret < 0) {
				submitted = -1;
			}
		}
	}

	return submitted;
}

int tls_process_handshake(struct tls_proxy_ctx *proxy)
{
	struct tls_ctx *tls = &proxy->tls;
	int ret = 1;
	while (tls->handshake_state == TLS_HS_IN_PROGRESS) {
		fprintf(stdout, "TLS handshake in progress...\n");
		int err = gnutls_handshake(tls->session);
		if (err == GNUTLS_E_SUCCESS) {
			tls->handshake_state = TLS_HS_DONE;
			fprintf(stdout, "TLS handshake has completed\n");
			ret = 1;
			if (proxy->client_pending.len != 0) {
				write_to_client_pending(proxy);
			}
		} else if (gnutls_error_is_fatal(err)) {
			fprintf(stderr, "gnutls_handshake failed: %s (%d)\n",
				gnutls_strerror_name(err), err);
			ret = -1;
			break;
		} else {
			fprintf(stderr, "gnutls_handshake nonfatal error: %s (%d)\n",
				gnutls_strerror_name(err), err);
			ret = 0;
			break;
		}
	}
	return ret;
}

int tls_process_from_client(struct tls_proxy_ctx *proxy, const uint8_t *buf, ssize_t nread)
{
	struct tls_ctx *tls = &proxy->tls;

	tls->buf = buf;
	tls->nread = nread >= 0 ? nread : 0;
	tls->consumed = 0;

	fprintf(stdout, "tls_process: reading %zd bytes from client\n", nread);

	int ret = tls_process_handshake(proxy);
	if (ret <= 0) {
		return ret;
	}

	int submitted = 0;
	while (true) {
		ssize_t count = 0;
		count = gnutls_record_recv(tls->session, tls->recv_buf, sizeof(tls->recv_buf));
		if (count == GNUTLS_E_AGAIN) {
			break;    /* No data available */
		} else if (count == GNUTLS_E_INTERRUPTED) {
			continue; /* Try reading again */
		} else if (count == GNUTLS_E_REHANDSHAKE) {
			tls->handshake_state = TLS_HS_IN_PROGRESS;
			ret = tls_process_handshake(proxy);
			if (ret <= 0) {
				return ret;
			}
			continue;
		} else if (count < 0) {
			fprintf(stderr, "gnutls_record_recv failed: %s (%zd)\n",
				gnutls_strerror_name(count), count);
			return -1;
		} else if (count == 0) {
			break;
		}
		if (proxy->upstream_state == STATE_CONNECTED) {
			bool upstream_pending_is_empty = (proxy->upstream_pending.len == 0);
			push_to_upstream_pending(proxy, tls->recv_buf, count);
			if (upstream_pending_is_empty) {
				write_to_upstream_pending(proxy);
			}
		} else if (proxy->upstream_state == STATE_NOT_CONNECTED) {
			/* TODO avoid allocation */
			uv_tcp_init(proxy->loop, &proxy->upstream);	
			uv_connect_t *conn = (uv_connect_t *) malloc(sizeof(uv_connect_t));
			proxy->upstream_state = STATE_CONNECT_IN_PROGRESS;
			fprintf(stdout, "connecting to %s\n",
				ip_straddr((struct sockaddr *)&proxy->upstream_addr));
			uv_tcp_connect(conn, &proxy->upstream, (struct sockaddr *)&proxy->upstream_addr,
				       on_connect_to_upstream);
			push_to_upstream_pending(proxy, tls->recv_buf, count);
		} else if (proxy->upstream_state == STATE_CONNECT_IN_PROGRESS) {
			push_to_upstream_pending(proxy, tls->recv_buf, count);
		}
		submitted += count;
	}
	return submitted;
}

struct tls_proxy_ctx *tls_proxy_allocate()
{
	return malloc(sizeof(struct tls_proxy_ctx));
}

int tls_proxy_init(struct tls_proxy_ctx *proxy,
		   const char *server_addr, int server_port,
		   const char *upstream_addr, int upstream_port,
		   const char *cert_file, const char *key_file)
{	
	proxy->loop = uv_default_loop();
	uv_tcp_init(proxy->loop, &proxy->server);
	int res = uv_ip4_addr(server_addr, server_port, (struct sockaddr_in *)&proxy->server_addr);
	if (res != 0) {
		fprintf(stderr, "uv_ip4_addr failed with string '%s'\n", server_addr);
		return -1;
	}
	res = uv_ip4_addr(upstream_addr, upstream_port, (struct sockaddr_in *)&proxy->upstream_addr);
	if (res != 0) {
		fprintf(stderr, "uv_ip4_addr failed with string '%s'\n", upstream_addr);
		return -1;
	}
	array_init(proxy->buffer_pool);
	array_init(proxy->upstream_pending);
	array_init(proxy->client_pending);
	proxy->server_state = STATE_NOT_CONNECTED;
	proxy->client_state = STATE_NOT_CONNECTED;
	proxy->upstream_state = STATE_NOT_CONNECTED;

	proxy->loop->data = proxy;
	
	int err = 0;
	if (gnutls_references == 0) {
		err = gnutls_global_init();
		if (err != GNUTLS_E_SUCCESS) {
			fprintf(stderr, "gnutls_global_init() failed: (%d) %s\n",
				     err, gnutls_strerror_name(err));
			return -1;
		}
	}
	gnutls_references += 1;
	
	err = gnutls_certificate_allocate_credentials(&proxy->tls.credentials);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "gnutls_certificate_allocate_credentials() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		return -1;
	}

	err = gnutls_certificate_set_x509_system_trust(proxy->tls.credentials);
	if (err <= 0) {
		fprintf(stderr, "gnutls_certificate_set_x509_system_trust() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		return -1;
	}

	if (cert_file && key_file) {
		err = gnutls_certificate_set_x509_key_file(proxy->tls.credentials,
						     cert_file, key_file, GNUTLS_X509_FMT_PEM);
		if (err != GNUTLS_E_SUCCESS) {
			fprintf(stderr, "gnutls_certificate_set_x509_key_file() failed: (%d) %s\n",
				     err, gnutls_strerror_name(err));
			return -1;
		}
	}

	err = gnutls_priority_init(&proxy->tls.priority_cache, NULL, NULL);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "gnutls_priority_init() failed: (%d) %s\n",
			     err, gnutls_strerror_name(err));
		return -1;
	}

	
	proxy->tls.handshake_state = TLS_HS_NOT_STARTED;
	return 0;
}

void tls_proxy_free(struct tls_proxy_ctx *proxy)
{
	if (!proxy) {
		return;
	}
	clear_upstream_pending(proxy);
	clear_client_pending(proxy);
	clear_buffer_pool(proxy);
	gnutls_certificate_free_credentials(proxy->tls.credentials);
        gnutls_priority_deinit(proxy->tls.priority_cache);
	/* TODO correctly close all the uv_tcp_t */
	free(proxy);
	
	gnutls_references -= 1;
	if (gnutls_references == 0) {
		gnutls_global_deinit();
	}
}

int tls_proxy_start_listen(struct tls_proxy_ctx *proxy)
{	
	uv_tcp_bind(&proxy->server, (const struct sockaddr*)&proxy->server_addr, 0);
	int ret = uv_listen((uv_stream_t*)&proxy->server, 128, on_client_connection);
	if (ret == 0) {
		proxy->server_state = STATE_LISTENING;
	}
	return ret;
}

int tls_proxy_run(struct tls_proxy_ctx *proxy)
{
	return uv_run(proxy->loop, UV_RUN_DEFAULT);
}
