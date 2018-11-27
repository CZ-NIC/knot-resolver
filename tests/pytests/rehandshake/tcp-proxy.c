#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <uv.h>
#include "array.h"

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

struct proxy_ctx {
	uv_loop_t *loop;
	uv_tcp_t server;
	uv_tcp_t client;
	uv_tcp_t upstream;
	struct sockaddr_storage server_addr;
	struct sockaddr_storage upstream_addr;
	
	int server_state;
	int client_state;
	int upstream_state;

	array_t(struct buf *) buffer_pool;
	array_t(struct buf *) upstream_pending;
};

static void read_from_upstream_cb(uv_stream_t *upstream, ssize_t nread, const uv_buf_t *buf);
static void read_from_client_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf);

static struct buf *borrow_io_buffer(struct proxy_ctx *proxy)
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

static void release_io_buffer(struct proxy_ctx *proxy, struct buf *buf)
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

static void push_to_upstream_pending(struct proxy_ctx *proxy, const char *buf, size_t size)
{
	while (size > 0) {
		struct buf *b = borrow_io_buffer(proxy);
		b->size = size <= sizeof(b->buf) ? size : sizeof(b->buf);
		memcpy(b->buf, buf, b->size);
		array_push(proxy->upstream_pending, b);
		size -= b->size;
	}
}

static struct buf *get_first_upstream_pending(struct proxy_ctx *proxy)
{
	struct buf *buf = NULL;
	if (proxy->upstream_pending.len > 0) {
		buf = proxy->upstream_pending.at[0];
	}
	return buf;
}

static void remove_first_upstream_pending(struct proxy_ctx *proxy)
{
	for (int i = 1; i < proxy->upstream_pending.len; ++i) {
		proxy->upstream_pending.at[i - 1] = proxy->upstream_pending.at[i];
	}
	if (proxy->upstream_pending.len > 0) {
		proxy->upstream_pending.len -= 1;
	}
}

static void clear_upstream_pending(struct proxy_ctx *proxy)
{
	for (int i = 1; i < proxy->upstream_pending.len; ++i) {
		struct buf *b = proxy->upstream_pending.at[i];
		release_io_buffer(proxy, b);
	}
	proxy->upstream_pending.len = 0;
}

static void clear_buffer_pool(struct proxy_ctx *proxy)
{
	for (int i = 1; i < proxy->buffer_pool.len; ++i) {
		struct buf *b = proxy->buffer_pool.at[i];
		free(b);
	}
	proxy->buffer_pool.len = 0;
}

static void alloc_uv_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	buf->base = (char*)malloc(suggested_size);
	buf->len = suggested_size;
}

static void on_client_close(uv_handle_t *handle)
{
	struct proxy_ctx *proxy = (struct proxy_ctx *)handle->loop->data;
	proxy->client_state = STATE_NOT_CONNECTED;
}

static void on_upstream_close(uv_handle_t *handle)
{
	struct proxy_ctx *proxy = (struct proxy_ctx *)handle->loop->data;
	proxy->upstream_state = STATE_NOT_CONNECTED;
}

static void write_to_client_cb(uv_write_t *req, int status)
{
	struct proxy_ctx *proxy = (struct proxy_ctx *)req->handle->loop->data;
	free(req);
	if (status) {
		fprintf(stderr, "error writing to client: %s\n", uv_strerror(status));
		clear_upstream_pending(proxy);
		proxy->client_state = STATE_CLOSING_IN_PROGRESS;
		uv_close((uv_handle_t*)&proxy->client, on_client_close);
	}
}

static void write_to_upstream_cb(uv_write_t *req, int status)
{
	struct proxy_ctx *proxy = (struct proxy_ctx *)req->handle->loop->data;
	free(req);
	if (status) {
		fprintf(stderr, "error writing to upstream: %s\n", uv_strerror(status));
		clear_upstream_pending(proxy);
		proxy->upstream_state = STATE_CLOSING_IN_PROGRESS;
		uv_close((uv_handle_t*)&proxy->upstream, on_upstream_close);
		return;
	}
	if (proxy->upstream_pending.len > 0) {
		struct buf *buf = get_first_upstream_pending(proxy);
		remove_first_upstream_pending(proxy);
		release_io_buffer(proxy, buf);
		if (proxy->upstream_state == STATE_CONNECTED &&
		    proxy->upstream_pending.len > 0) {
			buf = get_first_upstream_pending(proxy);
			/* TODO avoid allocation */
			uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));
			uv_buf_t wrbuf = uv_buf_init(buf->buf, buf->size);
			uv_write(req, (uv_stream_t *)&proxy->upstream, &wrbuf, 1, write_to_upstream_cb);
		}
	}
}

static void on_client_connection(uv_stream_t *server, int status)
{
	if (status < 0) {
		fprintf(stderr, "incoming connection error: %s\n", uv_strerror(status));
		return;
	}

	fprintf(stdout, "incoming connection\n");

	struct proxy_ctx *proxy = (struct proxy_ctx *)server->loop->data;
	if (proxy->client_state != STATE_NOT_CONNECTED) {
		fprintf(stderr, "client already connected, ignoring\n");
		return;
	}

	uv_tcp_init(proxy->loop, &proxy->client);
	proxy->client_state = STATE_CONNECTED;
	if (uv_accept(server, (uv_stream_t*)&proxy->client) == 0) {
		uv_read_start((uv_stream_t*)&proxy->client, alloc_uv_buffer, read_from_client_cb);
	} else {
		proxy->client_state = STATE_CLOSING_IN_PROGRESS;
		uv_close((uv_handle_t*)&proxy->client, on_client_close);
	}
}

static void on_connect_to_upstream(uv_connect_t *req, int status)
{
	struct proxy_ctx *proxy = (struct proxy_ctx *)req->handle->loop->data;
	free(req);
	if (status < 0) {
		fprintf(stderr, "error connecting to upstream: %s\n", uv_strerror(status));
		clear_upstream_pending(proxy);
		proxy->upstream_state = STATE_CLOSING_IN_PROGRESS;
		uv_close((uv_handle_t*)&proxy->upstream, on_upstream_close);
		return;
	}

	proxy->upstream_state = STATE_CONNECTED;
	uv_read_start((uv_stream_t*)&proxy->upstream, alloc_uv_buffer, read_from_upstream_cb);
	if (proxy->upstream_pending.len > 0) {
		struct buf *buf = get_first_upstream_pending(proxy);
		/* TODO avoid allocation */
		uv_write_t *wreq = (uv_write_t *) malloc(sizeof(uv_write_t));
		uv_buf_t wrbuf = uv_buf_init(buf->buf, buf->size);
		uv_write(wreq, (uv_stream_t *)&proxy->upstream, &wrbuf, 1, write_to_upstream_cb);
	}
}

static void read_from_client_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
	if (nread == 0) {
		return;
	}
	struct proxy_ctx *proxy = (struct proxy_ctx *)client->loop->data;
	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stderr, "error reading from client: %s\n", uv_err_name(nread));
		}
		if (proxy->client_state == STATE_CONNECTED) {
			proxy->client_state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*) client, on_client_close);
		}
		return;
	}
	if (proxy->upstream_state == STATE_CONNECTED) {
		if (proxy->upstream_pending.len > 0) {
			push_to_upstream_pending(proxy, buf->base, nread);
		} else {
			/* TODO avoid allocation */
			uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));
			uv_buf_t wrbuf = uv_buf_init(buf->base, nread);
			uv_write(req, (uv_stream_t *)&proxy->upstream, &wrbuf, 1, write_to_upstream_cb);
		}
	} else if (proxy->upstream_state == STATE_NOT_CONNECTED) {
		/* TODO avoid allocation */
		uv_tcp_init(proxy->loop, &proxy->upstream);	
		uv_connect_t *conn = (uv_connect_t *) malloc(sizeof(uv_connect_t));
		proxy->upstream_state = STATE_CONNECT_IN_PROGRESS;
		uv_tcp_connect(conn, &proxy->upstream, (struct sockaddr *)&proxy->upstream_addr,
			       on_connect_to_upstream);
		push_to_upstream_pending(proxy, buf->base, nread);
	} else if (proxy->upstream_state == STATE_CONNECT_IN_PROGRESS) {
		push_to_upstream_pending(proxy, buf->base, nread);
	}
}

static void read_from_upstream_cb(uv_stream_t *upstream, ssize_t nread, const uv_buf_t *buf)
{
	if (nread == 0) {
		return;
	}
	struct proxy_ctx *proxy = (struct proxy_ctx *)upstream->loop->data;
	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stderr, "error reading from upstream: %s\n", uv_err_name(nread));
		}
		clear_upstream_pending(proxy);
		if (proxy->upstream_state == STATE_CONNECTED) {
			proxy->upstream_state = STATE_CLOSING_IN_PROGRESS;
			uv_close((uv_handle_t*)&proxy->upstream, on_upstream_close);
		}
		return;
	}
	if (proxy->client_state == STATE_CONNECTED) {
		/* TODO Avoid allocation */
		uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));
		uv_buf_t wrbuf = uv_buf_init(buf->base, nread);
		uv_write(req, (uv_stream_t *)&proxy->client, &wrbuf, 1, write_to_client_cb);
	}
}

struct proxy_ctx *proxy_allocate()
{
	return malloc(sizeof(struct proxy_ctx));
}

int proxy_init(struct proxy_ctx *proxy,
	       const char *server_addr, int server_port,
	       const char *upstream_addr, int upstream_port)
{
	proxy->loop = uv_default_loop();
	uv_tcp_init(proxy->loop, &proxy->server);
	int res = uv_ip4_addr(server_addr, server_port, (struct sockaddr_in *)&proxy->server_addr);
	if (res != 0) {
		return res;
	}
	res = uv_ip4_addr(upstream_addr, upstream_port, (struct sockaddr_in *)&proxy->upstream_addr);
	if (res != 0) {
		return res;
	}
	array_init(proxy->buffer_pool);
	array_init(proxy->upstream_pending);
	proxy->server_state = STATE_NOT_CONNECTED;
	proxy->client_state = STATE_NOT_CONNECTED;
	proxy->upstream_state = STATE_NOT_CONNECTED;

	proxy->loop->data = proxy;
	return 0;
}

void proxy_free(struct proxy_ctx *proxy)
{
	if (!proxy) {
		return;
	}
	clear_upstream_pending(proxy);
	clear_buffer_pool(proxy);
	/* TODO correctly close all the uv_tcp_t */
	free(proxy);
}

int proxy_start_listen(struct proxy_ctx *proxy)
{	
	uv_tcp_bind(&proxy->server, (const struct sockaddr*)&proxy->server_addr, 0);
	int ret = uv_listen((uv_stream_t*)&proxy->server, 128, on_client_connection);
	if (ret == 0) {
		proxy->server_state = STATE_LISTENING;
	}
	return ret;
}

int proxy_run(struct proxy_ctx *proxy)
{
	return uv_run(proxy->loop, UV_RUN_DEFAULT);
}
