/*
 * Copyright (C) 2020 CZ.NIC, z.s.p.o
 *
 * Initial Author: Jan Hák <jan.hak@nic.cz>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <nghttp2/nghttp2.h>
#include <uv.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon/io.h"
#include "daemon/http.h"
#include "daemon/worker.h"
#include "daemon/session.h"

#include "contrib/base64url.h"

#define MAKE_NV(K, KS, V, VS) \
	{ (uint8_t *)K, (uint8_t *)V, KS, VS, NGHTTP2_NV_FLAG_NONE }

#define MAKE_STATIC_NV(K, V) \
	MAKE_NV(K, sizeof(K) - 1, V, sizeof(V) - 1)

/* Use same maximum as for tcp_pipeline_max. */
#define HTTP_MAX_CONCURRENT_STREAMS UINT16_MAX

#define MAX_DECIMAL_LENGTH(VT) (CHAR_BIT * sizeof(VT) / 3) + 3

struct http_data_buffer {
	uint8_t *data;
	size_t len;
	size_t pos;
};

/*
 * Write HTTP/2 data to underlying transport layer.
 */
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length,
			     int flags, void *user_data)
{
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	return ctx->send_cb(data, length, ctx->user_ctx);
}

/*
 * Process a query from URI path if there's base64url encoded dns variable.
 */
static int process_uri_path(struct http_ctx *ctx, const char* path, int32_t stream_id)
{
	if (!ctx || !path)
		return kr_error(EINVAL);

	static const char key[] = "dns=";
	char *beg = strstr((const char *)path, key);
	char *end;
	size_t remaining;
	ssize_t ret;
	uint8_t *dest;

	if (!beg)  /* No dns variable in path. */
		return 0;

	beg += sizeof(key) - 1;
	end = strchrnul(beg, '&');
	ctx->buf_pos = sizeof(uint16_t);  /* Reserve 2B for dnsmsg len. */
	remaining = ctx->buf_size - ctx->submitted - ctx->buf_pos;
	dest = ctx->buf + ctx->buf_pos;

	ret = kr_base64url_decode((uint8_t*)beg, end - beg, dest, remaining);
	if (ret < 0) {
		ctx->buf_pos = 0;
		kr_log_verbose("[http] base64url decode failed %s\n",
			       strerror(ret));
		return ret;
	}

	ctx->buf_pos += ret;
	queue_push(ctx->streams, stream_id);
	return 0;
}

static void refuse_stream(nghttp2_session *session, int32_t stream_id)
{
	nghttp2_submit_rst_stream(
		session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_REFUSED_STREAM);
}

static int header_callback(nghttp2_session *session, const nghttp2_frame *frame,
			   const uint8_t *name, size_t namelen, const uint8_t *value,
			   size_t valuelen, uint8_t flags, void *user_data)
{
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	int32_t stream_id = frame->hd.stream_id;

	/* If the HEADERS don't have END_STREAM set, there are some DATA frames,
	 * which implies POST method.  Skip header processing for POST. */
	if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == 0)
		return 0;

	/* If there is incomplete data in the buffer, we can't process the new stream. */
	if (ctx->incomplete_stream) {
		kr_log_verbose("[http] previous stream incomplete, refusing\n");
		refuse_stream(session, stream_id);
		return 0;
	}

	if (!strcasecmp(":path", (const char *)name)) {
		if (process_uri_path(ctx, (const char*)value, stream_id) < 0)
			refuse_stream(session, stream_id);
	}
	return 0;
}

/*
 * Process DATA chunk sent by the client (by POST method).
 *
 * We use a single DNS message buffer for the entire connection. Therefore, we
 * don't support interweaving DATA chunks from different streams. To successfully
 * parse multiple subsequent streams, each one must be fully received before
 * processing a new stream.
 */
static int data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
				    const uint8_t *data, size_t len, void *user_data)
{
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	ssize_t remaining;
	ssize_t required;

	if (ctx->incomplete_stream) {
		if (queue_len(ctx->streams) <= 0) {
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		} else if (queue_tail(ctx->streams) != stream_id) {
			kr_log_verbose("[http] previous stream incomplete, refusing\n");
			refuse_stream(session, stream_id);
			return 0;
		}
	}

	remaining = ctx->buf_size - ctx->submitted - ctx->buf_pos;
	required = len + sizeof(uint16_t);
	if (required > remaining) {
		kr_log_error("[http] insufficient space in buffer\n");
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	if (!ctx->incomplete_stream) {
		ctx->incomplete_stream = true;
		ctx->buf_pos = sizeof(uint16_t);  /* Reserve 2B for dnsmsg len. */
		queue_push(ctx->streams, stream_id);
	}

	memcpy(ctx->buf + ctx->buf_pos, data, len);
	ctx->buf_pos += len;
	return 0;
}

/*
 * Finalize existing buffer upon receiving the last frame in the stream.
 *
 * For GET, this would be HEADERS frame.
 * For POST, it is a DATA frame.
 *
 * Unrelated frames (such as SETTINGS) are ignored (no data was buffered).
 */
static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	ssize_t len;

	if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) && ctx->buf_pos != 0) {
		ctx->incomplete_stream = false;

		len = ctx->buf_pos - sizeof(uint16_t);
		if (len <= 0 || len > KNOT_WIRE_MAX_PKTSIZE) {
			kr_log_verbose("[http] invalid dnsmsg size: %zd B\n", len);
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}

		knot_wire_write_u16(ctx->buf, len);
		ctx->submitted += ctx->buf_pos;
		ctx->buf += ctx->buf_pos;
		ctx->buf_pos = 0;
	}

	return 0;
}

/*
 * Setup and initialize connection with new HTTP/2 context.
 */
struct http_ctx* http_new(http_send_callback cb, void *user_ctx)
{
	assert(cb != NULL);

	nghttp2_session_callbacks *callbacks;
	struct http_ctx *ctx;
	static const nghttp2_settings_entry iv[] = {
		{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, HTTP_MAX_CONCURRENT_STREAMS }
	};

	nghttp2_session_callbacks_new(&callbacks);
	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, header_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
		callbacks, data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(
		callbacks, on_frame_recv_callback);

	ctx = calloc(1UL, sizeof(struct http_ctx));
	ctx->send_cb = cb;
	ctx->user_ctx = user_ctx;
	queue_init(ctx->streams);
	ctx->incomplete_stream = false;
	ctx->submitted = 0;

	nghttp2_session_server_new(&ctx->session, callbacks, ctx);
	nghttp2_session_callbacks_del(callbacks);

	nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE,
		iv, sizeof(iv)/sizeof(*iv));

	return ctx;
}

/*
 * Process inbound HTTP/2 data and return number of bytes read into session wire buffer.
 *
 * This function may trigger outgoing HTTP/2 data, such as stream resets, window updates etc.
 */
ssize_t http_process_input_data(struct session *s, const uint8_t *in_buf, ssize_t in_buf_len)
{
	struct http_ctx *ctx = session_http_get_server_ctx(s);
	ssize_t ret = 0;

	if (!ctx->session)  // TODO session vs h2; assert session equals
		return kr_error(ENOSYS);

	ctx->submitted = 0;
	ctx->buf = session_wirebuf_get_free_start(s);
	ctx->buf_pos = 0;
	ctx->buf_size = session_wirebuf_get_free_size(s);

	ret = nghttp2_session_mem_recv(ctx->session, in_buf, in_buf_len);
	if (ret < 0) {
		kr_log_error("[http] nghttp2_session_mem_recv failed: %s (%zd)\n",
			     nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	ret = nghttp2_session_send(ctx->session);
	if (ret < 0) {
		kr_log_error("[http] nghttp2_session_send failed: %s (%zd)\n",
			     nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	return ctx->submitted;
}

/*
 *
 */
static ssize_t send_response_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf,
				      size_t length, uint32_t *data_flags,
				      nghttp2_data_source *source, void *user_data)
{
	struct http_data_buffer *buffer = (struct http_data_buffer *)source->ptr;
	assert(buffer != NULL);
	size_t send = MIN(buffer->len - buffer->pos, length);
	memcpy(buf, buffer->data + buffer->pos, send);
	buffer->pos += send;

	if (buffer->pos == buffer->len) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
		free(buffer->data);
		free(buffer);
		source->ptr = NULL;
	}

	return send;
}

int http_write(uv_write_t *req, uv_handle_t *handle, int32_t stream_id, knot_pkt_t *pkt, uv_write_cb cb)
{
	if (!pkt || !handle || !handle->data || stream_id < 0) {
		return kr_error(EINVAL);
	}

	struct session *s = handle->data;
	struct http_ctx *http_ctx = session_http_get_server_ctx(s);

	assert (http_ctx);
	assert (!session_flags(s)->outgoing);

	char size[MAX_DECIMAL_LENGTH(pkt->size)] = { 0 };
	int size_len = snprintf(size, MAX_DECIMAL_LENGTH(pkt->size), "%ld", pkt->size);

	/* Copy the packet data into a separate buffer, because nghttp2_session_send()
	 * isn't guaranteed to process the data immediately. */
	uint8_t *buf = malloc(pkt->size);
	memcpy(buf, pkt->wire, pkt->size);

	struct http_data_buffer *data_buff = malloc(sizeof(struct http_data_buffer));
	data_buff->data = buf;
	data_buff->len = pkt->size;
	data_buff->pos = 0;

	const nghttp2_data_provider data_prd = {
		.source = {
			.ptr = data_buff
		},
		.read_callback = send_response_callback
	};

	nghttp2_nv hdrs[] = {
		MAKE_STATIC_NV(":status", "200"),
		MAKE_STATIC_NV("content-type", "application/dns-message"),
		MAKE_NV("content-length", 14, size, size_len)
	};

	int ret = nghttp2_submit_response(http_ctx->session, stream_id, hdrs, sizeof(hdrs)/sizeof(*hdrs), &data_prd);
	if (ret != 0) {
		kr_log_error("[http] nghttp2_submit_response failed: %s (%d)\n", nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	if((ret = nghttp2_session_send(http_ctx->session)) < 0) {
		kr_log_error("[http] nghttp2_session_send failed: %s (%d)\n", nghttp2_strerror(ret), ret);
 		return kr_error(EIO);
	}

	/* The data is now accepted in gnutls internal buffers, the message can be treated as sent */
	req->handle = (uv_stream_t *)handle;
	cb(req, 0);

	return kr_ok();
}

/*
 * Release HTTP/2 context.
 */
void http_free(struct http_ctx *ctx)
{
	if (!ctx)
		return;

	queue_deinit(ctx->streams);
	nghttp2_session_del(ctx->session);
	free(ctx);
}
