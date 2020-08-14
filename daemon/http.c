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

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
	struct http_ctx_t *ctx = (struct http_ctx_t *)user_data;
	return ctx->send_cb(data, length, ctx->user_ctx);
}

static int header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
	struct http_ctx_t *ctx = (struct http_ctx_t *)user_data;
	static const char key[] = "dns=";
	int32_t stream_id = frame->hd.stream_id;

	/* If the HEADERS don't have END_STREAM set, there are some DATA frames,
	 * which implies POST method.  Skip header processing for POST. */
	if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == 0) {
		return 0;
	}

	/* If there is incomplete data in the buffer, we can't process the new stream. */
	if (ctx->incomplete_stream) {
		kr_log_verbose("[http] refusing new http stream due to incomplete data from other stream\n");
		nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_REFUSED_STREAM);
		return 0;
	}

	if (!strcasecmp(":path", (const char *)name)) {
		char *beg = strstr((const char *)value, key);
		if (beg) {
			beg += sizeof(key) - 1;
			char *end = strchrnul(beg, '&');
			ctx->buf_pos = sizeof(uint16_t);
			ssize_t remaining = ctx->buf_size - ctx->submitted - ctx->buf_pos;
			uint8_t* dest = ctx->buf + ctx->buf_pos;
			ssize_t ret = kr_base64url_decode((uint8_t*)beg, end - beg, dest, remaining);
			if (ret < 0) {
				ctx->buf_pos = 0;
				nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_REFUSED_STREAM);
				kr_log_verbose("[http] refusing GET request, insufficient buffer size\n");
				return 0;
			}
			ctx->buf_pos += ret;
			queue_push(ctx->streams, stream_id);
		}
	}
	return 0;
}

/* This method is called for data received via POST. */
static int data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
	struct http_ctx_t *ctx = (struct http_ctx_t *)user_data;

	if (ctx->incomplete_stream) {
		if (queue_len(ctx->streams) <= 0) {
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		} else if (queue_tail(ctx->streams) != stream_id) {
			/* If the received DATA chunk is from a new stream and the previous
			 * one still has unfinished DATA, refuse the new stream. */
			kr_log_verbose("[http] refusing http DATA chunk, other stream has incomplete DATA\n");
			nghttp2_submit_rst_stream(
				session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_REFUSED_STREAM);
			return 0;
		}
	}

	/* Check message and its length can still fit into the wire buffer. */
	ssize_t remaining = ctx->buf_size - ctx->submitted - ctx->buf_pos;
	ssize_t required = len + sizeof(uint16_t);
	if (required > remaining) {
		kr_log_error(
			"[http] insufficient space in buffer: remaining %zd B, required %zd B\n",
			remaining, required);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	if (!ctx->incomplete_stream) {
		ctx->incomplete_stream = true;
		queue_push(ctx->streams, stream_id);

		/* 2B at the start of buffer is reserved for message length. */
		ctx->buf_pos = sizeof(uint16_t);
	}
	memcpy(ctx->buf + ctx->buf_pos, data, len);
	ctx->buf_pos += len;

	return 0;
}

static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
	struct http_ctx_t *ctx = (struct http_ctx_t *)user_data;

	if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) && ctx->buf_pos != 0) {
		ctx->incomplete_stream = false;

		ssize_t len = ctx->buf_pos - sizeof(uint16_t);
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

struct http_ctx_t* http_new(http_send_callback cb, void *user_ctx)
{
	assert(cb != NULL);

	nghttp2_session_callbacks *callbacks;
	nghttp2_session_callbacks_new(&callbacks);
	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, header_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);

	struct http_ctx_t *ctx = calloc(1UL, sizeof(struct http_ctx_t));
	ctx->send_cb = cb;
	ctx->user_ctx = user_ctx;
	queue_init(ctx->streams);
	ctx->incomplete_stream = false;
	ctx->submitted = 0;

	nghttp2_session_server_new(&ctx->session, callbacks, ctx);
	nghttp2_session_callbacks_del(callbacks);

	static const nghttp2_settings_entry iv[] = {
		{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, HTTP_MAX_CONCURRENT_STREAMS }
	};

	nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, iv, sizeof(iv)/sizeof(*iv) );

	return ctx;
}

ssize_t http_process_input_data(struct session *s, const uint8_t *in_buf, ssize_t in_buf_len)
{
	struct http_ctx_t *http_p = session_http_get_server_ctx(s);
	if (!http_p->session) {
		return kr_error(ENOSYS);
	}

	http_p->submitted = 0;
	http_p->buf = session_wirebuf_get_free_start(s);
	http_p->buf_pos = 0;
	http_p->buf_size = session_wirebuf_get_free_size(s);

	ssize_t ret = 0;
	if ((ret = nghttp2_session_mem_recv(http_p->session, in_buf, in_buf_len)) < 0) {
		kr_log_error("[http] nghttp2_session_mem_recv failed: %s (%zd)\n", nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	if ((ret = nghttp2_session_send(http_p->session)) < 0) {
		kr_log_error("[http] nghttp2_session_send failed: %s (%zd)\n", nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	return http_p->submitted;
}

static ssize_t send_response_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
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
	struct http_ctx_t *http_ctx = session_http_get_server_ctx(s);

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

void http_free(struct http_ctx_t *ctx)
{
	if (ctx == NULL || ctx->session == NULL) {
		return;
	}
	queue_deinit(ctx->streams);
	nghttp2_session_del(ctx->session);
	ctx->session = NULL;
}
