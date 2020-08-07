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
	const uint8_t *end;
};

static char const server_logstring[] = "http";

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
	struct http_ctx_t *ctx = (struct http_ctx_t *)user_data;
	return ctx->send_cb(data, length, ctx->user_ctx);
}

static int header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
	//TODO some validation.. When POST, no DNS variable in path...
	//In knot we parse path using some static lib, think of use it too but not necessary
	static const char key[] = "dns=";
	struct http_ctx_t *ctx = (struct http_ctx_t *)user_data;
	if (!strcasecmp(":path", (const char *)name)) {
		char *beg = strstr((const char *)value, key);
		if (beg) {
			// TODO check we're not interefing with incomplete stream
			beg += sizeof(key) - 1;
			char *end = strchrnul(beg, '&');
			ctx->wire_len = kr_base64url_decode((uint8_t*)beg, end - beg, ctx->wire + sizeof(uint16_t), ctx->wire_len - sizeof(uint16_t));
			queue_push(ctx->streams, frame->hd.stream_id);
		}
	}
	return 0;
}

/* This method is called for data received via POST. */
static int data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
	struct http_ctx_t *ctx = (struct http_ctx_t *)user_data;

	if (ctx->incomplete_stream && queue_len(ctx->streams) > 0 && queue_tail(ctx->streams) != stream_id) {
		/* If the received DATA chunk is from a different stream
		 * than the one being currently handled, ignore it and refuse
		 * the stream. */
		kr_log_verbose("[doh2] resetting http stream due to incomplete data\n");
		nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_REFUSED_STREAM);
		return 0;
	}

	// TODO is there enough space in the wire buffer?
	if (!ctx->incomplete_stream) {
		ctx->incomplete_stream = true;
		queue_push(ctx->streams, stream_id);

		ctx->wire += sizeof(uint16_t);
		ctx->wire_len = 0;
	}
	memcpy(ctx->wire + ctx->wire_len, data, len);
	ctx->wire_len += len;

	return 0;
}

static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
	struct http_ctx_t *ctx = (struct http_ctx_t *)user_data;

	if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM && ctx->incomplete_stream) {
		ctx->incomplete_stream = false;

		knot_wire_write_u16(ctx->wire - sizeof(uint16_t), ctx->wire_len);  // TODO wire_len can be overflow when negative  int32_t
		ctx->submitted += ctx->wire_len + sizeof(uint16_t);
		ctx->wire += ctx->wire_len;
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
	http_p->wire_start_idx = session_wirebuf_get_free_start(s);
	http_p->wire = http_p->wire_start_idx;
	// http_p->wire_len = session_wirebuf_get_free_size(s);  // TODO initialize this for GET
	ssize_t ret = 0;
	if ((ret = nghttp2_session_mem_recv(http_p->session, in_buf, in_buf_len)) < 0) {
		kr_log_error("[%s] nghttp2_session_mem_recv failed: %s (%zd)\n", server_logstring, nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	if ((ret = nghttp2_session_send(http_p->session)) < 0) {
		kr_log_error("[%s] nghttp2_session_send failed: %s (%zd)\n", server_logstring, nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	return http_p->submitted;
}

static ssize_t send_response_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
	struct http_data_buffer *buffer = (struct http_data_buffer *)source->ptr;
	size_t send = MIN(buffer->end - buffer->data, length);
	memcpy(buf, buffer->data, send);
	buffer->data += send;
	//*data_flags |= (buffer->data == buffer->end) ? NGHTTP2_DATA_FLAG_EOF : 0;
	if (buffer->data == buffer->end) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
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
	int size_len = sprintf(size, "%ld", pkt->size);

	struct http_data_buffer data_buff = {
		.data = pkt->wire,
		.end = pkt->wire + pkt->size
	};

	const nghttp2_data_provider data_prd = {
		.source = {
			.ptr = &data_buff
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
		kr_log_error("[%s] nghttp2_submit_response failed: %s (%d)\n", server_logstring, nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	if((ret = nghttp2_session_send(http_ctx->session)) < 0) {
		kr_log_error("[%s] nghttp2_session_send failed: %s (%d)\n", server_logstring, nghttp2_strerror(ret), ret);
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
