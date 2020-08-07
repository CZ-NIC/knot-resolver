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

#define HTTP_MAX_CONCURRENT_STREAMS 1

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
			beg += sizeof(key) - 1;
			char *end = strchrnul(beg, '&');
			ctx->wire_len = kr_base64url_decode((uint8_t*)beg, end - beg, ctx->wire + sizeof(uint16_t), ctx->wire_len - sizeof(uint16_t));
			ctx->request_stream_id = frame->hd.stream_id;
		}
	}
	return 0;
}

static int query_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
	struct http_ctx_t *ctx = (struct http_ctx_t *)user_data;
	memcpy(ctx->wire + sizeof(uint16_t), data, len);
	ctx->wire_len = len;
	ctx->request_stream_id = stream_id;
	return 0;
}

struct http_ctx_t* http_new(http_send_callback cb, void *user_ctx)
{
	assert(cb != NULL);

	nghttp2_session_callbacks *callbacks;
	nghttp2_session_callbacks_new(&callbacks);
	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, header_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, query_recv_callback);

	struct http_ctx_t *ctx = calloc(1UL, sizeof(struct http_ctx_t));
	ctx->send_cb = cb;
	ctx->user_ctx = user_ctx;
	ctx->request_stream_id = -1;

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

	http_p->wire = session_wirebuf_get_free_start(s);
	http_p->wire_len = session_wirebuf_get_free_size(s);
	ssize_t ret = 0;
	if ((ret = nghttp2_session_mem_recv(http_p->session, in_buf, in_buf_len)) < 0) {
		kr_log_error("[%s] nghttp2_session_mem_recv failed: %s (%zd)\n", server_logstring, nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	if ((ret = nghttp2_session_send(http_p->session)) < 0) {
		kr_log_error("[%s] nghttp2_session_send failed: %s (%zd)\n", server_logstring, nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	ssize_t submitted = 0;
	if (http_p->request_stream_id >= 0) {
		knot_wire_write_u16(http_p->wire, http_p->wire_len);
		submitted = http_p->wire_len + sizeof(uint16_t);
	}

	return submitted;
}

static ssize_t send_response_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
	struct http_data_buffer *buffer = (struct http_data_buffer *)source->ptr;
	struct http_ctx_t *ctx = (struct http_ctx_t *)user_data; //TODO remove maybe
	size_t send = MIN(buffer->end - buffer->data, length);
	memcpy(buf, buffer->data, send);
	buffer->data += send;
	//*data_flags |= (buffer->data == buffer->end) ? NGHTTP2_DATA_FLAG_EOF : 0;
	if (buffer->data == buffer->end) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
		ctx->request_stream_id = -1;
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
	nghttp2_session_del(ctx->session);
	ctx->session = NULL;
}
