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

static char const server_logstring[] = "http";

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
	return 0;
}

static int header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
	//TODO some validation.. When POST, no DNS variable in path...
	//In knot we parse path using some static lib, think of use it too but not necessary
	static const uint8_t key[] = "dns=";
	struct http_ctx_t *ctx = (struct http_ctx_t *)user_data;
	if (!strcasecmp(":path", (char *)name)) {
		uint8_t *beg = strstr(value, key);
		if (beg) {
			beg += sizeof(key) - 1;
			uint8_t *end = strchrnul(beg, '&');
			ctx->wire_len = kr_base64url_decode(beg, end - beg, ctx->wire + sizeof(uint16_t), ctx->wire_len - sizeof(uint16_t));
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
		{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}
	};

	nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, iv, sizeof(iv)/sizeof(*iv) );

	return ctx;
}

int http_send_server_connection_header(struct session *s)
{
	nghttp2_settings_entry iv[] = {
		{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}
	};

	int ret = nghttp2_submit_settings(session_http_get_server_ctx(s)->session, NGHTTP2_FLAG_NONE, iv, sizeof(iv)/sizeof(*iv) );
	if (ret != 0) {
		kr_log_error("[%s] nghttp2_submit_settings failed: %s (%zd)\n", server_logstring, nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}
	return 0;
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

	uint8_t *wire_buf = NULL;
	ssize_t len = 0;
	while ((len = nghttp2_session_mem_send(http_p->session, &wire_buf)) > 0) {
		if ((ret = http_p->send_cb(wire_buf, len, http_p->user_ctx)) < 0) {
			kr_log_error("[%s] send callback failed: %s (%zd)\n", server_logstring, nghttp2_strerror(ret), ret);
			return kr_error(EIO);
		}
	}

	ssize_t submitted = 0;
	if (http_p->request_stream_id >= 0) {
		knot_wire_write_u16(http_p->wire, http_p->wire_len);
		submitted = http_p->wire_len + sizeof(uint16_t);
	}

	return submitted;
}

static ssize_t read_data_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
	//TODO Larger messages than 'length' not tested.
	//     From documentation of nghttp2 i have no clue how does it work
	uint8_t *src = ((knot_pkt_t *)source->ptr)->wire;
	size_t src_len = ((knot_pkt_t *)source->ptr)->size;
	size_t send = MIN(src_len, length);
	memcpy(buf, src, send);
	*data_flags |= (src_len == send) ? NGHTTP2_DATA_FLAG_EOF : 0;
	return send;
}

int32_t http_pack(struct session *ctx, knot_pkt_t *pkt)
{
	char size[6] = { 0 };
	int size_len = sprintf(size, "%ld", pkt->size);
	struct http_ctx_t *http_ctx = session_http_get_server_ctx(ctx);

	const nghttp2_data_provider data_prd = {
		.source = {
			.ptr = pkt
		},
		.read_callback = read_data_callback
	};

	nghttp2_nv hdrs[] = {
		MAKE_STATIC_NV(":status", "200"),
		MAKE_STATIC_NV("content-type", "application/dns-message"),
		MAKE_NV("content-length", 14, size, size_len)
	};

	ssize_t ret = nghttp2_submit_response(http_ctx->session, http_ctx->request_stream_id, hdrs, sizeof(hdrs)/sizeof(*hdrs), &data_prd);
	if (ret != 0) {
		kr_log_error("[%s] nghttp2_submit_response failed: %s (%zd)\n", server_logstring, nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	//TODO right now it send response (by its own), should be passed to `qr_task_send`
	uint8_t *data = NULL;
	ssize_t send = 0;
	while ((send = nghttp2_session_mem_send(http_ctx->session, &data)) > 0) {
		if ((ret = http_ctx->send_cb(data, send, http_ctx->user_ctx)) < 0) {
			kr_log_error("[%s] send callback failed: %s (%zd)\n", server_logstring, nghttp2_strerror(ret), ret);
			return kr_error(EIO);
		}
	}

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