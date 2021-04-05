/*
 * Copyright (C) 2020 CZ.NIC, z.s.p.o
 *
 * Initial Author: Jan Hák <jan.hak@nic.cz>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <uv.h>
#include <libknot/packet/pkt.h>

#if ENABLE_DOH2
#include <nghttp2/nghttp2.h>
#endif

#include "lib/generic/queue.h"

/** Transport session (opaque). */
struct session;

typedef ssize_t(*http_send_callback)(const uint8_t *buffer,
				     const size_t buffer_len,
				     struct session *session);

struct http_stream {
	int32_t id;
	kr_http_header_array_t *headers;
};

typedef queue_t(struct http_stream) queue_http_stream;

typedef enum {
	HTTP_METHOD_NONE = 0,
	HTTP_METHOD_GET = 1,
	HTTP_METHOD_POST = 2,
} http_method_t;

struct http_ctx {
	struct nghttp2_session *h2;
	http_send_callback send_cb;
	struct session *session;
	queue_http_stream streams;  /* Streams present in the wire buffer. */
	int32_t incomplete_stream;
	ssize_t submitted;
	http_method_t current_method;
	char *uri_path;
	kr_http_header_array_t *headers;
	uint8_t *buf;  /* Part of the wire_buf that belongs to current HTTP/2 stream. */
	ssize_t buf_pos;
	ssize_t buf_size;
};

#if ENABLE_DOH2
struct http_ctx* http_new(struct session *session, http_send_callback send_cb);
ssize_t http_process_input_data(struct session *session, const uint8_t *buf, ssize_t nread);
int http_write(uv_write_t *req, uv_handle_t *handle, knot_pkt_t* pkt, int32_t stream_id,
	       uv_write_cb on_write);
void http_free(struct http_ctx *ctx);
#endif
