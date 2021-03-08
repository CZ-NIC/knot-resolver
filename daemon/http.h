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

typedef queue_t(int32_t) queue_int32_t;

typedef enum {
	HTTP_METHOD_NONE = 0,
	HTTP_METHOD_GET = 1,
	HTTP_METHOD_POST = 2,
} http_method_t;

struct http_stream_status {
	int32_t stream_id;
	int err_status;
	char *err_msg;
};

struct http_ctx {
	struct nghttp2_session *h2;
	http_send_callback send_cb;
	struct session *session;
	queue_int32_t streams;  /* IDs of streams present in the buffer. */
	int32_t incomplete_stream;
	ssize_t submitted;
	http_method_t current_method;
	char *uri_path;
	char *content_type;
	uint8_t *buf;  /* Part of the wire_buf that belongs to current HTTP/2 stream. */
	ssize_t buf_pos;
	ssize_t buf_size;
	trie_t *stream_status;
	struct http_stream_status *current_stream;
};

#if ENABLE_DOH2
struct http_ctx* http_new(struct session *session, http_send_callback send_cb);
ssize_t http_process_input_data(struct session *session, const uint8_t *buf, ssize_t nread);
int http_write(uv_write_t *req, uv_handle_t *handle, knot_pkt_t* pkt, int32_t stream_id,
	       uv_write_cb on_write);
void http_free(struct http_ctx *ctx);
#endif
