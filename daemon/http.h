/*
 * Copyright (C) 2020 CZ.NIC, z.s.p.o
 *
 * Initial Author: Jan Hák <jan.hak@nic.cz>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <uv.h>
#include <nghttp2/nghttp2.h>
#include <libknot/packet/pkt.h>

#include "lib/generic/queue.h"

/** Transport session (opaque). */
struct session;

typedef ssize_t(*http_send_callback)(const uint8_t *buffer, const size_t buffer_len, void *user_ctx);

typedef queue_t(int32_t) queue_int32_t;

struct http_ctx {
	struct nghttp2_session *session;
	http_send_callback send_cb;
	void *user_ctx;
	queue_int32_t streams;  /* List of stream IDs of read HTTP/2 frames. */
	bool incomplete_stream;
	ssize_t submitted;
	uint8_t *buf;  /* Part of the session->wire_buf that belongs to current HTTP/2 stream. */
	ssize_t buf_pos;
	ssize_t buf_size;
};

struct http_ctx* http_new(http_send_callback cb, void *user_ctx);
ssize_t http_process_input_data(struct session *s, const uint8_t *buf, ssize_t nread);
int http_write(uv_write_t *req, uv_handle_t *handle, int32_t stream_id, knot_pkt_t *pkt, uv_write_cb cb);
void http_free(struct http_ctx *ctx);
