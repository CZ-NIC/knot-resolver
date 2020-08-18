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

typedef ssize_t(*http_send_callback)(const uint8_t *buffer,
				     const size_t buffer_len,
				     struct session *session);

typedef queue_t(int32_t) queue_int32_t;

struct http_ctx {
	struct nghttp2_session *h2;
	http_send_callback send_cb;
	struct session *session;
	queue_int32_t streams;  /* IDs of streams present in the buffer. */
	bool incomplete_stream;
	ssize_t submitted;
	uint8_t *buf;  /* Part of the wire_buf that belongs to current HTTP/2 stream. */
	ssize_t buf_pos;
	ssize_t buf_size;
};

struct http_ctx* http_new(struct session *session, http_send_callback send_cb);
ssize_t http_process_input_data(struct session *session, const uint8_t *buf, ssize_t nread);
int http_write(uv_write_t *req, uv_handle_t *handle, int32_t stream_id, uv_write_cb on_write);
void http_free(struct http_ctx *ctx);
