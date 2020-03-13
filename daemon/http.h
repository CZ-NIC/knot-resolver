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

/** Transport session (opaque). */
struct session;

typedef ssize_t(*http_send_callback)(const uint8_t *buffer, const size_t buffer_len, void *user_ctx);

struct http_ctx_t {
     struct nghttp2_session *session;
     http_send_callback send_cb;
     void *user_ctx;
     int32_t request_stream_id;
     uint8_t *wire;
     int32_t wire_len;
};

struct http_ctx_t* http_new(http_send_callback cb, void *user_ctx);
ssize_t http_process_input_data(struct session *s, const uint8_t *buf, ssize_t nread);
int32_t http_pack(struct session *ctx, knot_pkt_t *pkt);
void http_free(struct http_ctx_t *ctx);