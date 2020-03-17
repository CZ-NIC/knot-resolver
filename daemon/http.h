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

//enum http_method {
//     NONE = 0,
//     GET,
//     POST,
//     UNKNOWN
//};

//enum http_state {
//     REQUEST = 0,
//     RESPONSE,
//     DONE
//};

typedef ssize_t(*http_send_callback)(uint8_t *buffer, size_t buffer_len, void *user_ctx);

struct http_ctx_t {
     struct nghttp2_session *session;
     http_send_callback send_cb;
     void *user_ctx;
     int32_t request_stream_id;
     uint8_t *wire;
     int32_t wire_len;

     //enum http_state state;
     //enum http_method method;
};

struct http_ctx_t* http_new(struct worker_ctx* worker, http_send_callback cb, void *user_ctx);

ssize_t http_process_input_data(struct session *s, const uint8_t *buf, ssize_t nread);
int http_send_server_connection_header(struct session *s);
//int http_pack(uv_write_t *req, uv_handle_t* handle, knot_pkt_t * pkt);
int32_t http_pack(struct session *ctx, knot_pkt_t * pkt);
void http_clear(struct http_ctx_t *ctx);
void http_close(struct http_ctx_t *ctx);