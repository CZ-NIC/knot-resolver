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
#include "lib/generic/trie.h"

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
	HTTP_METHOD_HEAD = 3, /**< Same as GET, except it does not return payload.
			       * Required to be implemented by RFC 7231. */
} http_method_t;

/** HTTP status codes returned by kresd.
 * This is obviously non-exhaustive of all HTTP status codes, feel free to add
 * more if needed. */
enum http_status {
	HTTP_STATUS_OK                              = 200,
	HTTP_STATUS_BAD_REQUEST                     = 400,
	HTTP_STATUS_NOT_FOUND                       = 404,
	HTTP_STATUS_PAYLOAD_TOO_LARGE               = 413,
	HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE          = 415,
	HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
	HTTP_STATUS_NOT_IMPLEMENTED                 = 501,
};

struct http_ctx {
	struct nghttp2_session *h2;
	http_send_callback send_cb;
	struct session *session;
	queue_http_stream streams;  /* Streams present in the wire buffer. */
	trie_t *stream_write_data;  /* Dictionary of stream data that needs to be freed after write. */
	int32_t incomplete_stream;
	int32_t last_stream;   /* The last used stream - mostly the same as incomplete_stream, but can be used after
				  completion for sending HTTP status codes. */
	ssize_t submitted;
	http_method_t current_method;
	char *uri_path;
	kr_http_header_array_t *headers;
	uint8_t *buf;  /* Part of the wire_buf that belongs to current HTTP/2 stream. */
	ssize_t buf_pos;
	ssize_t buf_size;
	enum http_status status;
	bool streaming;             /* True: not all data in the stream has been received yet. */
};

#if ENABLE_DOH2
struct http_ctx* http_new(struct session *session, http_send_callback send_cb);
int http_process_input_data(struct session *session, const uint8_t *buf, ssize_t nread,
			    ssize_t *out_submitted);
int http_send_status(struct session *session, enum http_status status);
int http_write(uv_write_t *req, uv_handle_t *handle, knot_pkt_t* pkt, int32_t stream_id,
	       uv_write_cb on_write);
void http_free(struct http_ctx *ctx);
void http_free_headers(kr_http_header_array_t *headers);

/** Checks if `status` has the correct `category`.
 * E.g. status 200 has category 2, status 404 has category 4, 501 has category 5 etc. */
static inline bool http_status_has_category(enum http_status status, int category)
{
	return status / 100 == category;
}
#endif
