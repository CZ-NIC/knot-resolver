/*
 *
 * Copyright (C) 2020 CZ.NIC, z.s.p.o
 *
 * Initial Author: Jan Hák <jan.hak@nic.cz>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon/io.h"
#include "daemon/http.h"
#include "daemon/worker.h"
#include "daemon/session.h"
#include "lib/layer/iterate.h" /* kr_response_classify */
#include "lib/cache/util.h"
#include "lib/generic/array.h"

#include "contrib/cleanup.h"
#include "contrib/base64url.h"

/** Makes a `nghttp2_nv`. `K` is the key, `KS` is the key length,
 * `V` is the value, `VS` is the value length. */
#define MAKE_NV(K, KS, V, VS) \
	(nghttp2_nv) { (uint8_t *)(K), (uint8_t *)(V), (KS), (VS), NGHTTP2_NV_FLAG_NONE }

/** Makes a `nghttp2_nv` with static data. `K` is the key,
 * `V` is the value. Both `K` and `V` MUST be string literals. */
#define MAKE_STATIC_NV(K, V) \
	MAKE_NV((K), sizeof(K) - 1, (V), sizeof(V) - 1)

/** Makes a `nghttp2_nv` with a static key. `K` is the key,
 * `V` is the value, `VS` is the value length. `K` MUST be a string literal. */
#define MAKE_STATIC_KEY_NV(K, V, VS) \
	MAKE_NV((K), sizeof(K) - 1, (V), (VS))

/* Use same maximum as for tcp_pipeline_max. */
#define HTTP_MAX_CONCURRENT_STREAMS UINT16_MAX

#define HTTP_MAX_HEADER_IN_SIZE 1024

#define HTTP_FRAME_HDLEN 9
#define HTTP_FRAME_PADLEN 1

#define MAX_DECIMAL_LENGTH(VT) ((CHAR_BIT * sizeof(VT) / 3) + 3)

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

struct http_data {
	uint8_t *buf;
	size_t len;
	size_t pos;
	uint32_t ttl;
	uv_write_cb on_write;
	uv_write_t *req;
};

typedef array_t(nghttp2_nv) nghttp2_array_t;

static int http_send_response(struct http_ctx *ctx, int32_t stream_id,
			      nghttp2_data_provider *prov, enum http_status status);
static int http_send_response_rst_stream(struct http_ctx *ctx, int32_t stream_id,
			      nghttp2_data_provider *prov, enum http_status status);

/*
 * Write HTTP/2 protocol data to underlying transport layer.
 */
static ssize_t send_callback(nghttp2_session *h2, const uint8_t *data, size_t length,
			     int flags, void *user_data)
{
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	return ctx->send_cb(data, length, ctx->session);
}

/*
 * Send padding length (if greater than zero).
 */
static int send_padlen(struct http_ctx *ctx, size_t padlen)
{
	int ret;
	uint8_t buf;

	if (padlen == 0)
		return 0;

	buf = (uint8_t)padlen;
	ret = ctx->send_cb(&buf, HTTP_FRAME_PADLEN, ctx->session);
	if (ret < 0)
		return NGHTTP2_ERR_CALLBACK_FAILURE;

	return 0;
}

/*
 * Send HTTP/2 zero-byte padding.
 *
 * This sends only padlen-1 bytes of padding (if any), since padlen itself
 * (already sent) is also considered padding. Refer to RFC7540, section 6.1
 */
static int send_padding(struct http_ctx *ctx, uint8_t padlen)
{
	static const uint8_t buf[UINT8_MAX];
	int ret;

	if (padlen <= 1)
		return 0;

	ret = ctx->send_cb(buf, padlen - 1, ctx->session);
	if (ret < 0)
		return NGHTTP2_ERR_CALLBACK_FAILURE;

	return 0;
}

/*
 * Write entire DATA frame to underlying transport layer.
 *
 * This function reads directly from data provider to avoid copying packet wire buffer.
 */
static int send_data_callback(nghttp2_session *h2, nghttp2_frame *frame, const uint8_t *framehd,
			      size_t length, nghttp2_data_source *source, void *user_data)
{
	struct http_data *data;
	int ret;
	struct http_ctx *ctx;

	ctx = (struct http_ctx *)user_data;
	data = (struct http_data*)source->ptr;

	ret = ctx->send_cb(framehd, HTTP_FRAME_HDLEN, ctx->session);
	if (ret < 0)
		return NGHTTP2_ERR_CALLBACK_FAILURE;

	ret = send_padlen(ctx, frame->data.padlen);
	if (ret < 0)
		return NGHTTP2_ERR_CALLBACK_FAILURE;

	ret = ctx->send_cb(data->buf + data->pos, length, ctx->session);
	if (ret < 0)
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	data->pos += length;
	if (kr_fails_assert(data->pos <= data->len))
		return NGHTTP2_ERR_CALLBACK_FAILURE;

	ret = send_padding(ctx, (uint8_t)frame->data.padlen);
	if (ret < 0)
		return NGHTTP2_ERR_CALLBACK_FAILURE;

	return 0;
}

/*
 * Check endpoint and uri path
 */
static int check_uri(const char* uri_path)
{
	static const char key[] = "dns=";
	static const char *delim = "&";
	static const char *endpoints[] = {"dns-query", "doh"};
	char *beg;
	char *end_prev;
	ssize_t endpoint_len;
	ssize_t ret;

	if (!uri_path)
		return kr_error(EINVAL);

	auto_free char *path = malloc(sizeof(*path) * (strlen(uri_path) + 1));
	if (!path)
		return kr_error(ENOMEM);

	memcpy(path, uri_path, strlen(uri_path));
	path[strlen(uri_path)] = '\0';

	char *query_mark = strstr(path, "?");

	/* calculating of endpoint_len - for POST or GET method */
	endpoint_len = (query_mark) ? query_mark - path - 1 : strlen(path) - 1;

	/* check endpoint */
	ret = -1;
	for(int i = 0; i < sizeof(endpoints)/sizeof(*endpoints); i++)
	{
		if (strlen(endpoints[i]) != endpoint_len)
			continue;
		ret = strncmp(path + 1, endpoints[i], strlen(endpoints[i]));
		if (!ret)
			break;
	}

	if (ret) /* no endpoint found */
		return kr_error(ENOENT);

	/* FIXME This also passes for GET when no variables are provided.
	 * Fixing it doesn't seem straightforward, since :method may not be
	 * known by the time check_uri() is called... */
	if (endpoint_len == strlen(path) - 1) /* done for POST method */
		return 0;

	/* go over key:value pair */
	beg = strtok(query_mark + 1, delim);
	if (beg) {
		while (beg != NULL) {
			if (!strncmp(beg, key, 4)) { /* dns variable in path found */
				break;
			}
			end_prev = beg + strlen(beg);
			beg = strtok(NULL, delim);
			if (!beg || beg-1 != end_prev) { /* detect && */
				return -1;
			}
		}

		if (!beg) { /* no dns variable in path */
			return -1;
		}
	}

	return 0;
}

/*
 * Process a query from URI path if there's base64url encoded dns variable.
 */
static int process_uri_path(struct http_ctx *ctx, const char* path, int32_t stream_id)
{
	if (!ctx || !path)
		return kr_error(EINVAL);

	static const char key[] = "dns=";
	char *beg = strstr(path, key);
	char *end;
	size_t remaining;
	uint8_t *dest;

	if (!beg)  /* No dns variable in path. */
		return -1;

	beg += sizeof(key) - 1;
	end = strchr(beg, '&');
	if (end == NULL)
		end = beg + strlen(beg);

	ctx->buf_pos = sizeof(uint16_t);  /* Reserve 2B for dnsmsg len. */
	remaining = ctx->buf_size - ctx->submitted - ctx->buf_pos;
	dest = ctx->buf + ctx->buf_pos;

	int ret = kr_base64url_decode((uint8_t*)beg, end - beg, dest, remaining);
	if (ret < 0) {
		ctx->buf_pos = 0;
		kr_log_debug(DOH, "[%p] base64url decode failed %s\n", (void *)ctx->h2, kr_strerror(ret));
		return ret;
	}

	ctx->buf_pos += ret;

	struct http_stream stream = {
		.id = stream_id,
		.headers = ctx->headers
	};
	queue_push(ctx->streams, stream);
	return 0;
}

static void refuse_stream(nghttp2_session *h2, int32_t stream_id)
{
	nghttp2_submit_rst_stream(
		h2, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_REFUSED_STREAM);
}

void http_free_headers(kr_http_header_array_t *headers)
{
	if (headers == NULL)
		return;

	for (int i = 0; i < headers->len; i++) {
		free(headers->at[i].name);
		free(headers->at[i].value);
	}
	array_clear(*headers);
	free(headers);
}
/* Return the http ctx into a pristine state in which no stream is being processed. */
static void http_cleanup_stream(struct http_ctx *ctx)
{
	ctx->incomplete_stream = -1;
	ctx->current_method = HTTP_METHOD_NONE;
	free(ctx->uri_path);
	ctx->uri_path = NULL;
	http_free_headers(ctx->headers);
	ctx->headers = NULL;
}

/*
 * Save stream id from first header's frame.
 *
 * We don't support interweaving from different streams. To successfully parse
 * multiple subsequent streams, each one must be fully received before processing
 * a new stream.
 */
static int begin_headers_callback(nghttp2_session *h2, const nghttp2_frame *frame,
				 void *user_data)
{
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	int32_t stream_id = frame->hd.stream_id;

	if (frame->hd.type != NGHTTP2_HEADERS ||
		frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
		return 0;
	}

	if (ctx->incomplete_stream != -1) {
		kr_log_debug(DOH, "[%p] stream %d incomplete, refusing (begin_headers_callback)\n",
				(void *)h2, ctx->incomplete_stream);
		refuse_stream(h2, stream_id);
	} else {
		http_cleanup_stream(ctx);  // Free any leftover data and ensure pristine state
		ctx->incomplete_stream = stream_id;
		ctx->headers = malloc(sizeof(kr_http_header_array_t));
		array_init(*ctx->headers);
	}
	return 0;
}

/*
 * Process a received header name-value pair.
 *
 * In DoH, GET requests contain the base64url-encoded query in dns variable present in path.
 * This variable is parsed from :path pseudoheader.
 */
static int header_callback(nghttp2_session *h2, const nghttp2_frame *frame,
			   const uint8_t *name, size_t namelen, const uint8_t *value,
			   size_t valuelen, uint8_t flags, void *user_data)
{
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	int32_t stream_id = frame->hd.stream_id;

	if (frame->hd.type != NGHTTP2_HEADERS)
		return 0;

	if (ctx->incomplete_stream != stream_id) {
		kr_log_debug(DOH, "[%p] stream %d incomplete, refusing (header_callback)\n",
				(void *)h2, ctx->incomplete_stream);
		refuse_stream(h2, stream_id);
		return 0;
	}

	/* Store chosen headers to pass them to kr_request. */
	for (int i = 0; i < the_worker->doh_qry_headers.len; i++) {
		if (!strcasecmp(the_worker->doh_qry_headers.at[i], (const char *)name)) {
			kr_http_header_array_entry_t header;

			/* Limit maximum value size to reduce attack surface. */
			if (valuelen > HTTP_MAX_HEADER_IN_SIZE) {
				kr_log_debug(DOH,
					"[%p] stream %d: header too large (%zu B), refused\n",
					(void *)h2, stream_id, valuelen);
				return http_send_response_rst_stream(ctx, stream_id, NULL,
						HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE);
			}

			/* Copy the user-provided header name to keep the original case. */
			header.name = malloc(sizeof(*header.name) * (namelen + 1));
			memcpy(header.name, the_worker->doh_qry_headers.at[i], namelen);
			header.name[namelen] = '\0';

			header.value = malloc(sizeof(*header.value) * (valuelen + 1));
			memcpy(header.value, value, valuelen);
			header.value[valuelen] = '\0';

			array_push(*ctx->headers, header);
			break;
		}
	}

	if (!strcasecmp(":path", (const char *)name)) {
		int uri_result = check_uri((const char *)value);
		if (uri_result == kr_error(ENOENT)) {
			return http_send_response_rst_stream(ctx, stream_id, NULL,
					HTTP_STATUS_NOT_FOUND);
		} else if (uri_result < 0) {
			return http_send_response_rst_stream(ctx, stream_id, NULL,
					HTTP_STATUS_BAD_REQUEST);
		}

		kr_assert(ctx->uri_path == NULL);
		ctx->uri_path = malloc(sizeof(*ctx->uri_path) * (valuelen + 1));
		if (!ctx->uri_path)
			return kr_error(ENOMEM);
		memcpy(ctx->uri_path, value, valuelen);
		ctx->uri_path[valuelen] = '\0';
	}

	if (!strcasecmp(":method", (const char *)name)) {
		if (!strcasecmp("get", (const char *)value)) {
			ctx->current_method = HTTP_METHOD_GET;
		} else if (!strcasecmp("post", (const char *)value)) {
			ctx->current_method = HTTP_METHOD_POST;
		} else if (!strcasecmp("head", (const char *)value)) {
			ctx->current_method = HTTP_METHOD_HEAD;
		} else {
			ctx->current_method = HTTP_METHOD_NONE;
			return http_send_response_rst_stream(ctx, stream_id, NULL,
					HTTP_STATUS_NOT_IMPLEMENTED);
		}
	}

	if (!strcasecmp("content-type", (const char *)name)) {
		if (strcasecmp("application/dns-message", (const char *)value)) {
			return http_send_response_rst_stream(ctx, stream_id, NULL,
					HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE);
		}
	}

	return 0;
}

/*
 * Process DATA chunk sent by the client (by POST method).
 *
 * We use a single DNS message buffer for the entire connection. Therefore, we
 * don't support interweaving DATA chunks from different streams. To successfully
 * parse multiple subsequent streams, each one must be fully received before
 * processing a new stream. See https://gitlab.nic.cz/knot/knot-resolver/-/issues/619
 */
static int data_chunk_recv_callback(nghttp2_session *h2, uint8_t flags, int32_t stream_id,
				    const uint8_t *data, size_t len, void *user_data)
{
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	ssize_t remaining;
	ssize_t required;
	bool is_first = queue_len(ctx->streams) == 0 || queue_tail(ctx->streams).id != ctx->incomplete_stream;

	if (ctx->incomplete_stream != stream_id) {
		kr_log_debug(DOH, "[%p] stream %d incomplete, refusing (data_chunk_recv_callback)\n",
			(void *)h2, ctx->incomplete_stream);
		refuse_stream(h2, stream_id);
		ctx->incomplete_stream = -1;
		return 0;
	}

	remaining = ctx->buf_size - ctx->submitted - ctx->buf_pos;
	required = len;
	/* First data chunk of the new stream */
	if (is_first)
		required += sizeof(uint16_t);

	if (required > remaining) {
		kr_log_error(DOH, "[%p] insufficient space in buffer\n", (void *)h2);
		ctx->incomplete_stream = -1;
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	if (is_first) {
		/* FIXME: reserving the 2B length should be done elsewhere,
		 * ideally for both POST and GET at the same time. The right
		 * place would probably be after receiving HEADERS frame in
		 * on_frame_recv()
		 *
		 * queue_push() should be moved: see FIXME in
		 * submit_to_wirebuffer() */
		ctx->buf_pos = sizeof(uint16_t);  /* Reserve 2B for dnsmsg len. */
		struct http_stream stream = {
			.id = stream_id,
			.headers = ctx->headers
		};
		queue_push(ctx->streams, stream);
	}

	memmove(ctx->buf + ctx->buf_pos, data, len);
	ctx->buf_pos += len;
	return 0;
}

static int submit_to_wirebuffer(struct http_ctx *ctx)
{
	int ret = -1;
	ssize_t len;

	/* Transfer ownership to stream (waiting in wirebuffer) */
	/* FIXME: technically, transferring memory ownership should happen
	 * along with queue_push(ctx->streams) to avoid confusion of who owns
	 * what and when. Pushing to queue should be done AFTER we successfully
	 * finish this function. On error, we'd clean up and not push anything.
	 * However, queue's content is now also used to detect first DATA frame
	 * in stream, so it needs to be refactored first.
	 *
	 * For now, we assume memory is transferred even on error and the
	 * headers themselves get cleaned up during http_free() which is
	 * triggered after the error when session is closed.  */
	ctx->headers = NULL;

	len = ctx->buf_pos - sizeof(uint16_t);
	if (len <= 0 || len > KNOT_WIRE_MAX_PKTSIZE) {
		kr_log_debug(DOH, "[%p] invalid dnsmsg size: %zd B\n", (void *)ctx->h2, len);
		http_send_response_rst_stream(ctx, stream_id, NULL, (len <= 0)
				? HTTP_STATUS_BAD_REQUEST
				: HTTP_STATUS_PAYLOAD_TOO_LARGE);
		ret = -1;
		goto cleanup;
	}

	/* Submit data to wirebuffer. */
	knot_wire_write_u16(ctx->buf, len);
	ctx->submitted_stream = stream_id;
	ctx->submitted += ctx->buf_pos;
	ctx->buf += ctx->buf_pos;
	ctx->buf_pos = 0;
	ret = 0;
cleanup:
	http_cleanup_stream(ctx);
	return ret;
}

/*
 * Finalize existing buffer upon receiving the last frame in the stream.
 *
 * For GET, this would be HEADERS frame.
 * For POST, it is a DATA frame.
 *
 * Unrelated frames (such as SETTINGS) are ignored (no data was buffered).
 */
static int on_frame_recv_callback(nghttp2_session *h2, const nghttp2_frame *frame, void *user_data)
{
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	int32_t stream_id = frame->hd.stream_id;
	if(kr_fails_assert(stream_id != -1))
		return NGHTTP2_ERR_CALLBACK_FAILURE;

	if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) && ctx->incomplete_stream == stream_id) {
		ctx->streaming = false;

		if (ctx->current_method == HTTP_METHOD_GET || ctx->current_method == HTTP_METHOD_HEAD) {
			if (process_uri_path(ctx, ctx->uri_path, stream_id) < 0) {
				/* End processing - don't submit to wirebuffer. */
				return http_send_response_rst_stream(ctx, stream_id, NULL,
						HTTP_STATUS_BAD_REQUEST);
			}
		}

		if (submit_to_wirebuffer(ctx) < 0)
			return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

/*
 * Call on_write() callback for written (or failed) packet data.
 */
static void on_pkt_write(struct http_data *data, int status)
{
	if (!data || !data->req || !data->on_write)
		return;

	data->on_write(data->req, status);
	free(data);
}

static int stream_write_data_free_err(trie_val_t *val, void *null)
{
	on_pkt_write(*val, kr_error(EIO));
	return 0;
}

/*
 * Cleanup for closed streams.
 */
static int on_stream_close_callback(nghttp2_session *h2, int32_t stream_id,
				    uint32_t error_code, void *user_data)
{
	struct http_data *data;
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	int ret;

	/* Ensure connection state is cleaned up in case the stream gets
	 * unexpectedly closed, e.g. by PROTOCOL_ERROR issued from nghttp2. */
	if (ctx->incomplete_stream == stream_id)
		http_cleanup_stream(ctx);

	ret = trie_del(ctx->stream_write_data, (char *)&stream_id, sizeof(stream_id), (trie_val_t*)&data);
	if (ret == KNOT_EOK && data)
		on_pkt_write(data, error_code == 0 ? 0 : kr_error(EIO));

	return 0;
}

/*
 * Setup and initialize connection with new HTTP/2 context.
 */
struct http_ctx* http_new(struct session *session, http_send_callback send_cb)
{
	if (!session || !send_cb)
		return NULL;

	nghttp2_session_callbacks *callbacks;
	struct http_ctx *ctx = NULL;
	static const nghttp2_settings_entry iv[] = {
		{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, HTTP_MAX_CONCURRENT_STREAMS }
	};

	if (nghttp2_session_callbacks_new(&callbacks) < 0)
		return ctx;
	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_send_data_callback(callbacks, send_data_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, header_callback);
	nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, begin_headers_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
		callbacks, data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(
		callbacks, on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(
		callbacks, on_stream_close_callback);

	ctx = calloc(1UL, sizeof(struct http_ctx));
	if (!ctx)
		goto finish;

	ctx->send_cb = send_cb;
	ctx->session = session;
	queue_init(ctx->streams);
	ctx->stream_write_data = trie_create(NULL);
	ctx->incomplete_stream = -1;
	ctx->submitted_stream = -1;
	ctx->submitted = 0;
	ctx->streaming = true;
	ctx->current_method = HTTP_METHOD_NONE;
	ctx->uri_path = NULL;

	nghttp2_session_server_new(&ctx->h2, callbacks, ctx);
	nghttp2_submit_settings(ctx->h2, NGHTTP2_FLAG_NONE,
		iv, sizeof(iv)/sizeof(*iv));

	struct sockaddr *peer = session_get_peer(session);
	kr_log_debug(DOH, "[%p] h2 session created for %s\n", (void *)ctx->h2, kr_straddr(peer));
finish:
	nghttp2_session_callbacks_del(callbacks);
	return ctx;
}

/*
 * Process inbound HTTP/2 data and return number of bytes read into session wire buffer.
 *
 * This function may trigger outgoing HTTP/2 data, such as stream resets, window updates etc.
 *
 * Returns 1 if stream has not ended yet, 0 if the stream has ended, or
 * a negative value on error.
 */
int http_process_input_data(struct session *session, const uint8_t *buf,
			    ssize_t nread, ssize_t *out_submitted)
{
	struct http_ctx *ctx = session_http_get_server_ctx(session);
	ssize_t ret = 0;

	if (!ctx->h2)
		return kr_error(ENOSYS);
	if (kr_fails_assert(ctx->session == session))
		return kr_error(EINVAL);

	/* FIXME It is possible for the TLS/HTTP processing to be cut off at
	 * any point, waiting for more data. If we're using POST which is split
	 * into multiple DATA frames and such a stream is in the middle of
	 * processing, resetting buf_pos will corrupt its contents (and the
	 * query will be ignored).  This may also be problematic in other
	 * cases.  */
	ctx->submitted = 0;
	ctx->streaming = true;
	ctx->buf = session_wirebuf_get_free_start(session);
	ctx->buf_pos = 0;
	ctx->buf_size = session_wirebuf_get_free_size(session);

	ret = nghttp2_session_mem_recv(ctx->h2, buf, nread);
	if (ret < 0) {
		kr_log_debug(DOH, "[%p] nghttp2_session_mem_recv failed: %s (%zd)\n",
			     (void *)ctx->h2, nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	ret = nghttp2_session_send(ctx->h2);
	if (ret < 0) {
		kr_log_debug(DOH, "[%p] nghttp2_session_send failed: %s (%zd)\n",
			     (void *)ctx->h2, nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	*out_submitted = ctx->submitted;
	return ctx->streaming;
}

int http_send_bad_request(struct session *session)
{
	struct http_ctx *ctx = session_http_get_server_ctx(session);
	if (ctx->submitted_stream >= 0)
		return http_send_response_rst_stream(ctx, ctx->submitted_stream, NULL,
				HTTP_STATUS_BAD_REQUEST);

	return 0;
}

/*
 * Provide data from buffer to HTTP/2 library.
 *
 * To avoid copying the packet wire buffer, we use NGHTTP2_DATA_FLAG_NO_COPY
 * and take care of sending entire DATA frames ourselves with nghttp2_send_data_callback.
 *
 * See https://www.nghttp2.org/documentation/types.html#c.nghttp2_data_source_read_callback
 */
static ssize_t read_callback(nghttp2_session *h2, int32_t stream_id, uint8_t *buf,
			     size_t length, uint32_t *data_flags,
			     nghttp2_data_source *source, void *user_data)
{
	struct http_data *data;
	size_t avail;
	size_t send;

	data = (struct http_data*)source->ptr;
	avail = data->len - data->pos;
	send = MIN(avail, length);

	if (avail == send)
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;

	*data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;
	return send;
}

/** Convenience function for pushing `nghttp2_nv` made with MAKE_*_NV into
 * arrays. */
static inline void push_nv(nghttp2_array_t *arr, nghttp2_nv nv)
{
	array_push(*arr, nv);
}

/*
 * Send dns response provided by the HTTP/2 data provider.
 *
 * Data isn't guaranteed to be sent immediately due to underlying HTTP/2 flow control.
 */
static int http_send_response(struct http_ctx *ctx, int32_t stream_id,
			      nghttp2_data_provider *prov, enum http_status status)
{
	nghttp2_session *h2 = ctx->h2;
	int ret;

	nghttp2_array_t hdrs;
	array_init(hdrs);
	array_reserve(hdrs, 5);

	auto_free char *status_str = NULL;
	if (likely(status == HTTP_STATUS_OK)) {
		push_nv(&hdrs, MAKE_STATIC_NV(":status", "200"));
	} else {
		int status_len = asprintf(&status_str, "%" PRIu16, status);
		kr_require(status_len >= 0);
		push_nv(&hdrs, MAKE_STATIC_KEY_NV(":status", status_str, status_len));
	}
	push_nv(&hdrs, MAKE_STATIC_NV("access-control-allow-origin", "*"));

	struct http_data *data = NULL;
	auto_free char *size = NULL;
	auto_free char *max_age = NULL;

	if (ctx->current_method == HTTP_METHOD_HEAD && prov) {
		/* HEAD method is the same as GET but only returns headers,
		 * so let's clean up the data here as we don't need it. */
		free(prov->source.ptr);
		prov = NULL;
	}

	if (prov) {
		data = (struct http_data*)prov->source.ptr;
		const char *directive_max_age = "max-age=";
		int max_age_len;
		int size_len;

		size_len = asprintf(&size, "%zu", data->len);
		kr_require(size_len >= 0);
		max_age_len = asprintf(&max_age, "%s%" PRIu32, directive_max_age, data->ttl);
		kr_require(max_age_len >= 0);

		push_nv(&hdrs, MAKE_STATIC_NV("content-type", "application/dns-message"));
		push_nv(&hdrs, MAKE_STATIC_KEY_NV("content-length", size, size_len));
		push_nv(&hdrs, MAKE_STATIC_KEY_NV("cache-control", max_age, max_age_len));
	}

	ret = nghttp2_submit_response(h2, stream_id, hdrs.at, hdrs.len, prov);
	array_clear(hdrs);
	if (ret != 0) {
		kr_log_debug(DOH, "[%p] nghttp2_submit_response failed: %s\n", (void *)h2, nghttp2_strerror(ret));
		free(data);
		return kr_error(EIO);
	}

	/* Keep reference to data, since we need to free it later on.
	 * Due to HTTP/2 flow control, this stream data may be sent at a later point, or not at all.
	 */
	trie_val_t *stream_data_p = trie_get_ins(ctx->stream_write_data, (char *)&stream_id, sizeof(stream_id));
	if (kr_fails_assert(stream_data_p)) {
		kr_log_debug(DOH, "[%p] failed to insert to stream_write_data\n", (void *)h2);
		free(data);
		return kr_error(EIO);
	}
	*stream_data_p = data;
	ret = nghttp2_session_send(h2);
	if(ret < 0) {
		kr_log_debug(DOH, "[%p] nghttp2_session_send failed: %s\n", (void *)h2, nghttp2_strerror(ret));

		/* At this point, there was an error in some nghttp2 callback. The on_pkt_write()
		 * callback which also calls free(data) may or may not have been called. Therefore,
		 * we must guarantee it will have been called by explicitly closing the stream.
		 * Afterwards, we have no option but to pretend this function was a success. If we
		 * returned an error, qr_task_send() logic would lead to a double-free because
		 * on_write() was already called. */
		nghttp2_submit_rst_stream(h2, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_INTERNAL_ERROR);
		return 0;
	}

	return 0;
}

/*
 * Same as `http_send_response`, but resets the HTTP stream afterwards. Used
 * for sending negative status messages.
 */
static int http_send_response_rst_stream(struct http_ctx *ctx, int32_t stream_id,
			      nghttp2_data_provider *prov, enum http_status status)
{
	int ret = http_send_response(ctx, stream_id, prov, status);
	if (ret)
		return ret;

	ctx->submitted_stream = -1;
	nghttp2_submit_rst_stream(ctx->h2, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_NO_ERROR);
	ret = nghttp2_session_send(ctx->h2);
	return ret;
}


/*
 * Send HTTP/2 stream data created from packet's wire buffer.
 *
 * If this function returns an error, the on_write() callback isn't (and
 * mustn't be!) called, since such errors are handled in an upper layer - in
 * qr_task_step() in daemon/worker.
 */
static int http_write_pkt(struct http_ctx *ctx, knot_pkt_t *pkt, int32_t stream_id,
			  uv_write_t *req, uv_write_cb on_write)
{
	struct http_data *data;
	nghttp2_data_provider prov;
	const bool is_negative = kr_response_classify(pkt) & (PKT_NODATA|PKT_NXDOMAIN);

	data = malloc(sizeof(struct http_data));
	if (!data)
		return kr_error(ENOMEM);

	data->buf = pkt->wire;
	data->len = pkt->size;
	data->pos = 0;
	data->on_write = on_write;
	data->req = req;
	data->ttl = packet_ttl(pkt, is_negative);

	prov.source.ptr = data;
	prov.read_callback = read_callback;

	return http_send_response(ctx, stream_id, &prov, HTTP_STATUS_OK);
}

/*
 * Write request to HTTP/2 stream.
 *
 * Packet wire buffer must stay valid until the on_write callback.
 */
int http_write(uv_write_t *req, uv_handle_t *handle, knot_pkt_t *pkt, int32_t stream_id,
	       uv_write_cb on_write)
{
	struct session *session;
	struct http_ctx *ctx;
	int ret;

	if (!req || !pkt || !handle || !handle->data || stream_id < 0)
		return kr_error(EINVAL);
	req->handle = (uv_stream_t *)handle;

	session = handle->data;
	if (session_flags(session)->outgoing)
		return kr_error(ENOSYS);

	ctx = session_http_get_server_ctx(session);
	if (!ctx || !ctx->h2)
		return kr_error(EINVAL);

	ret = http_write_pkt(ctx, pkt, stream_id, req, on_write);
	if (ret < 0)
		return ret;

	return kr_ok();
}

/*
 * Release HTTP/2 context.
 */
void http_free(struct http_ctx *ctx)
{
	if (!ctx)
		return;

	kr_log_debug(DOH, "[%p] h2 session freed\n", (void *)ctx->h2);

	/* Clean up any headers whose ownership may not have been transferred.
	 * This may happen when connection is abruptly ended (e.g. due to errors while
	 * processing HTTP stream. */
	while (queue_len(ctx->streams) > 0) {
		struct http_stream stream = queue_head(ctx->streams);
		http_free_headers(stream.headers);
		if (stream.headers == ctx->headers)
			ctx->headers = NULL;  // to prevent double-free
		queue_pop(ctx->streams);
	}

	trie_apply(ctx->stream_write_data, stream_write_data_free_err, NULL);
	trie_free(ctx->stream_write_data);

	http_cleanup_stream(ctx);
	queue_deinit(ctx->streams);
	nghttp2_session_del(ctx->h2);
	free(ctx);
}
