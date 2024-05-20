/*
 * Copyright (C) CZ.NIC, z.s.p.o
 *
 * Initial Author: Jan Hák <jan.hak@nic.cz>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <nghttp2/nghttp2.h>

#include "contrib/base64url.h"
#include "contrib/cleanup.h"
#include "daemon/session2.h"
#include "daemon/worker.h"

#include "daemon/http.h"

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

/* Initial max frame size: https://tools.ietf.org/html/rfc7540#section-6.5.2 */
#define HTTP_MAX_FRAME_SIZE 16384

#define HTTP_FRAME_HDLEN 9
#define HTTP_FRAME_PADLEN 1

struct http_stream {
	int32_t id;
	kr_http_header_array_t *headers;
};

typedef queue_t(struct http_stream) queue_http_stream;
typedef array_t(nghttp2_nv) nghttp2_array_t;

enum http_method {
	HTTP_METHOD_NONE = 0,
	HTTP_METHOD_GET = 1,
	HTTP_METHOD_POST = 2,
	HTTP_METHOD_HEAD = 3, /**< Same as GET, except it does not return payload.
			       * Required to be implemented by RFC 7231. */
};

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

struct pl_http_sess_data {
	struct protolayer_data h;
	struct nghttp2_session *h2;

	queue_http_stream streams;  /* Streams present in the wire buffer. */
	trie_t *stream_write_queues;  /* Dictionary of stream data that needs to be freed after write. */
	int32_t incomplete_stream;
	int32_t last_stream;   /* The last used stream - mostly the same as incomplete_stream, but can be used after
				  completion for sending HTTP status codes. */
	enum http_method current_method;
	char *uri_path;
	kr_http_header_array_t *headers;
	enum http_status status;
	struct wire_buf wire_buf;
};

struct http_send_ctx {
	struct pl_http_sess_data *sess_data;
	uint8_t data[];
};


/** Checks if `status` has the correct `category`.
 * E.g. status 200 has category 2, status 404 has category 4, 501 has category 5 etc. */
static inline bool http_status_has_category(enum http_status status, int category)
{
	return status / 100 == category;
}

/*
 * Sets the HTTP status of the specified `context`, but only if its status has
 * not already been changed to an unsuccessful one.
 */
static inline void set_status(struct pl_http_sess_data *ctx, enum http_status status)
{
	if (http_status_has_category(ctx->status, 2))
		ctx->status = status;
}

/*
 * Check endpoint and uri path
 */
static int check_uri(const char* path)
{
	static const char *endpoints[] = {"dns-query", "doh"};
	ssize_t endpoint_len;
	ssize_t ret;

	if (!path)
		return kr_error(EINVAL);

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

	return (ret) ? kr_error(ENOENT) : kr_ok();
}

static kr_http_header_array_t *headers_dup(kr_http_header_array_t *src)
{
	kr_http_header_array_t *dst = malloc(sizeof(kr_http_header_array_t));
	kr_require(dst);
	array_init(*dst);
	for (size_t i = 0; i < src->len; i++) {
		struct kr_http_header_array_entry *src_entry = &src->at[i];
		struct kr_http_header_array_entry dst_entry = {
			.name = strdup(src_entry->name),
			.value = strdup(src_entry->value)
		};
		array_push(*dst, dst_entry);
	}

	return dst;
}

/*
 * Process a query from URI path if there's base64url encoded dns variable.
 */
static int process_uri_path(struct pl_http_sess_data *ctx, const char* path, int32_t stream_id)
{
	if (!ctx || !path)
		return kr_error(EINVAL);

	static const char key[] = "dns=";
	static const char *delim = "&";
	char *beg, *end;
	uint8_t *dest;
	uint32_t remaining;

	char *query_mark = strstr(path, "?");
	if (!query_mark || strlen(query_mark) == 0) /* no parameters in path */
		return kr_error(EINVAL);

	/* go over key:value pair */
	for (beg = strtok(query_mark + 1, delim); beg != NULL; beg = strtok(NULL, delim)) {
		if (!strncmp(beg, key, 4)) /* dns variable in path found */
			break;
	}

	if (!beg) /* no dns variable in path */
		return kr_error(EINVAL);

	beg += sizeof(key) - 1;
	end = strchr(beg, '&');
	if (end == NULL)
		end = beg + strlen(beg);

	struct wire_buf *wb = &ctx->wire_buf;
	remaining = wire_buf_free_space_length(wb);
	dest = wire_buf_free_space(wb);

	/* Decode dns message from the parameter */
	int ret = kr_base64url_decode((uint8_t*)beg, end - beg, dest, remaining);
	if (ret < 0) {
		wire_buf_reset(wb);
		kr_log_debug(DOH, "[%p] base64url decode failed %s\n", (void *)ctx->h2, kr_strerror(ret));
		return ret;
	}

	wire_buf_consume(wb, ret);

	struct http_stream stream = {
		.id = stream_id,
		.headers = headers_dup(ctx->headers)
	};
	queue_push(ctx->streams, stream);

	return kr_ok();
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
static void http_cleanup_stream(struct pl_http_sess_data *ctx)
{
	ctx->incomplete_stream = -1;
	ctx->current_method = HTTP_METHOD_NONE;
	ctx->status = HTTP_STATUS_OK;
	free(ctx->uri_path);
	ctx->uri_path = NULL;
	http_free_headers(ctx->headers);
	ctx->headers = NULL;
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
static int http_send_response(struct pl_http_sess_data *http, int32_t stream_id,
                              nghttp2_data_provider *prov, enum http_status status)
{
	nghttp2_session *h2 = http->h2;
	int ret;

	nghttp2_array_t hdrs;
	array_init(hdrs);
	array_reserve(hdrs, 5);

	auto_free char *status_str = NULL;
	if (likely(status == HTTP_STATUS_OK)) {
		push_nv(&hdrs, MAKE_STATIC_NV(":status", "200"));
	} else {
		int status_len = asprintf(&status_str, "%d", (int)status);
		kr_require(status_len >= 0);
		push_nv(&hdrs, MAKE_STATIC_KEY_NV(":status", status_str, status_len));
	}
	push_nv(&hdrs, MAKE_STATIC_NV("access-control-allow-origin", "*"));

	struct protolayer_iter_ctx *ctx = NULL;
	auto_free char *size = NULL;
	auto_free char *max_age = NULL;

	if (http->current_method == HTTP_METHOD_HEAD && prov) {
		/* HEAD method is the same as GET but only returns headers,
		 * so let's clean up the data here as we don't need it. */
		protolayer_break(prov->source.ptr, kr_ok());
		prov = NULL;
	}

	if (prov) {
		ctx = prov->source.ptr;
		const char *directive_max_age = "max-age=";
		int max_age_len;
		int size_len;

		size_len = asprintf(&size, "%zu", protolayer_payload_size(&ctx->payload));
		kr_require(size_len >= 0);

		max_age_len = asprintf(&max_age, "%s%" PRIu32, directive_max_age, ctx->payload.ttl);
		kr_require(max_age_len >= 0);

		/* TODO: add a per-protolayer_grp option for content-type if we
		 * need to support protocols other than DNS here */
		push_nv(&hdrs, MAKE_STATIC_NV("content-type", "application/dns-message"));
		push_nv(&hdrs, MAKE_STATIC_KEY_NV("content-length", size, size_len));
		push_nv(&hdrs, MAKE_STATIC_KEY_NV("cache-control", max_age, max_age_len));
	}

	ret = nghttp2_submit_response(h2, stream_id, hdrs.at, hdrs.len, prov);
	array_clear(hdrs);
	if (ret != 0) {
		kr_log_debug(DOH, "[%p] nghttp2_submit_response failed: %s\n", (void *)h2, nghttp2_strerror(ret));
		if (ctx)
			protolayer_break(ctx, kr_error(EIO));
		return kr_error(EIO);
	}

	/* Keep reference to data, since we need to free it later on.
	 * Due to HTTP/2 flow control, this stream data may be sent at a later point, or not at all.
	 */
	if (ctx) {
		protolayer_iter_ctx_queue_t **ctx_queue =
			(protolayer_iter_ctx_queue_t **)trie_get_ins(
					http->stream_write_queues,
					(char *)&stream_id, sizeof(stream_id));

		if (kr_fails_assert(ctx_queue)) {
			kr_log_debug(DOH, "[%p] failed to insert to stream_write_data\n", (void *)h2);
			if (ctx)
				protolayer_break(ctx, kr_error(EIO));
			return kr_error(EIO);
		}

		if (!*ctx_queue) {
			*ctx_queue = malloc(sizeof(**ctx_queue));
			kr_require(*ctx_queue);
			queue_init(**ctx_queue);
		}

		queue_push(**ctx_queue, ctx);
	}

	ret = nghttp2_session_send(h2);
	if(ret) {
		kr_log_debug(DOH, "[%p] nghttp2_session_send failed: %s\n", (void *)h2, nghttp2_strerror(ret));

		/* At this point, there was an error in some nghttp2 callback. The protolayer_break()
		 * function which also calls free(ctx) may or may not have been called. Therefore,
		 * we must guarantee it will have been called by explicitly closing the stream. */
		nghttp2_submit_rst_stream(h2, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_INTERNAL_ERROR);
		return kr_error(EIO);
	}

	return 0;
}

/*
 * Same as `http_send_response`, but resets the HTTP stream afterwards. Used
 * for sending negative status messages.
 */
static int http_send_response_rst_stream(struct pl_http_sess_data *ctx, int32_t stream_id,
                                         nghttp2_data_provider *prov, enum http_status status)
{
	int ret = http_send_response(ctx, stream_id, prov, status);
	if (ret)
		return ret;

	ctx->last_stream = -1;
	nghttp2_submit_rst_stream(ctx->h2, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_NO_ERROR);
	ret = nghttp2_session_send(ctx->h2);
	return ret;
}

static void callback_finished_free_baton(int status, struct session2 *session,
                                         const struct comm_info *comm, void *baton)
{
	free(baton);
}

/*
 * Write HTTP/2 protocol data to underlying transport layer.
 */
static ssize_t send_callback(nghttp2_session *h2, const uint8_t *data, size_t length,
			     int flags, void *user_data)
{
	struct pl_http_sess_data *http = user_data;
	struct http_send_ctx *send_ctx = malloc(sizeof(*send_ctx) + length);
	kr_require(send_ctx);
	send_ctx->sess_data = http;
	memcpy(send_ctx->data, data, length);

	kr_log_debug(DOH, "[%p] send_callback: %p\n", (void *)h2, (void *)send_ctx->data);
	session2_wrap_after(http->h.session, PROTOLAYER_PROTOCOL_HTTP,
			protolayer_buffer(send_ctx->data, length, false), NULL,
			callback_finished_free_baton, send_ctx);

	return length;
}

struct http_send_data_ctx {
	uint8_t padlen;
	struct iovec iov[];
};

static int send_data_callback(nghttp2_session *h2, nghttp2_frame *frame, const uint8_t *framehd,
			      size_t length, nghttp2_data_source *source, void *user_data)
{
	struct pl_http_sess_data *http = user_data;

	int has_padding = !!(frame->data.padlen);
	uint8_t padlen = (frame->data.padlen > 1) ? frame->data.padlen : 2;

	struct protolayer_iter_ctx *ctx = source->ptr;
	struct protolayer_payload *pld = &ctx->payload;

	struct iovec bufiov;
	struct iovec *dataiov;
	int dataiovcnt;
	bool adapt_iovs = false;
	if (pld->type == PROTOLAYER_PAYLOAD_BUFFER) {
		size_t to_copy = MIN(length, pld->buffer.len);
		if (!to_copy)
			return NGHTTP2_ERR_PAUSE;

		bufiov = (struct iovec){ pld->buffer.buf, to_copy };
		dataiov = &bufiov;
		dataiovcnt = 1;

		pld->buffer.buf = (char *)pld->buffer.buf + to_copy;
		pld->buffer.len -= to_copy;
	} else if (pld->type == PROTOLAYER_PAYLOAD_WIRE_BUF) {
		size_t wbl = wire_buf_data_length(pld->wire_buf);
		size_t to_copy = MIN(length, wbl);
		if (!to_copy)
			return NGHTTP2_ERR_PAUSE;

		bufiov = (struct iovec){
			wire_buf_data(pld->wire_buf),
			to_copy
		};
		dataiov = &bufiov;
		dataiovcnt = 1;

		wire_buf_trim(pld->wire_buf, to_copy);
		if (wire_buf_data_length(pld->wire_buf) == 0) {
			wire_buf_reset(pld->wire_buf);
		}
	} else if (pld->type == PROTOLAYER_PAYLOAD_IOVEC) {
		if (pld->iovec.cnt <= 0)
			return NGHTTP2_ERR_PAUSE;

		dataiov = pld->iovec.iov;
		dataiovcnt = 0;
		size_t avail = 0;
		for (int i = 0; i < pld->iovec.cnt && avail < length; i++) {
			avail += pld->iovec.iov[i].iov_len;
			dataiovcnt += 1;
		}

		/* The actual iovec generation needs to be done later when we
		 * have memory for them. Here, we just count the number of
		 * needed iovecs. */
		adapt_iovs = true;
	} else {
		kr_assert(false && "Invalid payload");
		protolayer_break(ctx, kr_error(EINVAL));
		return kr_error(EINVAL);
	}

	int iovcnt = 1 + dataiovcnt + (2 * has_padding);
	struct http_send_data_ctx *sdctx = calloc(iovcnt, sizeof(*ctx) + sizeof(struct iovec[iovcnt]));
	sdctx->padlen = padlen;

	struct iovec *dest_iov = sdctx->iov;
	static const uint8_t padding[UINT8_MAX];

	int cur = 0;
	dest_iov[cur++] = (struct iovec){ (void *)framehd, HTTP_FRAME_HDLEN };

	if (has_padding)
		dest_iov[cur++] = (struct iovec){ &sdctx->padlen, HTTP_FRAME_PADLEN };

	if (adapt_iovs) {
		while (pld->iovec.cnt && length > 0) {
			struct iovec *iov = pld->iovec.iov;
			size_t to_copy = MIN(length, iov->iov_len);

			dest_iov[cur++] = (struct iovec){
				iov->iov_base, to_copy
			};
			length -= to_copy;
			iov->iov_base = ((char *)iov->iov_base) + to_copy;
			iov->iov_len -= to_copy;

			if (iov->iov_len == 0) {
				pld->iovec.iov++;
				pld->iovec.cnt--;
			}
		}
	} else {
		memcpy(&dest_iov[cur], dataiov, sizeof(struct iovec[dataiovcnt]));
		cur += dataiovcnt;
	}

	if (has_padding)
		dest_iov[cur++] = (struct iovec){ (void *)padding, padlen - 1 };

	kr_assert(cur == iovcnt);
	int ret = session2_wrap_after(http->h.session, PROTOLAYER_PROTOCOL_HTTP,
			protolayer_iovec(dest_iov, cur, false),
			NULL, callback_finished_free_baton, sdctx);

	if (ret < 0)
		return ret;
	return 0;
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
	struct pl_http_sess_data *ctx = user_data;
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
		ctx->last_stream = stream_id;
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
	struct pl_http_sess_data *ctx = user_data;
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
				set_status(ctx, HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE);
				return 0;
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
			set_status(ctx, HTTP_STATUS_NOT_FOUND);
			return 0;
		} else if (uri_result < 0) {
			set_status(ctx, HTTP_STATUS_BAD_REQUEST);
			return 0;
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
			set_status(ctx, HTTP_STATUS_NOT_IMPLEMENTED);
			return 0;
		}
	}

	if (!strcasecmp("content-type", (const char *)name)) {
		/* TODO: add a per-group option for content-type if we need to
		 * support protocols other than DNS here */
		if (strcasecmp("application/dns-message", (const char *)value) != 0) {
			set_status(ctx, HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE);
			return 0;
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
	struct pl_http_sess_data *ctx = user_data;
	bool is_first = queue_len(ctx->streams) == 0 || queue_tail(ctx->streams).id != ctx->incomplete_stream;

	if (ctx->incomplete_stream != stream_id) {
		kr_log_debug(DOH, "[%p] stream %d incomplete, refusing (data_chunk_recv_callback)\n",
			(void *)h2, ctx->incomplete_stream);
		refuse_stream(h2, stream_id);
		ctx->incomplete_stream = -1;
		return 0;
	}

	struct wire_buf *wb = &ctx->wire_buf;

	ssize_t remaining = wire_buf_free_space_length(wb);
	ssize_t required = len;
	/* First data chunk of the new stream */
	if (is_first)
		required += sizeof(uint16_t);

	if (required > remaining) {
		kr_log_error(DOH, "[%p] insufficient space in buffer\n", (void *)h2);
		ctx->incomplete_stream = -1;
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	if (is_first) {
		/* queue_push() should be moved: see FIXME in
		 * submit_to_wirebuffer() */
		struct http_stream stream = {
			.id = stream_id,
			.headers = headers_dup(ctx->headers)
		};
		queue_push(ctx->streams, stream);
	}

	memmove(wire_buf_free_space(wb), data, len);
	wire_buf_consume(wb, len);
	return 0;
}

static int submit_to_wirebuffer(struct pl_http_sess_data *ctx)
{
	int ret = -1;

	/* Free http_ctx's headers - by now the stream has obtained its own
	 * copy of the headers which it can operate on. */
	/* FIXME: technically, transferring memory ownership should happen
	 * along with queue_push(ctx->streams) to avoid confusion of who owns
	 * what and when. Pushing to queue should be done AFTER we successfully
	 * finish this function. On error, we'd clean up and not push anything.
	 * However, queue's content is now also used to detect first DATA frame
	 * in stream, so it needs to be refactored first.
	 *
	 * For now, we assume memory is transferred even on error and the
	 * headers themselves get cleaned up during http_free() which is
	 * triggered after the error when session is closed.
	 *
	 * EDIT(2022-05-19): The original logic was causing occasional
	 * double-free conditions once status code support was extended.
	 *
	 * Currently, we are copying the headers from ctx instead of transferring
	 * ownership, which is still a dirty workaround and, ideally, the whole
	 * logic around header (de)allocation should be reworked to make
	 * the ownership situation clear. */
	http_free_headers(ctx->headers);
	ctx->headers = NULL;

	struct wire_buf *wb = &ctx->wire_buf;

	ssize_t len = wire_buf_data_length(wb) - sizeof(uint16_t);
	if (len <= 0 || len > KNOT_WIRE_MAX_PKTSIZE) {
		kr_log_debug(DOH, "[%p] invalid dnsmsg size: %zd B\n", (void *)ctx->h2, len);
		set_status(ctx, (len <= 0)
				? HTTP_STATUS_BAD_REQUEST
				: HTTP_STATUS_PAYLOAD_TOO_LARGE);
		ret = 0;
		goto cleanup;
	}

	ret = 0;
	session2_unwrap_after(ctx->h.session, PROTOLAYER_PROTOCOL_HTTP,
			protolayer_wire_buf(wb, false), NULL, NULL, NULL);
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
	struct pl_http_sess_data *ctx = user_data;
	int32_t stream_id = frame->hd.stream_id;
	if(kr_fails_assert(stream_id != -1))
		return NGHTTP2_ERR_CALLBACK_FAILURE;

	if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) && ctx->incomplete_stream == stream_id) {
		if (ctx->current_method == HTTP_METHOD_GET || ctx->current_method == HTTP_METHOD_HEAD) {
			if (process_uri_path(ctx, ctx->uri_path, stream_id) < 0) {
				/* End processing - don't submit to wirebuffer. */
				set_status(ctx, HTTP_STATUS_BAD_REQUEST);
				return 0;
			}
		}

		if (!http_status_has_category(ctx->status, 2))
			return 0;

		if (submit_to_wirebuffer(ctx) < 0)
			return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

/*
 * Cleanup for closed streams.
 */
static int on_stream_close_callback(nghttp2_session *h2, int32_t stream_id,
                                    uint32_t error_code, void *user_data)
{
	struct pl_http_sess_data *http = user_data;
	int ret;

	/* Ensure connection state is cleaned up in case the stream gets
	 * unexpectedly closed, e.g. by PROTOCOL_ERROR issued from nghttp2. */
	if (http->incomplete_stream == stream_id)
		http_cleanup_stream(http);

	protolayer_iter_ctx_queue_t *queue;
	ret = trie_del(http->stream_write_queues, (char *)&stream_id, sizeof(stream_id), (trie_val_t*)&queue);
	if (ret == KNOT_EOK && queue) {
		uint32_t e = error_code == 0 ? 0 : kr_error(EIO);
		while (queue_len(*queue) > 0) {
			struct protolayer_iter_ctx *ctx = queue_head(*queue);
			protolayer_break(ctx, e);
			queue_pop(*queue);
		}
		queue_deinit(*queue);
		free(queue);
	}

	return 0;
}

int http_send_status(struct pl_http_sess_data *ctx, enum http_status status)
{
	if (ctx->last_stream >= 0)
		return http_send_response_rst_stream(
				ctx, ctx->last_stream, NULL, status);

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
	struct protolayer_iter_ctx *ctx = source->ptr;
	size_t avail = protolayer_payload_size(&ctx->payload);
	size_t send = MIN(avail, length);

	if (avail == send)
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;

	*data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;
	return send;
}

static int pl_http_sess_init(struct protolayer_manager *manager,
                             void *data, void *param)
{
	struct pl_http_sess_data *http = data;

	nghttp2_session_callbacks *callbacks;
	static const nghttp2_settings_entry iv[] = {
		{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, HTTP_MAX_CONCURRENT_STREAMS }
	};

	int ret = nghttp2_session_callbacks_new(&callbacks);
	if (ret < 0)
		return ret;

	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_send_data_callback(callbacks, send_data_callback);
	nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, begin_headers_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, header_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
		callbacks, data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(
		callbacks, on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(
		callbacks, on_stream_close_callback);

	queue_init(http->streams);
	http->stream_write_queues = trie_create(NULL);
	http->incomplete_stream = -1;
	http->last_stream = -1;
	http->current_method = HTTP_METHOD_NONE;
	http->uri_path = NULL;
	http->status = HTTP_STATUS_OK;
	wire_buf_init(&http->wire_buf, manager->wire_buf.size);

	ret = nghttp2_session_server_new(&http->h2, callbacks, http);
	if (ret < 0)
		goto exit_callbacks;
	nghttp2_submit_settings(http->h2, NGHTTP2_FLAG_NONE, iv, ARRAY_SIZE(iv));

	struct sockaddr *peer = session2_get_peer(manager->session);
	kr_log_debug(DOH, "[%p] h2 session created for %s\n", (void *)http->h2, kr_straddr(peer));

	manager->session->custom_emalf_handling = true;

	ret = kr_ok();

exit_callbacks:
	nghttp2_session_callbacks_del(callbacks);
	return ret;
}

static int stream_write_data_break_err(trie_val_t *val, void *baton)
{
	protolayer_iter_ctx_queue_t *queue = *val;
	if (!queue)
		return 0;

	while (queue_len(*queue) > 0) {
		struct protolayer_iter_ctx *ctx = queue_head(*queue);
		protolayer_break(ctx, kr_error(EIO));
		queue_pop(*queue);
	}
	queue_deinit(*queue);
	free(queue);
	return 0;
}

static int pl_http_sess_deinit(struct protolayer_manager *manager,
                               void *data)
{
	struct pl_http_sess_data *http = data;

	kr_log_debug(DOH, "[%p] h2 session freed\n", (void *)http->h2);

	while (queue_len(http->streams) > 0) {
		struct http_stream *stream = &queue_head(http->streams);
		http_free_headers(stream->headers);
		queue_pop(http->streams);
	}

	trie_apply(http->stream_write_queues, stream_write_data_break_err, NULL);
	trie_free(http->stream_write_queues);

	http_cleanup_stream(http);
	queue_deinit(http->streams);
	wire_buf_deinit(&http->wire_buf);
	nghttp2_session_del(http->h2);

	return 0;
}

static enum protolayer_iter_cb_result pl_http_unwrap(
		void *sess_data, void *iter_data,
		struct protolayer_iter_ctx *ctx)
{
	struct pl_http_sess_data *http = sess_data;
	ssize_t ret = 0;

	if (!http->h2)
		return protolayer_break(ctx, kr_error(ENOSYS));

	struct protolayer_payload pld = ctx->payload;
	if (pld.type == PROTOLAYER_PAYLOAD_WIRE_BUF) {
		pld = protolayer_as_buffer(&pld);
	}

	if (pld.type == PROTOLAYER_PAYLOAD_BUFFER) {
		ret = nghttp2_session_mem_recv(http->h2,
				pld.buffer.buf, pld.buffer.len);
		if (ret < 0) {
			kr_log_debug(DOH, "[%p] nghttp2_session_mem_recv failed: %s (%zd)\n",
					(void *)http->h2, nghttp2_strerror(ret), ret);
			return protolayer_break(ctx, kr_error(EIO));
		}
	} else if (pld.type == PROTOLAYER_PAYLOAD_IOVEC) {
		for (int i = 0; i < pld.iovec.cnt; i++) {
			ret = nghttp2_session_mem_recv(http->h2,
					pld.iovec.iov[i].iov_base,
					pld.iovec.iov[i].iov_len);
			if (ret < 0) {
				kr_log_debug(DOH, "[%p] nghttp2_session_mem_recv failed: %s (%zd)\n",
						(void *)http->h2, nghttp2_strerror(ret), ret);
				return protolayer_break(ctx, kr_error(EIO));
			}
		}
	} else {
		kr_assert(false && "Invalid payload type");
		return protolayer_break(ctx, kr_error(EIO));
	}

	ret = nghttp2_session_send(http->h2);
	if (ret < 0) {
		kr_log_debug(DOH, "[%p] nghttp2_session_send failed: %s (%zd)\n",
			     (void *)http->h2, nghttp2_strerror(ret), ret);
		return protolayer_break(ctx, kr_error(EIO));
	}

	if (!http_status_has_category(http->status, 2)) {
		http_send_status(http, http->status);
		http_cleanup_stream(http);
		return protolayer_break(ctx, kr_error(EIO));
	}

	return protolayer_break(ctx, kr_ok());
}

static enum protolayer_iter_cb_result pl_http_wrap(
		void *sess_data, void *iter_data,
		struct protolayer_iter_ctx *ctx)
{
	nghttp2_data_provider prov;

	prov.source.ptr = ctx;
	prov.read_callback = read_callback;

	struct pl_http_sess_data *http = sess_data;
	int32_t stream_id = http->last_stream;
	int ret = http_send_response(sess_data, stream_id, &prov, HTTP_STATUS_OK);
	if (ret)
		return protolayer_break(ctx, ret);

	return protolayer_async();
}

static enum protolayer_event_cb_result pl_http_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct protolayer_manager *manager, void *sess_data)
{
	struct pl_http_sess_data *http = sess_data;

	if (event == PROTOLAYER_EVENT_MALFORMED) {
		http_send_status(http, HTTP_STATUS_BAD_REQUEST);
		return PROTOLAYER_EVENT_PROPAGATE;
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

static void pl_http_request_init(struct protolayer_manager *manager,
                                 struct kr_request *req,
                                 void *sess_data)
{
	struct pl_http_sess_data *http = sess_data;

	req->qsource.comm_flags.http = true;

	struct http_stream *stream = &queue_head(http->streams);
	req->qsource.stream_id = stream->id;
	if (stream->headers) {
		req->qsource.headers = *stream->headers;
		free(stream->headers);
		stream->headers = NULL;
	}
}

void http_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_PROTOCOL_HTTP] = (struct protolayer_globals) {
		.sess_size = sizeof(struct pl_http_sess_data),
		.sess_deinit = pl_http_sess_deinit,
		.wire_buf_overhead = HTTP_MAX_FRAME_SIZE,
		.sess_init = pl_http_sess_init,
		.unwrap = pl_http_unwrap,
		.wrap = pl_http_wrap,
		.event_unwrap = pl_http_event_unwrap,
		.request_init = pl_http_request_init
	};
}
