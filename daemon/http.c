/*
 * Copyright (C) 2020 CZ.NIC, z.s.p.o
 *
 * Initial Author: Jan Hák <jan.hak@nic.cz>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon/io.h"
#include "daemon/http.h"
#include "daemon/worker.h"
#include "daemon/session.h"
#include "lib/layer/iterate.h" /* kr_response_classify */
#include "lib/cache/util.h"

#include "contrib/cleanup.h"
#include "contrib/base64url.h"

#define MAKE_NV(K, KS, V, VS) \
	{ (uint8_t *)(K), (uint8_t *)(V), (KS), (VS), NGHTTP2_NV_FLAG_NONE }

#define MAKE_STATIC_NV(K, V) \
	MAKE_NV((K), sizeof(K) - 1, (V), sizeof(V) - 1)

/* Use same maximum as for tcp_pipeline_max. */
#define HTTP_MAX_CONCURRENT_STREAMS UINT16_MAX

#define HTTP_FRAME_HDLEN 9
#define HTTP_FRAME_PADLEN 1

#define MAX_DECIMAL_LENGTH(VT) ((CHAR_BIT * sizeof(VT) / 3) + 3)

struct http_data {
	uint8_t *buf;
	size_t len;
	size_t pos;
	uint32_t ttl;
	uv_write_cb on_write;
	uv_write_t *req;
};

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

static int http_status_remove(struct http_ctx *ctx, struct http_stream_status * stat);
static struct http_stream_status * http_status_get(struct http_ctx *ctx, int32_t stream_id);

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
	assert(data->pos <= data->len);

	ret = send_padding(ctx, (uint8_t)frame->data.padlen);
	if (ret < 0)
		return NGHTTP2_ERR_CALLBACK_FAILURE;

	http_status_remove(ctx, http_status_get(ctx, frame->hd.stream_id));

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

	if (!source->ptr) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
		return 0;
	}

	data = (struct http_data*)source->ptr;
	avail = data->len - data->pos;
	send = MIN(avail, length);

	if (avail == send)
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;

	*data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;
	return send;
}

/*
 * Get pointer to stream status.
 */
static struct http_stream_status * http_status_get(struct http_ctx *ctx, int32_t stream_id)
{
	assert(ctx);
	struct http_stream_status *stat = NULL;

	if (stream_id == ctx->incomplete_stream)
		return ctx->current_stream;


	for (size_t idx = 0; idx < ctx->stream_status.len; ++idx) {
		stat = ctx->stream_status.at[idx];
		if (stat->stream_id == stream_id)
			return stat;
	}
	return NULL;
}

/*
 * Remove error stream status from list
 */
static int http_status_remove(struct http_ctx *ctx, struct http_stream_status * stat)
{
	if (!stat)
		return 0;

	free(stat->err_msg);
	stat->err_msg = NULL;

	int idx = (stat->ref - ctx->stream_status.at)/sizeof(struct http_stream_status*);
	int ret = array_del(ctx->stream_status, idx);
	assert(ret == 0);

	return 0;
}

/*
 * Send http error status code.
 */
static int send_err_status(struct http_ctx *ctx, int32_t stream_id)
{
	int ret;
	int status_len;
	nghttp2_data_provider prov;
	struct http_stream_status *stat = http_status_get(ctx, stream_id);
	assert(stat);

	prov.source.ptr = NULL;
	prov.read_callback = read_callback;

	char status_str[MAX_DECIMAL_LENGTH(stat->err_status)] = { 0 };
	status_len = snprintf(status_str, MAX_DECIMAL_LENGTH(stat->err_status), "%u", stat->err_status);
	nghttp2_nv hdrs_err[] = {
		MAKE_NV(":status", 7, status_str, status_len),
	};

	if (stat->err_msg) {
		struct http_data *data = malloc(sizeof(struct http_data));
		if (!data)
			return kr_error(ENOMEM);

		data->buf = (uint8_t *)stat->err_msg;
		data->len = strlen(stat->err_msg);
		data->pos = 0;
		data->on_write = NULL;
		data->req = NULL;
		data->ttl = 0;
		prov.source.ptr = data;
	}

	ret = nghttp2_submit_response(ctx->h2, stream_id, hdrs_err, sizeof(hdrs_err)/sizeof(*hdrs_err), &prov);
	if (ret != 0)
		return kr_error(EIO);

	if (queue_len(ctx->streams) != 0)
		queue_pop(ctx->streams);

	return 0;
}

/*
 * Set error status for particural stream_id and return array index or error
 *
 * status_msg is optional and define error message.
 */
static struct http_stream_status * set_error_status(struct http_ctx *ctx, int32_t stream_id, int status, const char *const status_msg)
{

	struct http_stream_status *stat = http_status_get(ctx, stream_id);
	if (stat && stat->err_status != 200)
		return stat;

	// add new item to array
	if (!stat) {
		stat = malloc(sizeof(*stat));
		if (!stat)
			return NULL;

		// push to end of array
		if (array_push(ctx->stream_status, stat) < 0) {
			free(stat);
			return NULL;
		}

		stat->err_msg = NULL;
		// get reference to new iten in array
		stat->ref = &ctx->stream_status.at[ctx->stream_status.len - 1];
	}
	stat->stream_id = stream_id;
	stat->err_status = status;

	if (!status_msg) {
		if (stat->err_msg) { // remove previous message
			free(stat->err_msg);
			stat->err_msg = NULL;
		}

		return stat;
	}

	stat->err_msg = realloc(stat->err_msg, sizeof(*stat->err_msg) * (strlen(status_msg) + 2));
	if (!stat->err_msg) {
		return stat;
	}

	memcpy(stat->err_msg, status_msg, strlen(status_msg));
	stat->err_msg[strlen(status_msg)] = '\n';
	stat->err_msg[strlen(status_msg)+1] = '\0';

	return stat;
}

/*
 * Reinit temporaly data of current stream
 */
static void http_status_reinit(struct http_ctx *ctx, int stream_id)
{
	ctx->incomplete_stream = -1;
	ctx->current_method = HTTP_METHOD_NONE;
	ctx->current_stream = NULL;
	ctx->buf_pos = 0;
	if (ctx->content_type) {
		free(ctx->content_type);
		ctx->content_type = NULL;
	}
}

static void http_status_reinit_error(struct http_ctx *ctx, int stream_id)
{

	if (ctx->current_method == HTTP_METHOD_POST)
		queue_pop(ctx->streams);

	http_status_reinit(ctx, stream_id);
}

/*
 * Check endpoint and uri path
 */
static int check_uri(struct http_ctx *ctx, int32_t stream_id, const char* uri_path)
{
	static const char key[] = "dns=";
	static const char *delim = "&";
	static const char *endpoins[] = {"dns-query", "doh"};
	char *beg;
	char *end_prev;
	ssize_t endpoint_len;
	ssize_t ret;
	struct http_stream_status *stat;

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
	for(int i = 0; i < sizeof(endpoins)/sizeof(*endpoins); i++)
	{
		if (strlen(endpoins[i]) != endpoint_len)
			continue;
		ret = strncmp(path + 1, endpoins[i], strlen(endpoins[i]));
		if (!ret)
			break;
	}

	if (ret) { /* no endpoint found */
		stat = set_error_status(ctx, stream_id, 400, "missing endpoint");
		return stat ? kr_error(EINVAL) : kr_error(ENOMEM);
	}
	if (endpoint_len == strlen(path) - 1) /* done for POST method */
		return 0;

	/* go over key:value pair */
	beg = strtok(query_mark + 1, delim);
	if (beg) {
		while (beg != NULL) {
			if (!strncmp(beg, key, 4)) { /* dns variable in path found */
				break;
			}
			end_prev = beg + strlen(beg) - 1;
			beg = strtok(NULL, delim);
			if (beg && beg-1 != end_prev+1) { /* detect && */
				stat = set_error_status(ctx, stream_id, 400, "invalid uri path");
				return stat ? kr_error(EINVAL) : kr_error(ENOMEM);
			}
		}

		if (!beg) { /* no dns variable in path */
			stat = set_error_status(ctx, stream_id, 400, "'dns' key in path not found");
			return stat ? kr_error(EINVAL) : kr_error(ENOMEM);
		}
	} else {
		if (!beg) { /* no dns variable in path */
			stat = set_error_status(ctx, stream_id, 400, "'dns' key in path not found");
			return stat ? kr_error(EINVAL) : kr_error(ENOMEM);
		}
	}

	return 0;
}


/*
 * Process a query from URI path if there's base64url encoded dns variable.
 */
static int process_uri_path(struct http_ctx *ctx, int32_t stream_id)
{
	static const char key[] = "dns=";
	char *beg, *end;
	size_t remaining;
	ssize_t ret;
	uint8_t *dest;
	struct http_stream_status *stat;

	if (!ctx || !ctx->uri_path) {
		stat = set_error_status(ctx, stream_id, 400, "invalid uri path");
		return stat ? 0 : kr_error(ENOMEM);
	}

	beg = strstr(ctx->uri_path, key);
	if (!beg) {  /* No dns variable in ctx->uri_path. */
		stat = set_error_status(ctx, stream_id, 400, "'dns' key in path not found");
		return stat ? 0 : kr_error(ENOMEM);
	}

	beg += sizeof(key) - 1;
	end = strchr(beg, '&');
	if (end == NULL)
		end = beg + strlen(beg);

	ctx->buf_pos = sizeof(uint16_t);  /* Reserve 2B for dnsmsg len. */
	remaining = ctx->buf_size - ctx->submitted - ctx->buf_pos;
	dest = ctx->buf + ctx->buf_pos;

	ret = kr_base64url_decode((uint8_t*)beg, end - beg, dest, remaining);
	if (ret < 0) {
		ctx->buf_pos = 0;
		kr_log_verbose("[http] base64url decode failed %s\n", strerror(ret));
		if (ret == KNOT_ERANGE) {
			stat = set_error_status(ctx, stream_id, 414, NULL);// ? ;
		} else {
			stat = set_error_status(ctx, stream_id, 400, NULL);
		}
		return stat ? 0 : kr_error(ENOMEM);
	}

	ctx->buf_pos += ret;
	queue_push(ctx->streams, stream_id);
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
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	int32_t stream_id = frame->hd.stream_id;

	if (frame->hd.type != NGHTTP2_HEADERS ||
		frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
		return 0;
	}

	if (ctx->incomplete_stream != -1) {
		kr_log_verbose(
			"[http] stream %d incomplete\n", ctx->incomplete_stream);
		if (!set_error_status(ctx, stream_id, 501, "incomplete stream"))
			return NGHTTP2_ERR_CALLBACK_FAILURE;
	} else {
		ctx->current_stream = set_error_status(ctx, stream_id, 200, NULL);
		ctx->incomplete_stream = stream_id;
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
		kr_log_verbose(
			"[http] stream %d incomplete\n", ctx->incomplete_stream);
		if (!set_error_status(ctx, stream_id, 501, "incomplete stream"))
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		return 0;
	}

	if (!strcasecmp(":path", (const char *)name)) {
		int rc = check_uri(ctx, stream_id, (const char *)value);
		if (rc < 0) {
			if (rc == kr_error(ENOMEM))
				return NGHTTP2_ERR_CALLBACK_FAILURE;
		} else {
			ctx->uri_path = malloc(sizeof(*ctx->uri_path) * (valuelen + 1));
			if (!ctx->uri_path)
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			memcpy(ctx->uri_path, value, valuelen);
			ctx->uri_path[valuelen] = '\0';
		}
	}

	if (!strcasecmp(":method", (const char *)name)) {
		if (!strcasecmp("get", (const char *)value)) {
			ctx->current_method = HTTP_METHOD_GET;
		} else if (!strcasecmp("post", (const char *)value)) {
			ctx->current_method = HTTP_METHOD_POST;
		} else {
			ctx->current_method = HTTP_METHOD_NONE;
		}
	}

	if (!strcasecmp("content-type", (const char *)name)) {
		ctx->content_type = malloc(sizeof(*ctx->content_type) * valuelen+1);
		if (!ctx->content_type)
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		memcpy(ctx->content_type, value, valuelen);
		ctx->content_type[valuelen] = '\0';
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
	bool is_first = queue_len(ctx->streams) == 0 || queue_tail(ctx->streams) != ctx->incomplete_stream;

	if (ctx->incomplete_stream != stream_id) {
		kr_log_verbose(
			"[http] stream %d incomplete\n",
			ctx->incomplete_stream);
		if (!set_error_status(ctx, stream_id, 501, "incomplete stream"))
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		return 0;
	}

	remaining = ctx->buf_size - ctx->submitted - ctx->buf_pos;
	required = len;
	/* First data chunk of the new stream */
	if (is_first)
		required += sizeof(uint16_t);

	if (required > remaining) {
		kr_log_error("[http] insufficient space in buffer\n");
		if (!set_error_status(ctx, stream_id, 413, NULL)) {
			http_status_reinit_error(ctx, stream_id);
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
		return 0;
	}

	if (is_first) {
		ctx->buf_pos = sizeof(uint16_t);  /* Reserve 2B for dnsmsg len. */
		queue_push(ctx->streams, stream_id);
	}

	memmove(ctx->buf + ctx->buf_pos, data, len);
	ctx->buf_pos += len;
	return 0;
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
	ssize_t len;
	int32_t stream_id = frame->hd.stream_id;
	assert(stream_id != -1);

	if (stream_id == 0 || ctx == NULL)
		return 0;

	if (ctx->current_method == HTTP_METHOD_NONE) {
		kr_log_verbose("[http] unsupported HTTP method\n");
		if (!set_error_status(ctx, stream_id, 405, "only HTTP POST and GET are supported\n")) {
			http_status_reinit_error(ctx, stream_id);
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}

	if (ctx->content_type && strcasecmp("application/dns-message", (const char *)ctx->content_type)) {
		kr_log_verbose("[http] unsupported content-type %s\n", ctx->content_type);
		if (!set_error_status(ctx, stream_id, 415, "only Content-Type: application/dns-message is supported\n")) {
			http_status_reinit_error(ctx, stream_id);
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}

	if (frame && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
		struct http_stream_status *stat = ctx->current_stream;
		if (ctx->incomplete_stream == stream_id) {
			if (stat->err_status == 200) {
				if (ctx->current_method == HTTP_METHOD_GET) {
					if (process_uri_path(ctx, stream_id) < 0) {
						http_status_reinit_error(ctx, stream_id);
						return NGHTTP2_ERR_CALLBACK_FAILURE;
					}
				}
				free(ctx->uri_path);
				ctx->uri_path = NULL;

				if (ctx->buf_pos) {
					len = ctx->buf_pos - sizeof(uint16_t);
					if (len <= 0 || len > KNOT_WIRE_MAX_PKTSIZE) {
						kr_log_verbose("[http] invalid dnsmsg size: %zd B\n", len);
						http_status_reinit_error(ctx, stream_id);
						return NGHTTP2_ERR_CALLBACK_FAILURE;
					}

					if (len < 12) {
						if (!set_error_status(ctx, stream_id, 400, "input too short\n")) {
							http_status_reinit_error(ctx, stream_id);
							return NGHTTP2_ERR_CALLBACK_FAILURE;
						}
					}

					if (stat->err_status == 200) {
						knot_wire_write_u16(ctx->buf, len);
						ctx->submitted += ctx->buf_pos;
						ctx->buf += ctx->buf_pos;
					}
				}
			}

			if (stat->err_status != 200) {
				if (send_err_status(ctx, stream_id) < 0) {
					http_status_reinit_error(ctx, stream_id);
					return NGHTTP2_ERR_CALLBACK_FAILURE;
				}
			}

			http_status_reinit(ctx, stream_id);
			ctx->buf_pos = 0;
		} else {
			/* send error for non-processed stream */
			if (send_err_status(ctx, stream_id) < 0) {
				http_status_reinit_error(ctx, stream_id);
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			}
		}
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

/*
 * Cleanup for closed steams.
 *
 * If any stream_user_data was set, call the on_write callback to allow
 * freeing of the underlying data structure.
 */
static int on_stream_close_callback(nghttp2_session *h2, int32_t stream_id,
				    uint32_t error_code, void *user_data)
{
	struct http_data *data;

	data = nghttp2_session_get_stream_user_data(h2, stream_id);
	if (data)
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

	nghttp2_session_callbacks_new(&callbacks);
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
	ctx->incomplete_stream = -1;
	ctx->current_stream = NULL;
	ctx->submitted = 0;
	ctx->current_method = HTTP_METHOD_NONE;
	ctx->uri_path = NULL;
	ctx->content_type = NULL;
	array_init(ctx->stream_status);


	nghttp2_session_server_new(&ctx->h2, callbacks, ctx);
	nghttp2_submit_settings(ctx->h2, NGHTTP2_FLAG_NONE,
		iv, sizeof(iv)/sizeof(*iv));
finish:
	nghttp2_session_callbacks_del(callbacks);
	return ctx;
}

/*
 * Process inbound HTTP/2 data and return number of bytes read into session wire buffer.
 *
 * This function may trigger outgoing HTTP/2 data, such as stream resets, window updates etc.
 */
ssize_t http_process_input_data(struct session *session, const uint8_t *buf,
				ssize_t nread)
{
	struct http_ctx *ctx = session_http_get_server_ctx(session);
	ssize_t ret = 0;

	if (!ctx->h2)
		return kr_error(ENOSYS);
	assert(ctx->session == session);

	ctx->submitted = 0;
	ctx->buf = session_wirebuf_get_free_start(session);
	ctx->buf_pos = 0;
	ctx->buf_size = session_wirebuf_get_free_size(session);

	ret = nghttp2_session_mem_recv(ctx->h2, buf, nread);
	if (ret < 0) {
		kr_log_verbose("[http] nghttp2_session_mem_recv failed: %s (%zd)\n",
			       nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	ret = nghttp2_session_send(ctx->h2);
	if (ret < 0) {
		kr_log_verbose("[http] nghttp2_session_send failed: %s (%zd)\n",
			     nghttp2_strerror(ret), ret);
		return kr_error(EIO);
	}

	return ctx->submitted;
}

/*
 * Send dns response provided by the HTTTP/2 data provider.
 *
 * Data isn't guaranteed to be sent immediately due to underlying HTTP/2 flow control.
 */
static int http_send_response(nghttp2_session *h2, int32_t stream_id,
			      nghttp2_data_provider *prov)
{
	struct http_data *data = (struct http_data*)prov->source.ptr;
	int ret;
	const char *directive_max_age = "max-age=";
	char size[MAX_DECIMAL_LENGTH(data->len)] = { 0 };
	int max_age_len = MAX_DECIMAL_LENGTH(data->ttl) + strlen(directive_max_age);
	char max_age[max_age_len];
	int size_len;

	memset(max_age, 0, max_age_len * sizeof(*max_age));
	size_len = snprintf(size, MAX_DECIMAL_LENGTH(data->len), "%zu", data->len);
	max_age_len = snprintf(max_age, max_age_len, "%s%u", directive_max_age, data->ttl);

	nghttp2_nv hdrs[] = {
		MAKE_STATIC_NV(":status", "200"),
		MAKE_STATIC_NV("content-type", "application/dns-message"),
		MAKE_NV("content-length", 14, size, size_len),
		MAKE_NV("cache-control", 13, max_age, max_age_len),
	};

	ret = nghttp2_submit_response(h2, stream_id, hdrs, sizeof(hdrs)/sizeof(*hdrs), prov);
	if (ret != 0) {
		kr_log_verbose("[http] nghttp2_submit_response failed: %s\n", nghttp2_strerror(ret));
		return kr_error(EIO);
	}

	ret = nghttp2_session_set_stream_user_data(h2, stream_id, (void*)data);
	if (ret != 0) {
		kr_log_verbose("[http] failed to set stream user data: %s\n", nghttp2_strerror(ret));
		return kr_error(EIO);
	}

	ret = nghttp2_session_send(h2);
	if(ret < 0) {
		kr_log_verbose("[http] nghttp2_session_send failed: %s\n", nghttp2_strerror(ret));
		return kr_error(EIO);
	}

	return 0;
}

/*
 * Send HTTP/2 stream data created from packet's wire buffer.
 */
static int http_write_pkt(nghttp2_session *h2, knot_pkt_t *pkt, int32_t stream_id,
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

	return http_send_response(h2, stream_id, &prov);
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

	ret = http_write_pkt(ctx->h2, pkt, stream_id, req, on_write);
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

	while(ctx->stream_status.len)
		http_status_remove(ctx, ctx->stream_status.at[0]);
	array_clear(ctx->stream_status);

	queue_deinit(ctx->streams);
	nghttp2_session_del(ctx->h2);
	free(ctx->content_type);
	free(ctx);
}
