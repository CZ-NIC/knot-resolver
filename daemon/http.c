/*
 * Copyright (C) 2020 CZ.NIC, z.s.p.o
 *
 * Initial Author: Jan Hák <jan.hak@nic.cz>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <nghttp2/nghttp2.h>
#include <uv.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon/io.h"
#include "daemon/http.h"
#include "daemon/worker.h"
#include "daemon/session.h"

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
	ssize_t ret;
	uint8_t *dest;

	if (!beg)  /* No dns variable in path. */
		return 0;

	beg += sizeof(key) - 1;
	end = strchrnul(beg, '&');
	ctx->buf_pos = sizeof(uint16_t);  /* Reserve 2B for dnsmsg len. */
	remaining = ctx->buf_size - ctx->submitted - ctx->buf_pos;
	dest = ctx->buf + ctx->buf_pos;

	ret = kr_base64url_decode((uint8_t*)beg, end - beg, dest, remaining);
	if (ret < 0) {
		ctx->buf_pos = 0;
		kr_log_verbose("[http] base64url decode failed %s\n",
			       strerror(ret));
		return ret;
	}

	ctx->buf_pos += ret;
	ctx->incomplete_stream = stream_id;
	queue_push(ctx->streams, stream_id);
	return 0;
}

static void refuse_stream(nghttp2_session *h2, int32_t stream_id)
{
	nghttp2_submit_rst_stream(
		h2, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_REFUSED_STREAM);
}

/*
 * Process a received header name-value pair.
 *
 * In DoH, GET requests contain the base64url-encoded query in dns variable present in path.
 * This variable is parsed from :path pseudoheader.
 *
 * Since we don't need any headers for POST request, avoid processing them entirely to
 * avoid potential issues if dns variable would be present in path.
 */
static int header_callback(nghttp2_session *h2, const nghttp2_frame *frame,
			   const uint8_t *name, size_t namelen, const uint8_t *value,
			   size_t valuelen, uint8_t flags, void *user_data)
{
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	int32_t stream_id = frame->hd.stream_id;

	/* If the HEADERS don't have END_STREAM set, there are some DATA frames,
	 * which implies POST method.  Skip header processing for POST. */
	if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == 0)
		return 0;

	if (!strcasecmp(":path", (const char *)name)) {
		if (ctx->incomplete_stream != -1) {
			kr_log_verbose(
				"[http] stream %d incomplete, refusing\n", ctx->incomplete_stream);
			refuse_stream(h2, stream_id);
			return 0;
		}

		if (process_uri_path(ctx, (const char*)value, stream_id) < 0)
			refuse_stream(h2, stream_id);
	}
	return 0;
}

/*
 * Process DATA chunk sent by the client (by POST method).
 *
 * We use a single DNS message buffer for the entire connection. Therefore, we
 * don't support interweaving DATA chunks from different streams. To successfully
 * parse multiple subsequent streams, each one must be fully received before
 * processing a new stream.
 */
static int data_chunk_recv_callback(nghttp2_session *h2, uint8_t flags, int32_t stream_id,
				    const uint8_t *data, size_t len, void *user_data)
{
	struct http_ctx *ctx = (struct http_ctx *)user_data;
	ssize_t remaining;
	ssize_t required;

	if (ctx->incomplete_stream != -1 && ctx->incomplete_stream != stream_id) {
		kr_log_verbose(
			"[http] stream %d incomplete, refusing\n",
			ctx->incomplete_stream);
		refuse_stream(h2, stream_id);
		return 0;
	}

	remaining = ctx->buf_size - ctx->submitted - ctx->buf_pos;
	required = len;
	if (ctx->incomplete_stream == -1)
		required += sizeof(uint16_t);

	if (required > remaining) {
		kr_log_error("[http] insufficient space in buffer\n");
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	if (ctx->incomplete_stream == -1) {
		ctx->incomplete_stream = stream_id;
		ctx->buf_pos = sizeof(uint16_t);  /* Reserve 2B for dnsmsg len. */
		queue_push(ctx->streams, stream_id);
	}

	memcpy(ctx->buf + ctx->buf_pos, data, len);
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

	if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) && ctx->incomplete_stream == stream_id) {
		ctx->incomplete_stream = -1;

		len = ctx->buf_pos - sizeof(uint16_t);
		if (len <= 0 || len > KNOT_WIRE_MAX_PKTSIZE) {
			kr_log_verbose("[http] invalid dnsmsg size: %zd B\n", len);
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}

		knot_wire_write_u16(ctx->buf, len);
		ctx->submitted += ctx->buf_pos;
		ctx->buf += ctx->buf_pos;
		ctx->buf_pos = 0;
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
	ctx->submitted = 0;

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
		kr_log_error("[http] nghttp2_session_mem_recv failed: %s (%zd)\n",
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

/*
 * Send dns response provided by the HTTTP/2 data provider.
 *
 * Data isn't guaranteed to be sent immediately due to underlying HTTP/2 flow control.
 */
static int http_send_response(nghttp2_session *h2, char *size, size_t size_len,
			      int32_t stream_id, nghttp2_data_provider *prov)
{
	int ret;
	struct http_data *data = (struct http_data*)prov->source.ptr;
	nghttp2_nv hdrs[] = {
		MAKE_STATIC_NV(":status", "200"),
		MAKE_STATIC_NV("content-type", "application/dns-message"),
		MAKE_NV("content-length", 14, size, size_len)
	};

	ret = nghttp2_submit_response(h2, stream_id, hdrs, sizeof(hdrs)/sizeof(*hdrs), prov);
	if (ret != 0) {
		kr_log_verbose("[http] nghttp2_submit_response failed: %s\n", nghttp2_strerror(ret));
		on_pkt_write(data, kr_error(EIO));
		return kr_error(EIO);
	}

	ret = nghttp2_session_set_stream_user_data(h2, stream_id, (void*)data);
	if (ret != 0) {
		kr_log_verbose("[http] failed to set stream user data: %s\n", nghttp2_strerror(ret));
		on_pkt_write(data, kr_error(EIO));
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
	char size[MAX_DECIMAL_LENGTH(pkt->size)] = { 0 };
	int size_len;
	struct http_data *data;
	nghttp2_data_provider prov;

	size_len = snprintf(size, MAX_DECIMAL_LENGTH(pkt->size), "%zu", pkt->size);

	data = malloc(sizeof(struct http_data));
	if (!data)
		return kr_error(ENOMEM);

	data->buf = pkt->wire;
	data->len = pkt->size;
	data->pos = 0;
	data->on_write = on_write;
	data->req = req;

	prov.source.ptr = data;
	prov.read_callback = read_callback;

	return http_send_response(h2, size, size_len, stream_id, &prov);
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

	queue_deinit(ctx->streams);
	nghttp2_session_del(ctx->h2);
	free(ctx);
}
