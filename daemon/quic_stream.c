/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/resolve.h"
#include "quic_common.h"
#include "quic_conn.h"
#include "session2.h"
#include <ngtcp2/ngtcp2.h>
#include "quic_stream.h"

#define OUTBUF_SIZE 4096

/* forward declaration */
static int send_stream(struct pl_quic_stream_sess_data *stream,
		struct protolayer_iter_ctx *ctx, uint8_t *data,
		size_t len, bool fin, ngtcp2_ssize *sent);

static enum protolayer_iter_cb_result pl_quic_stream_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	struct pl_quic_stream_sess_data *stream = sess_data;

	if (!(stream->incflags & NGTCP2_STREAM_DATA_FLAG_FIN)) {
		return protolayer_break(ctx, kr_error(EINVAL));
	}

	kr_assert(stream->incflags & NGTCP2_STREAM_DATA_FLAG_FIN);
	ctx->payload = protolayer_payload_wire_buf(&stream->pers_inbuf, false);
	return protolayer_continue(ctx);
}

uint8_t *kr_quic_stream_add_data(struct pl_quic_stream_sess_data *s,
		   uint8_t *data, size_t len)
{
	if (s == NULL) {
		return NULL;
	}

	size_t prefix = sizeof(uint16_t);

	struct kr_quic_obuf *obuf = malloc(sizeof(*obuf) + prefix + len);
	if (obuf == NULL) {
		return NULL;
	}

	obuf->len = len + prefix;
	knot_wire_write_u16(obuf->buf, len);
	if (data != NULL) {
		memcpy(obuf->buf + prefix, data, len);
	}

	list_t *list = (list_t *)&s->outbufs;
	if (EMPTY_LIST(*list)) {
		s->unsent_obuf = obuf;
	}
	add_tail((list_t *)&s->outbufs, (node_t *)obuf);
	s->obufs_size += obuf->len;

	return obuf->buf + prefix;
}

static enum protolayer_iter_cb_result pl_quic_stream_wrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	kr_require(ctx->payload.type = PROTOLAYER_PAYLOAD_IOVEC);
	struct pl_quic_stream_sess_data *stream = sess_data;
	kr_require(stream->stream_id >= 0);
	ngtcp2_ssize sent = 0;

	kr_quic_stream_add_data(stream, ctx->payload.iovec.iov[1].iov_base,
			ctx->payload.iovec.iov[1].iov_len);

	ctx->payload = protolayer_payload_wire_buf(&stream->outbuf, false);

	size_t uf = stream->unsent_offset;
	struct kr_quic_obuf *uo = stream->unsent_obuf;
	if (uo == NULL) {
		return protolayer_break(ctx, kr_ok());
	}

	if (wire_buf_data_length(&stream->outbuf) != 0) {
		wire_buf_reset(&stream->outbuf);
	}

	bool fin = (((node_t *)uo->node.next)->next == NULL)/* && ignore_last == 0 */;
	int nwrite = send_stream(stream, ctx, uo->buf + uf, uo->len - uf - 0/* ignore_last*/,
			fin, &sent);

	if (nwrite <= 0) {
		if (nwrite == NGTCP2_ERR_NOMEM) {
			kr_log_error(DOQ, "Insufficient memory available\n");
			return protolayer_break(ctx, kr_error(ENOMEM));
		}

		return protolayer_break(ctx, kr_ok());
	}

	return protolayer_continue(ctx);
}

static int send_stream(struct pl_quic_stream_sess_data *stream,
		struct protolayer_iter_ctx *ctx, uint8_t *data,
		size_t len, bool fin, ngtcp2_ssize *sent)
{
	if (!stream->conn_ref || !QUIC_CAN_SEND(stream->conn_ref)) {
		return protolayer_break(ctx, kr_ok());
	}

	int64_t stream_id = stream->stream_id;
	uint32_t fl = ((stream_id >= 0 && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN
					       : NGTCP2_WRITE_STREAM_FLAG_NONE);
	ngtcp2_vec vec = { .base = data, .len = len };
	ngtcp2_pkt_info pi = { 0 };

	const ngtcp2_path *path = ngtcp2_conn_get_path(stream->conn);

	ngtcp2_conn_info info = { 0 };
	ngtcp2_conn_get_conn_info(stream->conn, &info);

	int nwrite = ngtcp2_conn_writev_stream(stream->conn,
			(ngtcp2_path *)path, &pi,
			wire_buf_free_space(ctx->payload.wire_buf),
			wire_buf_free_space_length(ctx->payload.wire_buf),
			sent, fl, stream_id, &vec,
			(stream_id >= 0 ? 1 : 0), quic_timestamp());

	if (*sent > 0) {
		vec.len -= *sent;
	}

	if (nwrite <= 0) {
		return nwrite < 0 ? nwrite : kr_error(ENODATA);
	}

	if (*sent < 0) {
		*sent = 0;
	}

	kr_require(wire_buf_consume(ctx->payload.wire_buf, nwrite) == kr_ok());
	return nwrite;
}

void kr_quic_stream_mark_sent(struct pl_quic_stream_sess_data *stream,
		size_t amount_sent)
{
	kr_require(stream);

	stream->unsent_offset += amount_sent;
	kr_assert(stream->unsent_offset <= stream->unsent_obuf->len);
	if (stream->unsent_offset == stream->unsent_obuf->len) {
		stream->unsent_offset = 0;
		stream->unsent_obuf =
			(struct kr_quic_obuf *)stream->unsent_obuf->node.next;
		// already behind the tail of list
		if (stream->unsent_obuf->node.next == NULL) {
			stream->unsent_obuf = NULL;
		}
	}
}

static int pl_quic_stream_sess_init(struct session2 *session,
		void *sess_data, void *param)
{
	struct pl_quic_stream_sess_data *stream = sess_data;
	stream->h.session = session;

	wire_buf_init(&stream->pers_inbuf, OUTBUF_SIZE);
	wire_buf_init(&stream->outbuf, OUTBUF_SIZE);

	session->secure = true;

	kr_require(param);
	struct kr_quic_stream_param *p = param;
	stream->conn = p->conn;
	stream->stream_id = p->stream_id;
	stream->comm_storage = p->comm_storage;

	if (stream->obufs_size == 0) {
		init_list(&stream->outbufs);
	} else {
		fix_list(&stream->outbufs);
	}

	return kr_ok();
}

void kr_quic_stream_ack_data(struct pl_quic_stream_sess_data *stream,
		int64_t stream_id, size_t end_acked, bool keep_stream)
{
	kr_require(stream);
	struct list *obs = &stream->outbufs;

	struct kr_quic_obuf *first;

	while (!EMPTY_LIST(*obs) && end_acked >=
			(first = HEAD(*obs))->len + stream->first_offset) {
		rem_node(&first->node);
		stream->obufs_size -= first->len;
		stream->first_offset += first->len;
		free(first);
		if (stream->unsent_obuf == first) {
			stream->unsent_obuf =
				EMPTY_LIST(*obs) == 0 ? NULL : HEAD(*obs);
			stream->unsent_offset = 0;
		}
	}
}

int update_stream_pers_buffer(struct pl_quic_stream_sess_data *stream,
		const uint8_t *data, size_t len, int64_t stream_id)
{
	kr_require(len > 0 && data && stream);

	if (wire_buf_free_space_length(&stream->pers_inbuf) < len) {
		size_t inc = MIN(stream->outbuf.size, 1024);
		char *new_buf = realloc(stream->pers_inbuf.buf,
				wire_buf_data_length(&stream->pers_inbuf) + inc);
		kr_require(new_buf);
		stream->pers_inbuf.buf = new_buf;
		stream->pers_inbuf.end += inc;
		stream->pers_inbuf.size += inc;
	}

	memcpy(wire_buf_free_space(&stream->pers_inbuf), data, len);
	kr_require(wire_buf_consume(&stream->pers_inbuf, len) == kr_ok());

	return kr_ok();
}

static int pl_quic_stream_sess_deinit(struct session2 *session, void *sess_data)
{
	struct pl_quic_stream_sess_data *stream = sess_data;
	kr_require(queue_len(session->waiting) <= 0);
	kr_quic_stream_ack_data(stream, stream->stream_id, SIZE_MAX, false);
	wire_buf_deinit(&stream->pers_inbuf);
	wire_buf_deinit(&stream->outbuf);
	return kr_ok();
}

static enum protolayer_event_cb_result pl_quic_stream_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if (event == PROTOLAYER_EVENT_CLOSE) {
		session2_dec_refs(session);
		return PROTOLAYER_EVENT_CONSUME;
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

static void pl_quic_stream_request_init(struct session2 *session,
					struct kr_request *req,
					void *sess_data)
{
	req->qsource.comm_flags.quic = true;
}

__attribute__((constructor))
static void quic_conn_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_QUIC_STREAM] = (struct protolayer_globals) {
		.sess_size = sizeof(struct pl_quic_stream_sess_data),
		.sess_init = pl_quic_stream_sess_init,
		.sess_deinit = pl_quic_stream_sess_deinit,
		.unwrap = pl_quic_stream_unwrap,
		.wrap = pl_quic_stream_wrap,
		.event_unwrap = pl_quic_stream_event_unwrap,
		.request_init = pl_quic_stream_request_init,
	};
}
