/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/worker.h"
#include "quic_common.h"
#include "quic_stream.h"
#include "lib/resolve.h"
#include "mempattern.h"
#include "lib/proto.h"
#include "quic_conn.h"
#include "session2.h"
#include "network.h"
#include <asm-generic/errno.h>
#include <ngtcp2/ngtcp2.h>
#include <stdint.h>

/* forward declaration */
static int send_stream(struct pl_quic_stream_sess_data *stream,
		struct protolayer_iter_ctx *ctx, uint8_t *data,
		size_t len, bool fin, ngtcp2_ssize *sent);
void kr_quic_stream_mark_sent(struct pl_quic_stream_sess_data *stream,
		size_t amount_sent);

static enum protolayer_iter_cb_result pl_quic_stream_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	struct pl_quic_stream_sess_data *stream = sess_data;

	if (unlikely(!(stream->incflags & NGTCP2_STREAM_DATA_FLAG_FIN))) {
		return protolayer_break(ctx, kr_error(EINVAL));
	}

	ctx->payload = protolayer_payload_wire_buf(&stream->pers_inbuf, false);
	/* a reference is added for unfinished payload in client side
	 * see kr_recv_stream_data_cb */
	if (stream->h.session->outgoing) {
		session2_timer_stop(stream->h.session);
		stream->state &= ~QUIC_STREAM_HAS_TIMER;
	}
	return protolayer_continue(ctx);
}

void kr_quic_stream_mark_sent(struct pl_quic_stream_sess_data *stream,
		size_t amount_sent)
{
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

uint8_t *kr_quic_stream_add_data(struct pl_quic_stream_sess_data *s,
		   uint8_t *data, size_t len)
{
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

	if (s->obufs_size == 0) {
		/* There was no data in the buffer, increase the session ref counter
		 * to avoid destructu of the session before it is handled gracefully */
		s->state |= QUIC_STREAM_ACK_PENDING;
		// session2_inc_refs(s->h.session);
	}

	list_t *list = (list_t *)&s->outbufs;
	if (EMPTY_LIST(*list)) { // NOLINT(bugprone-casting-through-void)
		s->unsent_obuf = obuf;
	}
	add_tail((list_t *)&s->outbufs, (node_t *)obuf);
	s->obufs_size += obuf->len;

	return obuf->buf + prefix;
}

static enum protolayer_iter_cb_result pl_quic_stream_wrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	struct pl_quic_stream_sess_data *stream = sess_data;
	// FIXME: Leftover from doq-client-new, see if necessary
	//
	// /* Connection already expired, this stream exists as an orphan only
	//  * to avoid force closing leading tasks */
	// if (stream->orphan) {
	// 	return protolayer_break(ctx, kr_error(ESHUTDOWN));
	// }

	/* new data only comes as a iovec, flushing the stream with no new data
	 * to append uses wire_buf */
	if (likely(ctx->payload.type == PROTOLAYER_PAYLOAD_IOVEC)) {
		if (unlikely(kr_quic_stream_add_data(stream, ctx->payload.iovec.iov[1].iov_base,
				ctx->payload.iovec.iov[1].iov_len) == NULL)) {
			return protolayer_break(ctx, kr_error(ENOMEM));
		}

		ctx->payload = protolayer_payload_wire_buf(&stream->outbuf,
				false);
	}
	// FIXME: from doq-client-new, might be sufficient, along the stream_add_data
	//
	// kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_IOVEC);
	// ctx->payload = protolayer_payload_wire_buf(&stream->outbuf, false);

	if (wire_buf_data_length(&stream->outbuf) != 0) {
		wire_buf_reset(&stream->outbuf);
	}

	ngtcp2_ssize sent;
	uint16_t sent_msgs = 0;
	do {
		sent = 0;
		size_t uf = stream->unsent_offset;
		struct kr_quic_obuf *uo = stream->unsent_obuf;
		if (uo == NULL) {
			break;
		}

		if (wire_buf_data_length(ctx->payload.wire_buf) != 0) {
			wire_buf_reset(ctx->payload.wire_buf);
		}

		bool fin = (((node_t *)uo->node.next)->next == NULL)/* && ignore_last == 0 */;
		int nwrite = send_stream(stream, ctx, uo->buf + uf, uo->len - uf - 0/* ignore_last*/,
				fin, &sent);
		if (nwrite < 0) {
			if (nwrite == NGTCP2_ERR_NOMEM) {
				kr_log_error(DOQ, "Insufficient memory available\n");
			} else if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
				stream->write_closed = true;
			}

			return protolayer_break(ctx, kr_ok());
		}

		if (sent > 0) {
			kr_quic_stream_mark_sent(stream, sent);
		}

		if (nwrite == 0) {
			break;
		}

		sent_msgs++;

		protolayer_finished_cb finished_cb = NULL;
		void *finished_baton = NULL;
		if (sent > 0 && stream->unsent_obuf == NULL
				&& stream->h.session->outgoing) {
			finished_cb = ctx->finished_cb;
			finished_baton = ctx->finished_cb_baton;
		}

		session2_wrap_after(stream->h.session->transport.parent,
				PROTOLAYER_TYPE_QUIC_CONN,
				ctx->payload,
				ctx->comm,
				finished_cb,
				finished_baton);
	} while (sent > 0 && sent_msgs < QUIC_MAX_SEND_PER_RECV);

	if (!stream->skip_update_time) {
		ngtcp2_conn_update_pkt_tx_time(stream->conn_ref->conn,
				quic_timestamp());
	}

	return protolayer_break(ctx, kr_ok());
}

static int send_stream(struct pl_quic_stream_sess_data *stream,
		struct protolayer_iter_ctx *ctx, uint8_t *data,
		size_t len, bool fin, ngtcp2_ssize *sent)
{
	if (!stream->conn_ref || !QUIC_CAN_SEND(stream->conn_ref)) {
		return kr_error(ENODATA);
	}

	int64_t stream_id = stream->stream_id;
	uint32_t fl = ((stream_id >= 0 && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN
					       : NGTCP2_WRITE_STREAM_FLAG_NONE);
	ngtcp2_vec vec = { .base = data, .len = len };
	ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };

	if (len > wire_buf_free_space_length(&stream->outbuf)) {
		wire_buf_reserve(&stream->outbuf,
			MIN(MAX(1200, wire_buf_data_length(&stream->outbuf) + len * 2),
				MAX_QUIC_FRAME_SIZE));
	}
	if (len >= wire_buf_free_space_length(&stream->outbuf)) {
		return NGTCP2_ERR_NOMEM;
	}

	const ngtcp2_path *path = ngtcp2_conn_get_path(stream->conn);

	ngtcp2_conn_info info = { 0 };
	ngtcp2_conn_get_conn_info(stream->conn, &info);

	int nwrite = ngtcp2_conn_writev_stream(stream->conn,
			(ngtcp2_path *)path, &pi,
			wire_buf_free_space(&stream->outbuf),
			wire_buf_free_space_length(&stream->outbuf),
			sent, fl, stream_id, &vec,
			(stream_id >= 0 ? 1 : 0), quic_timestamp());

	if (nwrite <= 0) {
		/* Make sure there is nothing to send if write failed */
		wire_buf_reset(&stream->outbuf);
		return nwrite;
	}

	if (*sent < 0) {
		*sent = 0;
	}

	wire_buf_consume(&stream->outbuf, nwrite);
	return nwrite;
}

static int pl_quic_stream_sess_init(struct session2 *session,
		void *sess_data, void *param)
{
	struct pl_quic_stream_sess_data *stream = sess_data;
	stream->h.session = session;

	wire_buf_init(&stream->pers_inbuf, NGTCP2_MAX_UDP_PAYLOAD_SIZE);
	wire_buf_init(&stream->outbuf, NGTCP2_MAX_UDP_PAYLOAD_SIZE);

	session->secure = true;

	struct kr_quic_stream_param *p = param;
	stream->orphan = false;
	stream->terminated_gracefully = false;
	stream->conn = p->conn;
	stream->closed = false;
	stream->stream_id = p->stream_id;
	stream->write_closed = false;
	stream->skip_update_time = false;
	session->comm_storage = p->comm_storage;
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
	if (stream->obufs_size == 0)
		return;

	struct list *obs = &stream->outbufs;
	struct kr_quic_obuf *first;

	// NOLINTNEXTLINE(bugprone-casting-through-void)
	while (!EMPTY_LIST(*obs) && end_acked >=
			(first = HEAD(*obs))->len + stream->first_offset) {
		rem_node(&first->node);
		stream->obufs_size -= first->len;
		stream->first_offset += first->len;
		if (stream->unsent_obuf == first) {
			// NOLINTNEXTLINE(bugprone-casting-through-void)
			stream->unsent_obuf = EMPTY_LIST(*obs)
				? NULL : HEAD(*obs);
			stream->unsent_offset = 0;
		}
		free(first);
	}

	if (stream->obufs_size == 0) {
		/* The buffer is now empty, potential stream
		 * session deinit shall not be blocked by payload reference */
		stream->state &= ~QUIC_STREAM_ACK_PENDING;
		// return session2_dec_refs(stream->h.session);
	}
}

static int pl_quic_stream_sess_deinit(struct session2 *session, void *sess_data)
{
	struct pl_quic_stream_sess_data *stream = sess_data;
	kr_quic_stream_ack_data(stream, stream->stream_id, SIZE_MAX, false);

	// FIXME: Again from doq-client-new...
	//
	// rem_node(&stream->list_node);
	//
	// if (!session2_tasklist_is_empty(session)) {
	// 	/* The stream is closing without resolving the query */
	// 	session2_tasklist_finalize(session, KR_STATE_FAIL);
	// }
	//
	// kr_require(session2_tasklist_is_empty(session));
	// kr_require(session2_waitinglist_is_empty(session));

	wire_buf_deinit(&stream->pers_inbuf);
	wire_buf_deinit(&stream->outbuf);
	return kr_ok();
}

static void on_close_stream_timer(uv_handle_t *handle)
{
	struct pl_quic_stream_sess_data *stream =
		protolayer_sess_data_get_proto(handle->data,
				PROTOLAYER_TYPE_QUIC_STREAM);
	stream->state &= ~QUIC_STREAM_HAS_TIMER;
	session2_dec_refs(handle->data);
}

static enum protolayer_event_cb_result pl_quic_stream_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if (event == PROTOLAYER_EVENT_CLOSE
			|| event == PROTOLAYER_EVENT_FORCE_CLOSE) {
		struct pl_quic_stream_sess_data *stream =
			protolayer_sess_data_get_proto(session,
					PROTOLAYER_TYPE_QUIC_STREAM);
		kr_quic_stream_ack_data(stream,
				stream->stream_id,
				SIZE_MAX,
				false);
	}
	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_quic_stream_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if (event == PROTOLAYER_EVENT_STATS_SEND_ERR) {
		the_worker->stats.err_quic += 1;
	}
	if (event == PROTOLAYER_EVENT_CLOSE
			|| event == PROTOLAYER_EVENT_FORCE_CLOSE) {
		kr_require(session2_is_empty(session));
		*baton = sess_data;
	}
	return PROTOLAYER_EVENT_PROPAGATE;
}

static void pl_quic_stream_request_init(struct session2 *session,
					struct kr_request *req,
					void *sess_data)
{
	struct pl_quic_stream_sess_data *stream = sess_data;
	req->qsource.comm_flags.quic = true;
	req->qsource.stream_id = stream->stream_id;

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
		.event_wrap = pl_quic_stream_event_wrap,
		.request_init = pl_quic_stream_request_init,
	};
}
