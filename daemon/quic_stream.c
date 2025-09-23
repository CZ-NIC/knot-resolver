/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <libknot/wire.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "quic_stream.h"
#include "lib/defines.h"
#include "mempattern.h"
#include "quic_conn.h"
#include "session2.h"
#include <ngtcp2/ngtcp2.h>
#include <string.h>
#include <sys/socket.h>

static enum protolayer_iter_cb_result pl_quic_stream_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	struct pl_quic_stream_sess_data *stream = sess_data;

	if (stream->incflags & NGTCP2_STREAM_DATA_FLAG_FIN) {
		ctx->payload = protolayer_payload_wire_buf(&stream->pers_inbuf, false);
		return protolayer_continue(ctx);
	} else {
		// TODO: store the data and wait for fin
		kr_log_info(DOQ, "pl_quic_stream awaits more data\n");
		kr_require(false);
		return protolayer_async();
	}

	return protolayer_break(ctx, kr_error(EINVAL));
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

	struct wire_buf *wb = mm_calloc(&ctx->pool, sizeof(struct wire_buf), 1);
	kr_require(wb);
	wb->buf = mm_calloc(&ctx->pool, 1200/* FIXME: */, 1);
	kr_require(wb->buf);
	wb->size = 1200/* FIXME: */;

	// wire_buf_init(wb, 1200/* FIXME: */);
	ctx->payload = protolayer_payload_wire_buf(wb, false);

	size_t uf = stream->unsent_offset;
	struct kr_quic_obuf *uo = stream->unsent_obuf;
	if (uo == NULL /* TODO: investigate if possible */) {
		kr_require(false);/* sanity for now FIXME: remove! */
		return protolayer_break(ctx, kr_ok());
	}

	bool fin = (((node_t *)uo->node.next)->next == NULL)/* && ignore_last == 0 */;
	int nwrite = send_stream(stream, ctx, uo->buf + uf, uo->len - uf - 0/* ignore_last*/,
			fin, &sent);

	// int nwrite = send_stream(stream, ctx, wire_buf_data(&stream->pers_inbuf),
	// 		wire_buf_data_length(&stream->pers_inbuf), true/*fin*/, &sent);
	if (nwrite <= 0) {
		kr_log_error(DOQ, "send_stream failed %s (%d)\n",
				ngtcp2_strerror(nwrite), nwrite);
	}

	kr_log_info(DOQ, "send_stream seemingly succeded %d\n", nwrite);
	return protolayer_continue(ctx);
}

static int send_stream(struct pl_quic_stream_sess_data *stream,
		struct protolayer_iter_ctx *ctx,
		// struct protolayer_payload *outwb,
		uint8_t *data, size_t len, bool fin, ngtcp2_ssize *sent)
{
	int64_t stream_id = stream->stream_id;
	uint32_t fl = ((stream_id >= 0 && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN
					       : NGTCP2_WRITE_STREAM_FLAG_NONE);
	ngtcp2_vec vec = { .base = data, .len = len };
	ngtcp2_pkt_info pi = { 0 };

	const ngtcp2_path *path = ngtcp2_conn_get_path(stream->conn);

	ngtcp2_conn_info info = { 0 };
	ngtcp2_conn_get_conn_info(stream->conn, &info);

	int nwrite = ngtcp2_conn_writev_stream(stream->conn, path, &pi,
			wire_buf_free_space(ctx->payload.wire_buf),
			wire_buf_free_space_length(ctx->payload.wire_buf),
			sent, fl, stream_id, &vec,
			(stream_id >= 0 ? 1 : 0), quic_timestamp());
	if (*sent > 0) {
		vec.len -= *sent;
	}

	/* TODO:
	 * This packet may contain frames other than STREAM frame. The
	 * packet might not contain STREAM frame if other frames
	 * occupy the packet. In that case, *pdatalen would
	 * be -1 if pdatalen is not NULL. */
	if (nwrite <= 0) {
		if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
			/* TODO: deal with stream closure */
		}

		return nwrite < 0 ? nwrite : kr_error(ENODATA);
	}

	if (*sent < 0) {
		*sent = 0;
	}

	kr_require(wire_buf_consume(ctx->payload.wire_buf, nwrite) == kr_ok());
	return nwrite;
}

/* Function for sending speciall packets, requires
 * a message (which special data are we to send: CONN_CLOSE, RESET, ...)
 * and a buffer to store the pkt in, for now ctx->payloay.wb
 * For now only kr_quic_send ever call send_special, though this might prove
 * to cause issues in situation where the connection has NOT been established
 * and we still would like to send data (i.e. we do not have decoded cids)
 * The only time we need to send_special without having at least the cids
 * is then the decode_v_cid fails with NGTCP2_ERR_VERSION_NEGOTIATION */
static int send_special(struct pl_quic_conn_sess_data *conn,
		struct protolayer_iter_ctx *ctx,
		/*kr_quic_table_t *quic_table, */ int action)
		/* ngtcp2_version_cid *decoded_cids) */
		// kr_quic_conn_t *relay /* only for connection close */)
{
	if (wire_buf_data_length(ctx->payload.wire_buf) != 0) {
		kr_log_error(DOQ, "wire_buf in quic/send_special is expected to be empty\n");
		return kr_error(EINVAL);
	}

	uint64_t now = quic_timestamp();
	int dvc_ret = NGTCP2_ERR_FATAL;

	// if ((message == -QUIC_SEND_VERSION_NEGOTIATION
	// 		|| message == -QUIC_SEND_RETRY)
	// 		&& rpl->in_payload != NULL && rpl->in_payload->iov_len > 0) {
	// 	dvc_ret = ngtcp2_pkt_decode_version_cid(
	// 		&decoded_cids, rpl->in_payload->iov_base,
	// 		rpl->in_payload->iov_len, SERVER_DEFAULT_SCIDLEN);
	// }

	uint8_t rnd = 0;
	dnssec_random_buffer(&rnd, sizeof(rnd));
	uint32_t supported_quic[1] = { NGTCP2_PROTO_VER_V1 };
	ngtcp2_cid new_dcid;
	uint8_t retry_token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN];
	uint8_t stateless_reset_token[NGTCP2_STATELESS_RESET_TOKENLEN];
	uint8_t sreset_rand[NGTCP2_MIN_STATELESS_RESET_RANDLEN];
	dnssec_random_buffer(sreset_rand, sizeof(sreset_rand));
	ngtcp2_ccerr ccerr;
	ngtcp2_ccerr_default(&ccerr);
	ngtcp2_pkt_info pi = { 0 };

	// struct sockaddr_storage path_loc = { 0 }, path_rem = { 0 };
	// ngtcp2_path path = { .local  = { .addr = (struct sockaddr *)&path_loc, .addrlen = sizeof(path_loc) },
	//                      .remote = { .addr = (struct sockaddr *)&path_rem, .addrlen = sizeof(path_rem) },
	//                      .user_data = NULL };
	// ??
	// bool find_path = (rpl->ip_rem == NULL);
	// ??
	// assert(find_path == (bool)(rpl->ip_loc == NULL));
	// ??
	// assert(!find_path || rpl->handle_ret == -QUIC_SEND_EXCESSIVE_LOAD);

	int ret = 0;
	switch (action) {
	case -QUIC_SEND_VERSION_NEGOTIATION:
		ret = ngtcp2_pkt_write_version_negotiation(
			wire_buf_free_space(ctx->payload.wire_buf),
			wire_buf_free_space_length(ctx->payload.wire_buf),
			rnd, conn->dec_cids.scid, conn->dec_cids.scidlen,
			conn->dec_cids.dcid, conn->dec_cids.dcidlen, supported_quic,
			sizeof(supported_quic) / sizeof(*supported_quic)
		);
		break;

	/* Returned by ngtcp2_conn_read_pkt
	 * Server must perform address validation by sending Retry packet
	 * (see `ngtcp2_crypto_write_retry` and `ngtcp2_pkt_write_retry`),
	 * and discard the connection state.  Client application does not
	 * get this error code. */
	case -QUIC_SEND_RETRY:
		// ngtcp2_cid_init(&dcid, decoded_cids->dcid, decoded_cids->dcidlen);
		// ngtcp2_cid_init(&scid, decoded_cids->scid, decoded_cids->scidlen);
		if (!conn || !ctx->comm || ! ctx->comm->target) {
			kr_log_error(DOQ, "unable to send Retry packet due to missing data\n");
			// return kr_error(EINVAL);
			break;
		}

		kr_require(conn && ctx->comm->target);
		ngtcp2_addr remote = ngtcp2_conn_get_path(conn->conn)->remote;
		struct quic_target *target = ctx->comm->target;
		// TODO:
		// init_random_cid(&new_dcid, 0);

		/* FIXME: quic_table will probably not be available here, and
		 * if it will be it shall be in pl_quic_conn_sess_data */
		// ret = ngtcp2_crypto_generate_retry_token(
		// 	retry_token, (const uint8_t *)quic_table->hash_secret,
		// 	sizeof(quic_table->hash_secret), decoded_cids->version,
		// 	(const struct sockaddr *)remote.addr, remote.addrlen,
		// 	&new_dcid, &target->dcid, now
		// );

		if (ret >= 0) {
			ret = ngtcp2_crypto_write_retry(
				wire_buf_free_space(ctx->payload.wire_buf),
				wire_buf_free_space_length(ctx->payload.wire_buf),
				conn->dec_cids.version, &conn->scid,
				&new_dcid, &conn->dcid,
				retry_token, ret
			);
			if (ret == -1) {
				// TODO
			}
		} else {
			kr_log_error(DOQ, "failed to generate Retry token\n");
			// return kr_error(ret);
		}
		break;
	case -QUIC_SEND_STATELESS_RESET:
		ret = ngtcp2_pkt_write_stateless_reset(
			wire_buf_free_space(ctx->payload.wire_buf),
			wire_buf_free_space_length(ctx->payload.wire_buf),
			stateless_reset_token, sreset_rand, sizeof(sreset_rand)
		);
		break;
	case -QUIC_SEND_CONN_CLOSE:
		ret = ngtcp2_conn_write_connection_close(
			conn->conn, NULL, &pi,
			wire_buf_free_space(ctx->payload.wire_buf),
			wire_buf_free_space_length(ctx->payload.wire_buf),
			&ccerr, now
		);
		break;
	case -QUIC_SEND_EXCESSIVE_LOAD:
		ccerr.type = NGTCP2_CCERR_TYPE_APPLICATION;
		ccerr.error_code = KR_QUIC_ERR_EXCESSIVE_LOAD;
		ret = ngtcp2_conn_write_connection_close(
			conn->conn,
			/* can this contain nonsence data? */
			ngtcp2_conn_get_path(conn->conn),
			&pi,
			wire_buf_free_space(ctx->payload.wire_buf),
			wire_buf_free_space_length(ctx->payload.wire_buf),
			&ccerr, now
		);
		break;
	default:
		ret = kr_error(EINVAL);
		break;
	}

	if (ret < 0) {
		wire_buf_reset(ctx->payload.wire_buf);
	} else {
		// if (wire_buf_consume(ctx->payload.wire_buf, ret) == kr_ok()) {
		// 	int wrap_ret = session2_wrap_after(ctx->session,
		// 			PROTOLAYER_TYPE_QUIC, ctx->payload, ctx->comm,
		// 			// PROTOLAYER_TYPE_QUIC_CONN, ctx->payload, ctx->comm,
		// 			ctx->finished_cb, ctx->finished_cb_baton);
		// 	if (wrap_ret < 0) {
		// 		ret = wrap_ret;
		// 	}
		//
		// } else {
		// 	kr_log_error(DOQ, "Wire_buf failed to consume: %s (%d)\n",
		// 			ngtcp2_strerror(ret), ret);
		// 	// goto exit;
		// }
	}

	return ret;
}

void kr_quic_stream_mark_sent(struct pl_quic_stream_sess_data *stream,
		int64_t stream_id/*redundant*/, size_t amount_sent)
{
	kr_require(stream);

	stream->unsent_offset += amount_sent;
	assert(stream->unsent_offset <= stream->unsent_obuf->len);
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

/* FIXME: move or remove */
#define OUTBUF_SIZE 1200

static int pl_quic_stream_sess_init(struct session2 *session,
		void *sess_data, void *param)
{
	struct pl_quic_stream_sess_data *stream = sess_data;
	stream->h.session = session;

	wire_buf_init(&stream->pers_inbuf, OUTBUF_SIZE);

	session->secure = true;
	queue_init(stream->wrap_queue);
	queue_init(stream->unwrap_queue);

	kr_require(param);
	struct kr_quic_stream_param *p = param;
	stream->conn = p->conn;
	stream->stream_id = p->stream_id;
	stream->firstib_consumed = 0;
	stream->comm_storage = p->comm_storage;

	size_t new_streams_count;
	struct kr_quic_stream *new_streams;


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

	// version 2
	while (!EMPTY_LIST(*obs) && end_acked >=
			(first = HEAD(*obs))->len + stream->first_offset) {
		rem_node(&first->node);
		assert(HEAD(*obs) != first); // help CLANG analyzer understand
					     // what rem_node did and that
					     // usage of HEAD(*obs) is safe
		stream->obufs_size -= first->len;
		// conn->obufs_size -= first->len;
		// conn->quic_table->obufs_size -= first->len;
		stream->first_offset += first->len;
		free(first);
		if (stream->unsent_obuf == first) {
			stream->unsent_obuf =
				EMPTY_LIST(*obs) == 0 ? NULL : HEAD(*obs);
			stream->unsent_offset = 0;
		}
	}

	// if (EMPTY_LIST(*obs) && !keep_stream) {
	// 	stream_outprocess(conn, stream);
	// 	memset(stream, 0, sizeof(*stream));
	// 	init_list(&stream->outbufs);
	// 	while (s = &conn->streams[0],
	// 			wire_buf_data_length(&stream->pers_inbuf) == 0 &&
	// 			stream->obufs_size == 0) {
	// 		kr_assert(conn->streams_count > 0);
	// 		conn->streams_count--;
	//
	// 		if (conn->streams_count == 0) {
	// 			free(conn->streams);
	// 			conn->streams = 0;
	// 			conn->first_stream_id = 0;
	// 			break;
	// 		} else {
	// 			conn->first_stream_id++;
	// 			conn->stream_inprocesstream--;
	// 			memmove(s, s + 1, sizeof(*s) * conn->streams_count);
	// 			// possible realloc to shrink allocated space,
	// 			// but probably useless
	// 			for (struct kr_quic_stream *si = s;
	// 					si < s + conn->streams_count;
	// 					si++) {
	// 				if (si->obufs_size == 0) {
	// 					init_list(&si->outbufs);
	// 				} else {
	// 					fix_list(&si->outbufs);
	// 				}
	// 			}
	// 		}
	// 	}
	// }
}

int update_stream_pers_buffer(struct pl_quic_stream_sess_data *stream,
		const uint8_t *data, size_t len, int64_t stream_id)
{
	kr_require(len > 0 && data && stream);

	if (wire_buf_free_space_length(&stream->pers_inbuf) < len) {
		kr_log_error(DOQ, "wire buf for stream no. %ld ran out of available space; needed: %zu, available: %zu\n",
				stream_id, len,
				wire_buf_free_space_length(&stream->pers_inbuf));
		return kr_error(ENOMEM);
	}

	// Assert would be better, this happenning is most likely a mistake */
	// kr_require(wire_buf_data_length(&stream->pers_inbuf) == 0);

	memcpy(wire_buf_free_space(&stream->pers_inbuf), data, len);
	/* FIXME reqire for now, though this is hardly the desired check */
	kr_require(wire_buf_consume(&stream->pers_inbuf, len) == kr_ok());

	return kr_ok();
}

static int pl_quic_stream_sess_deinit(struct session2 *session, void *sess_data)

{
	struct pl_quic_stream_sess_data *stream = sess_data;
	kr_quic_stream_ack_data(stream, stream->stream_id, SIZE_MAX, false);
	queue_deinit(stream->wrap_queue);
	queue_deinit(stream->unwrap_queue);
	wire_buf_deinit(&stream->pers_inbuf);

	WALK_LIST_FREE(stream->outbufs);

	/* FIXME: empty queues and free the rest */

	// wire_buf_deinit(&stream->unwrap_buf);

	return kr_ok();

	// pl_quic_sess_data_t *quic = data;
	// queue_deinit(quic->unwrap_queue);
	// queue_deinit(quic->wrap_queue);
	// kr_quic_table_free(quic->conn_table);
	// wire_buf_deinit(&quic->outbuf);
	//
	// return kr_ok();
}

static enum protolayer_event_cb_result pl_quic_stream_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	struct pl_quic_stream_sess_data *stream = sess_data;
	kr_log_info(DOQ, "entered QUIC STREAM E UNWRAP stream_id: %ld\n",
			stream->stream_id);

	if (event == PROTOLAYER_EVENT_CLOSE) {
		pl_quic_stream_sess_deinit(session, sess_data);
		return PROTOLAYER_EVENT_CONSUME;
	}

	return PROTOLAYER_EVENT_CONSUME;
}

static enum protolayer_event_cb_result pl_quic_stream_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	// session2_waitinglist_finalize(session, 0/* FIXME */);

	struct pl_quic_stream_sess_data *stream = sess_data;
	kr_log_info(DOQ, "entered QUIC STREAM E WRAP stream_id: %ld\n",
			stream->stream_id);

	/* TODO: force and normal should differ */
	if (event == PROTOLAYER_EVENT_CLOSE) {
		// pl_quic_stream_sess_deinit(session, sess_data);
		return PROTOLAYER_EVENT_PROPAGATE;
		// return PROTOLAYER_EVENT_CONSUME;
	}
	if (event == PROTOLAYER_EVENT_FORCE_CLOSE) {
		// pl_quic_stream_sess_deinit(session, sess_data);
		return PROTOLAYER_EVENT_PROPAGATE;
		// return PROTOLAYER_EVENT_CONSUME;
	}

	return PROTOLAYER_EVENT_PROPAGATE;
	// return PROTOLAYER_EVENT_CONSUME;
}

// static void pl_quic_request_init(struct session2 *session,
// 		struct kr_request *req, void *sess_data)
// {
// 	kr_log_warning(DOQ, "IN request init\n");
// 	req->qsource.comm_flags.quic = true;
// 	// struct pl_quic_sess_data *quic = sess_data;
// 	// quic->req = req;
//
// 	// req->qsource.stream_id = session->comm_storage.target;
// }

__attribute__((constructor))
static void quic_conn_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_QUIC_STREAM] = (struct protolayer_globals) {
		.sess_size = sizeof(struct pl_quic_stream_sess_data),
		// .iter_size = sizeof(struct ),
		.wire_buf_overhead = MAX_QUIC_FRAME_SIZE,
		// .iter_init = pl_quic_iter_init,
		// .iter_deinit = pl_quic_iter_deinit,
		.sess_init = pl_quic_stream_sess_init,
		.sess_deinit = pl_quic_stream_sess_deinit,
		.unwrap = pl_quic_stream_unwrap,
		.wrap = pl_quic_stream_wrap,
		.event_unwrap = pl_quic_stream_event_unwrap,
		.event_wrap = pl_quic_stream_event_wrap,
		// .request_init = pl_quic_request_init,
	};
}
