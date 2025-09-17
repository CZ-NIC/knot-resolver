/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <libknot/wire.h>
#include <openssl/ssl.h>
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

// uint64_t quic_timestamp(void)
// {
// 	struct timespec ts;
// 	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
// 		return 0;
//
// 	return ((uint64_t)ts.tv_sec * NGTCP2_SECONDS) + (uint64_t)ts.tv_nsec;
// }


int kr_quic_stream_add_data(struct pl_quic_stream_sess_data *stream,
		struct protolayer_payload *pl)
{

	kr_require(stream);

#define SIZE_PREFIX 0
#define DATA 1

	size_t prefix_size = sizeof(uint16_t);
	size_t prefix = *(uint16_t *)pl->iovec.iov[SIZE_PREFIX].iov_base;
	size_t len = pl->iovec.iov[DATA].iov_len;

	struct kr_quic_obuf *obuf = malloc(sizeof(*obuf) + prefix_size + len);
	kr_require(obuf);
	// if (!obuf)
	// 	return kr_error(ENOMEM)

	obuf->len = len + prefix_size;

	kr_require(obuf->buf);
	// memcpy(&obuf->buf, &prefix, prefix_size);
	knot_wire_write_u16(obuf->buf, prefix);
	if (len) {
		memcpy(obuf->buf + prefix_size, pl->iovec.iov[DATA].iov_base, len);
	}

#undef SIZE_PREFIX
#undef DATA

	list_t *list = (list_t *)&stream->outbufs;
	if (EMPTY_LIST(*list)) {
		stream->unsent_obuf = obuf;
	}
	add_tail((list_t *)&stream->outbufs, (node_t *)obuf);
	stream->obufs_size += obuf->len;
	// stream->quic_table->obufs_size += obuf->len;

	return len;
}

static enum protolayer_iter_cb_result pl_quic_stream_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	struct pl_quic_stream_sess_data *stream = sess_data;

	if (stream->incflags & NGTCP2_STREAM_DATA_FLAG_FIN) {
		// struct wire_buf *wb = mm_calloc(&ctx->pool, 1, sizeof(*wb));
		// kr_require(wb);
		//
		// wire_buf_init(wb, ctx->payload.buffer.len + 10);
		// memcpy(wire_buf_free_space(wb), ctx->payload.buffer.buf,
		// 		ctx->payload.buffer.len);
		//
		// kr_require(wire_buf_consume(wb, ctx->payload.buffer.len) == 0);
		ctx->payload = protolayer_payload_wire_buf(&stream->pers_inbuf, false);

		kr_log_info(DOQ, "CONTINUE from stream_unwrap\n");
		// session2_unwrap_after(stream->h.session,
		// 		PROTOLAYER_TYPE_QUIC_STREAM,
		// 		ctx->payload,
		// 		ctx->comm,
		// 		ctx->finished_cb,
		// 		ctx->finished_cb_baton);

		return protolayer_continue(ctx);
	} else {
		// TODO: store the data and wait for fin
		kr_log_info(DOQ, "pl_quic_stream awaits more data\n");
		return protolayer_async();
	}

	return protolayer_break(ctx, kr_error(EINVAL));
}

static int kr_quic_store_payload(struct protolayer_payload *pl,
		struct wire_buf *dest)
{
	kr_require(pl->type == PROTOLAYER_PAYLOAD_IOVEC && dest
			&& wire_buf_free_space_length(dest) == 1200);

	size_t prefix_size = sizeof(uint16_t);
	size_t prefix = *(uint16_t *)pl->iovec.iov[0].iov_base;
	size_t len = pl->iovec.iov[1].iov_len;


	memcpy(wire_buf_free_space(dest), &prefix, prefix_size);
	// knot_wire_write_u16(wire_buf_free_space(dest), prefix);
	wire_buf_consume(dest, prefix_size);
	memcpy(wire_buf_free_space(dest), pl->iovec.iov[1].iov_base, len);
	wire_buf_consume(dest, len);

	/* TODO: store in session data the current payload size? */
	return len;
}

/* This will not do, storing the prepared payload just in ctx will result
 * in it getting dereferenced. But we are obligated to keep
 * the data untill acked of stream_close */
static enum protolayer_iter_cb_result pl_quic_stream_wrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	kr_require(ctx->payload.type = PROTOLAYER_PAYLOAD_IOVEC);
	struct pl_quic_stream_sess_data *stream = sess_data;
	kr_require(stream->stream_id >= 0);
	ngtcp2_ssize sent = 0;

	wire_buf_reset(&stream->pers_inbuf);
	kr_quic_store_payload(&ctx->payload, &stream->pers_inbuf);

	struct wire_buf *wb = mm_alloc(&ctx->pool, sizeof(struct wire_buf));

	wire_buf_init(wb, 1200/* FIXME: */);
	ctx->payload = protolayer_payload_wire_buf(wb, false);

	int nwrite = send_stream(stream, ctx, wire_buf_data(&stream->pers_inbuf),
			wire_buf_data_length(&stream->pers_inbuf), true/*fin*/, &sent);
	if (nwrite <= 0) {
		kr_log_error(DOQ, "send_stream failed %s (%d)\n",
				ngtcp2_strerror(nwrite), nwrite);
	}

	kr_log_info(DOQ, "send_stream seemingly succeded %d\n", nwrite);
	protolayer_continue(ctx);


	// const ngtcp2_path *path = ngtcp2_conn_get_path(stream->conn);
	// ngtcp2_pkt_info pi = { 0 };
	//
	// ngtcp2_vec vec = {
	// 	.base = ctx->payload.iovec.iov[1].iov_base,
	// 	.len = ctx->payload.iovec.iov[1].iov_len
	// };
	//
	// kr_quic_stream_add_data(stream, &ctx->payload);
	// // TODO: deal with send special
	// size_t uf = stream->unsent_offset;
	// kr_quic_obuf_t *uo = stream->unsent_obuf;
	// if (uo == NULL) {
	// 	kr_log_error(DOQ, "unsent_obuf was null in pl_quic_stream_wrap\n");
	// 	kr_require(false);
	// }
	//
	// bool fin = (((node_t *)uo->node.next)->next == NULL)/* && ignore_last == 0*/;
	// int ret = send_stream(stream, ctx, uo->buf + uf,
	// 		uo->len - uf - 0/*ignore_last*/, fin, &sent);
	//
	// if (ret <= 0) {
	// 	kr_log_error(DOQ, "send_stream failed %s (%d)\n",
	// 			ngtcp2_strerror(ret), ret);
	//
	// }

	return protolayer_continue(ctx);
}

// 		void *iter_data, struct protolayer_iter_ctx *ctx)
// {
// 	kr_require(ctx->payload.type = PROTOLAYER_PAYLOAD_IOVEC);
// 	struct pl_quic_stream_sess_data *stream = sess_data;
// 	kr_require(stream->stream_id >= 0);
//
// 	// kr_quic_stream_add_data()
//
// 	const ngtcp2_path *path = ngtcp2_conn_get_path(stream->conn);
// 	ngtcp2_pkt_info pi = { 0 };
// 	ngtcp2_ssize sent = 0;
//
// 	ngtcp2_vec vec = {
// 		.base = ctx->payload.iovec.iov[1].iov_base,
// 		.len = ctx->payload.iovec.iov[1].iov_len
// 	};
//
// 	kr_quic_stream_add_data(stream, &ctx->payload);
// 	// TODO: deal with send special
// 	size_t uf = stream->unsent_offset;
// 	kr_quic_obuf_t *uo = stream->unsent_obuf;
// 	if (uo == NULL) {
// 		kr_log_error(DOQ, "unsent_obuf was null in pl_quic_stream_wrap\n");
// 		kr_require(false);
// 	}
//
// 	bool fin = (((node_t *)uo->node.next)->next == NULL)/* && ignore_last == 0*/;
// 	int ret = send_stream(stream, ctx, uo->buf + uf,
// 			uo->len - uf - 0/*ignore_last*/, fin, &sent);
//
// 	if (ret <= 0) {
// 		kr_log_error(DOQ, "send_stream failed %s (%d)\n",
// 				ngtcp2_strerror(ret), ret);
//
// 	}
//
// 	return protolayer_continue(ctx);
//
//
// 	// size_t uf = conn->streams[si].unsent_offset;
// 	// kr_quic_obuf_t *uo = conn->streams[si].unsent_obuf;
// 	// if (uo == NULL) {
// 	// 	si++;
// 	// 	continue;
// 	// }
// 	//
// 	// bool fin = (((node_t *)uo->node.next)->next == NULL) && ignore_last == 0;
// 	//
// 	// kr_log_info(DOQ, "About to SEND_STREAM fin: %d stream_id: %zu fsi: %zu streams_count: %d\n",
// 	// 	   fin, stream_id, conn->first_stream_id, conn->streams_count);
// 	//
// 	// ret = send_stream(conn, ctx, stream_id, uo->buf + uf,
// 	// 		  uo->len - uf - ignore_last, fin, &sent);
//
// 	// kr_quic_send(, struct protolayer_iter_ctx *ctx, int action,
// 	// unsigned int max_msgs, kr_quic_send_flag_t flags)
// 	// int nwrite = ngtcp2_conn_writev_stream(stream->conn, path, &pi,
// 	// 		wire_buf_free_space(ctx->payload.wire_buf),
// 	// 		wire_buf_free_space_length(ctx->payload.wire_buf),
// 	// 		&sent, fl, stream->stream_id, &vec,
// 	// 		(stream->stream_id >= 0 ? 1 : 0), quic_timestamp());
//
// 	// if (nwrite < 0) {
// 	// 	kr_log_error(DOQ, "failed to write quic packet %s (%d)\n",
// 	// 			ngtcp2_strerror(nwrite), nwrite);
// 	// 	return protolayer_break(ctx, nwrite);
// 	// }
//
//
// 	// kr_quic_stream_add_data(stream, &ctx->payload);
//
// 	// wire_buf_consume(ctx->payload.wire_buf, nwrite);
// 	//
// 	// kr_log_info(DOQ, "stream wrap wrote %d\n", nwrite);
// 	// ngtcp2_conn_update_pkt_tx_time(stream->conn, quic_timestamp());
// 	// return protolayer_continue(ctx);
// }

static int send_stream(struct pl_quic_stream_sess_data *stream,
		struct protolayer_iter_ctx *ctx,
		// struct protolayer_payload *outwb,
		uint8_t *data, size_t len, bool fin, ngtcp2_ssize *sent)
{
	/* require empty wire_buf TODO maybe remove*/
	kr_require(wire_buf_data_length(ctx->payload.wire_buf) == 0);
	kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF);
	// kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_IOVEC);
	int64_t stream_id = stream->stream_id;

	assert(stream_id >= 0 || (data == NULL && len == 0));

	// while (stream_id >= 0 && !kr_quic_stream_exists(conn, stream_id)) {
	// 	int64_t opened = 0;
	// 	kr_log_info(DOQ, "Openning bidirectional stream no: %zu\n",
	// 			stream_id);
	//
	// 	int ret = ngtcp2_conn_open_bidi_stream(conn->conn,
	// 			&opened, NULL);
	// 	if (ret != kr_ok()) {
	// 		kr_log_warning(DOQ, "remote endpoint isn't ready for streams: %s (%d)\n",
	// 				ngtcp2_strerror(ret), ret);
	// 		return ret;
	// 	}
	// 	kr_require((bool)(opened == stream_id) == kr_quic_stream_exists(conn, stream_id));
	// }
	
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


// static int send_stream(struct pl_quic_stream_sess_data *stream,
// 		struct protolayer_iter_ctx *ctx,
// 		// struct protolayer_payload *outwb,
// 		uint8_t *data, size_t len, bool fin, ngtcp2_ssize *sent)
// {
// 	/* require empty wire_buf TODO maybe remove*/
// 	kr_require(wire_buf_data_length(ctx->payload.wire_buf) == 0);
// 	kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF);
// 	// kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_IOVEC);
// 	int64_t stream_id = stream->stream_id;
//
// 	assert(stream_id >= 0 || (data == NULL && len == 0));
//
//
//
// 	// while (stream_id >= 0 && !kr_quic_stream_exists(conn, stream_id)) {
// 	// 	int64_t opened = 0;
// 	// 	kr_log_info(DOQ, "Openning bidirectional stream no: %zu\n",
// 	// 			stream_id);
// 	//
// 	// 	int ret = ngtcp2_conn_open_bidi_stream(conn->conn,
// 	// 			&opened, NULL);
// 	// 	if (ret != kr_ok()) {
// 	// 		kr_log_warning(DOQ, "remote endpoint isn't ready for streams: %s (%d)\n",
// 	// 				ngtcp2_strerror(ret), ret);
// 	// 		return ret;
// 	// 	}
// 	// 	kr_require((bool)(opened == stream_id) == kr_quic_stream_exists(conn, stream_id));
// 	// }
// 	
// 	uint32_t fl = ((stream_id >= 0 && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN
// 					       : NGTCP2_WRITE_STREAM_FLAG_NONE);
//
// 	ngtcp2_vec vec = { .base = data, .len = len };
// 	ngtcp2_pkt_info pi = { 0 };
//
// 	const ngtcp2_path *path = ngtcp2_conn_get_path(stream->conn);
//
// 	ngtcp2_conn_info info = { 0 };
// 	ngtcp2_conn_get_conn_info(stream->conn, &info);
// 	int nwrite = ngtcp2_conn_writev_stream(stream->conn, path, &pi,
// 			wire_buf_free_space(ctx->payload.wire_buf),
// 			wire_buf_free_space_length(ctx->payload.wire_buf),
// 			sent, fl, stream_id, &vec,
// 			(stream_id >= 0 ? 1 : 0), quic_timestamp());
//
// 	/* TODO:
// 	 * This packet may contain frames other than STREAM frame. The
// 	 * packet might not contain STREAM frame if other frames
// 	 * occupy the packet. In that case, *pdatalen would
// 	 * be -1 if pdatalen is not NULL. */
// 	if (nwrite <= 0) {
// 		return nwrite < 0 ? nwrite : kr_error(ENODATA);
// 	}
//
// 	if (*sent < 0) {
// 		*sent = 0;
// 	}
//
// 	kr_require(wire_buf_consume(ctx->payload.wire_buf, nwrite) == kr_ok());
// 	return nwrite;
//
// 	// return session2_wrap(conn->h.session,
// 	// // return session2_wrap_after(conn->h.session,
// 	// // 		PROTOLAYER_TYPE_QUIC_CONN,
// 	// 		ctx->payload,
// 	// 		ctx->comm,
// 	// 		NULL,
// 	// 		// ctx->req,
// 	// 		ctx->finished_cb,
// 	// 		ctx->finished_cb_baton);
// //
// // 	} else if (*sent >= 0) {
// // 		/* TODO this data has to be kept untill acked */
// // 		vec.len -= *sent;
// // 	}
// //
// // 	kr_require(wire_buf_consume(ctx->payload.wire_buf, nwrite));
// //
// // 	/* called from wrap, proceed to the next layer */
// // 	if (len) {
// // 		return nwrite;
// // 		// return protolayer_continue(ctx);
// // 	}
// //
// // 	/* called from unwrap, respond with QUIC communication data */
// // 	if (nwrite || *sent)  {
// // 		// int wrap_ret = session2_wrap_after(ctx->session,
// // 		// 		PROTOLAYER_TYPE_QUIC_CONN, ctx->payload, ctx->comm,
// // 		// 		ctx->finished_cb, ctx->finished_cb_baton);
// // 		//
// // 		// if (wrap_ret < 0) {
// // 		// 	nwrite = wrap_ret;
// // 		// }
// // 		return nwrite;
// //
// // 	} else {
// // 		// TODO?
// // 	}
// //
// // exit:
// // 	// wire_buf_deinit(wb);
// // 	// mm_free(&ctx->pool, wb);
// //
// // 	return -1;
// }

/* Function for sending speciall packets, requires
 * a message (which special data are we to send: CONN_CLOSE, RESET, ...)
 * and a buffer to store the pkt in, for now ctx->payloay.wb
 * For now only kr_quic_send ever call send_special, though this might proove
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
	// struct kr_quic_stream *s = kr_quic_conn_get_stream(conn, stream_id, false);
	// if (s == NULL) {
	// 	return;
	// }

	kr_require(stream);

	stream->unsent_offset += amount_sent;
	assert(stream->unsent_offset <= stream->unsent_obuf->len);
	if (stream->unsent_offset == stream->unsent_obuf->len) {
		stream->unsent_offset = 0;
		stream->unsent_obuf = (kr_quic_obuf_t *)stream->unsent_obuf->node.next;
		if (stream->unsent_obuf->node.next == NULL) { // already behind the tail of list
			stream->unsent_obuf = NULL;
		}
	}
}

// int kr_quic_send(struct pl_quic_conn_sess_data *conn,
// 		// void *sess_data,
// 		struct protolayer_iter_ctx *ctx,
// 		int action,
// 		// ngtcp2_version_cid *decoded_cids,
// 		unsigned max_msgs,
// 		kr_quic_send_flag_t flags)
// {
// 	if (/*quic_table == NULL || */ conn == NULL /* || reply == NULL */) {
// 		return kr_error(EINVAL);
// 	} else if ((conn->flags & KR_QUIC_CONN_BLOCKED) && !(flags & KR_QUIC_SEND_IGNORE_BLOCKED)) {
// 		return kr_error(EINVAL);
// 	} else if (action != 0) {
// 		return send_special(conn, ctx, /* quic_table, */ action /*, decoded_cids */);
// 	} else if (conn == NULL) {
// 		return kr_error(EINVAL);
// 	} else if (conn->conn == NULL) {
// 		return kr_ok();
// 	}
//
// 	if (!(conn->flags & KR_QUIC_CONN_HANDSHAKE_DONE)) {
// 		max_msgs = 1;
// 	}
//
// 	unsigned sent_msgs = 0, stream_msgs = 0, ignore_last = ((flags & KR_QUIC_SEND_IGNORE_LASTBYTE) ? 1 : 0);
// 	int ret = 1;
//
// 	for (int64_t si = 0; si < conn->streams_count && sent_msgs < max_msgs; /* NO INCREMENT */) {
// 		int64_t stream_id = 4 * (conn->first_stream_id + si);
//
// 		ngtcp2_ssize sent = 0;
// 		size_t uf = conn->streams[si].unsent_offset;
// 		kr_quic_obuf_t *uo = conn->streams[si].unsent_obuf;
// 		if (uo == NULL) {
// 			si++;
// 			continue;
// 		}
//
// 		bool fin = (((node_t *)uo->node.next)->next == NULL) && ignore_last == 0;
//
// 		kr_log_info(DOQ, "About to SEND_STREAM fin: %d stream_id: %zu fsi: %zu streams_count: %d\n",
// 			   fin, stream_id, conn->first_stream_id, conn->streams_count);
//
// 		// ret = send_stream(conn, ctx, stream_id, uo->buf + uf,
// 		// 		  uo->len - uf - ignore_last, fin, &sent);
//
// 		if (ret != PROTOLAYER_RET_NORMAL) {
// 			si++;
// 			continue;
// 		}
//
// 		ngtcp2_conn_update_pkt_tx_time(conn->conn, quic_timestamp());
// 		if (sent > 0)
// 			kr_quic_stream_mark_sent(conn, stream_id, sent);
//
// 		if (stream_msgs >= max_msgs / conn->streams_count) {
// 			stream_msgs = 0;
// 			si++; // if this stream is sending too much, give chance to other streams
// 		}
//
// 		// // /* FIXME just an attempted hotfix
// 		// //  * ok this actually worked, but it shadows an underlying issue */
// 		// // if (ret == NGTCP2_ERR_STREAM_SHUT_WR) {
// 		// // 	// kr_quic_stream_mark_sent(conn, stream_id, sent);
// 		// // 	si++;
// 		// // 	continue;
// 		// // /* FIXME just an attempted hotfix
// 		// //  * ok this actually worked, but it shadows an underlying issue */
// 		// // } else if (ret == NGTCP2_ERR_STREAM_ID_BLOCKED) {
// 		// // 	si++;
// 		// // 	continue;
// 		// // }
// 		//
// 		// if (ret < 0) {
// 		// 	ngtcp2_conn_update_pkt_tx_time(conn->conn, quic_timestamp());
// 		// 	return ret;
// 		// }
// 		//
// 		// sent_msgs++;
// 		// stream_msgs++;
// 		// if (sent > 0 && ignore_last > 0) {
// 		// 	sent++;
// 		// }
// 		// if (sent > 0) {
// 		// 	kr_quic_stream_mark_sent(conn, stream_id, sent);
// 		// }
// 		// /* FIXME: just an attempted hotfix
// 		//  * ok this actually worked, but it shadows an underlying issue */
// 		// if (ret >= 0) {
// 		// 	ngtcp2_conn_update_pkt_tx_time(conn->conn, quic_timestamp());
// 		// 	return ret;
// 		// }
// 		//
// 		// if (stream_msgs >= max_msgs / conn->streams_count) {
// 		// 	stream_msgs = 0;
// 		// 	si++; // if this stream is sending too much, give chance to other streams
// 		// }
// 	}
//
// 	while (ret == 1) {
// 		ngtcp2_ssize unused = 0;
// 		// ret = send_stream(conn, ctx, -1, NULL, 0, false, &unused);
// 	}
//
// 	// Might not be the correct place to call this
// 	ngtcp2_conn_update_pkt_tx_time(conn->conn, quic_timestamp());
// 	return sent_msgs;
// }

// struct kr_quic_stream *kr_quic_conn_get_stream(struct pl_quic_conn_sess_data *conn,
// 		int64_t stream_id, bool create)
// {
// 	if (stream_id % 4 != 0 || conn == NULL) {
// 		return NULL;
// 	}
// 	stream_id /= 4;
//
// 	if (conn->first_stream_id > stream_id) {
// 		return NULL;
// 	}
// 	if (conn->streams_count > stream_id - conn->first_stream_id) {
// 		return &conn->streams[stream_id - conn->first_stream_id];
// 	}
//
// 	if (create) {
// 		size_t new_streams_count;
// 		struct kr_quic_stream *new_streams;
//
// 		// should we attempt to purge unused streams here?
// 		// maybe only when we approach the limit
// 		if (conn->streams_count == 0) {
// 			new_streams = malloc(sizeof(new_streams[0]));
// 			if (new_streams == NULL) {
// 				return NULL;
// 			}
// 			new_streams_count = 1;
// 			conn->first_stream_id = stream_id;
// 		} else {
// 			new_streams_count = stream_id + 1 - conn->first_stream_id;
// 			if (new_streams_count > MAX_STREAMS_PER_CONN) {
// 				return NULL;
// 			}
// 			new_streams = realloc(conn->streams,
// 					new_streams_count * sizeof(*new_streams));
// 			if (new_streams == NULL) {
// 				return NULL;
// 			}
// 		}
//
// 		for (struct kr_quic_stream *si = new_streams;
// 				si < new_streams + conn->streams_count; si++) {
// 			if (si->obufs_size == 0) {
// 				init_list(&si->outbufs);
// 			} else {
// 				fix_list(&si->outbufs);
// 			}
// 		}
//
// 		for (struct kr_quic_stream *si = new_streams + conn->streams_count;
// 		     si < new_streams + new_streams_count; si++) {
// 			memset(si, 0, sizeof(*si));
// 			init_list(&si->outbufs);
// 		}
//
// 		conn->streams = new_streams;
// 		conn->streams_count = new_streams_count;
//
// 		return &conn->streams[stream_id - conn->first_stream_id];
// 	}
//
// 	return NULL;
// }
//
/** buffer resolved payload in wire format, this buffer
 * is used to create quic stream data. Data in this buffer
 * MUST be kept until ack frame confirms their retrieval
 * or the stream gets closed. */
// int kr_quic_stream_add_data(struct pl_quic_stream_sess_data *stream,
// 		int64_t stream_id, struct protolayer_payload *pl)
// {
//
// 	kr_require(stream);
//
// #define SIZE_PREFIX 0
// #define DATA 1
//
// 	size_t prefix_size = sizeof(uint16_t);
// 	size_t prefix = *(uint16_t *)pl->iovec.iov[SIZE_PREFIX].iov_base;
// 	size_t len = pl->iovec.iov[DATA].iov_len;
//
// 	struct kr_quic_obuf *obuf = malloc(sizeof(*obuf) + prefix_size + len);
// 	kr_require(obuf);
// 	// if (!obuf)
// 	// 	return kr_error(ENOMEM)
//
// 	obuf->len = len + prefix_size;
//
// 	kr_require(obuf->buf);
// 	// already in big endian
// 	memcpy(&obuf->buf, &prefix, prefix_size);
// 	// knot_wire_write_u16(obuf->buf, prefix);
// 	if (len) {
// 		memcpy(obuf->buf + prefix_size, pl->iovec.iov[DATA].iov_base, len);
// 	}
//
// #undef SIZE_PREFIX
// #undef DATA
//
// 	list_t *list = (list_t *)&stream->outbufs;
// 	if (EMPTY_LIST(*list)) {
// 		stream->unsent_obuf = obuf;
// 	}
// 	add_tail((list_t *)&stream->outbufs, (node_t *)obuf);
// 	stream->obufs_size += obuf->len;
// 	// stream->quic_table->obufs_size += obuf->len;
//
// 	return len;
// }

/* FIXME */
#define OUTBUF_SIZE 1200
	static int pl_quic_stream_sess_init(struct session2 *session, void *sess_data, void *param)
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
	// struct comm_info *comm = p->comm_storage;
	// if (comm->src_addr) {
	// 	int len = kr_sockaddr_len(comm->src_addr);
	// 	kr_require(len > 0 && len <= sizeof(union kr_sockaddr));
	// 	memcpy(&stream->comm_storage.src_addr, comm->src_addr, len);
	// 	// session->comm_storage.src_addr = &stream->comm_storage.src_addr.ip;
	// }
	// if (comm->comm_addr) {
	// 	int len = kr_sockaddr_len(comm->comm_addr);
	// 	kr_require(len > 0 && len <= sizeof(union kr_sockaddr));
	// 	memcpy(&stream->comm_storage.comm_addr, comm->comm_addr, len);
	// 	// session->comm_storage.comm_addr = &stream->comm_storage.comm_addr;
	// }
	// if (comm->dst_addr) {
	// 	int len = kr_sockaddr_len(comm->dst_addr);
	// 	kr_require(len > 0 && len <= sizeof(union kr_sockaddr));
	// 	memcpy(&stream->comm_storage.dst_addr, comm->dst_addr, len);
	// 	// session->comm_storage.dst_addr = &stream->comm_storage.dst_addr.ip;
	// }

	// stream->comm_storage = p->comm_storage;
	/* perhaps a pointer would suffice */
	// kr_require(p->comm_ref);
	// memcpy(&stream->comm_ref, p->comm_ref, sizeof(struct comm_info));

	return kr_ok();
}

void kr_quic_stream_ack_data(struct pl_quic_stream_sess_data *stream, int64_t stream_id,
                               size_t end_acked, bool keep_stream)
{
	kr_require(stream);
	struct list *obs = &stream->outbufs;

	struct kr_quic_obuf *first;

	while (!EMPTY_LIST(*obs) && end_acked >= (first = HEAD(*obs))->len + stream->first_offset) {
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
			stream->unsent_obuf = EMPTY_LIST(*obs) == 0 ? NULL : HEAD(*obs);
			stream->unsent_offset = 0;
		}
	}

	// if (EMPTY_LIST(*obs) && !keep_stream) {
		// stream_outprocess(conn, stream);
		// memset(stream, 0, sizeof(*stream));
		// init_list(&stream->outbufs);
		// while (s = &conn->streams[0],
		// 		wire_buf_data_length(&stream->pers_inbuf) == 0 &&
		// 		stream->obufs_size == 0) {
		// 	kr_assert(conn->streams_count > 0);
		// 	conn->streams_count--;
		//
		// 	if (conn->streams_count == 0) {
		// 		free(conn->streams);
		// 		conn->streams = 0;
		// 		conn->first_stream_id = 0;
		// 		break;
		// 	} else {
		// 		conn->first_stream_id++;
		// 		conn->stream_inprocesstream--;
		// 		memmove(s, s + 1, sizeof(*s) * conn->streams_count);
		// 		// possible realloc to shrink allocated space,
		// 		// but probably useless
		// 		for (struct kr_quic_stream *si = s;
		// 				si < s + conn->streams_count;
		// 				si++) {
		// 			if (si->obufs_size == 0) {
		// 				init_list(&si->outbufs);
		// 			} else {
		// 				fix_list(&si->outbufs);
		// 			}
		// 		}
		// 	}
		// }
	// }
}

/* store the index of the first stream that has a
 * query ready to be resolved in conn->stream_inprocess */
// void stream_inprocess(struct pl_quic_conn_sess_data *conn, struct kr_quic_stream *stream)
// {
// 	int16_t idx = stream - conn->streams;
// 	assert(idx >= 0);
// 	assert(idx < conn->streams_count);
// 	if (conn->stream_inprocess < 0 || conn->stream_inprocess > idx) {
// 		conn->stream_inprocess = idx;
// 	}
// }

int update_stream_pers_buffer(struct pl_quic_stream_sess_data *stream,
		const uint8_t *data, size_t len, int64_t stream_id)
{
	kr_require(len > 0 && data && stream);

	kr_log_info(DOQ, "updating pers_buffer of stream %ld, with %zu data, it already contained %zu bytes\n",
			stream_id, len, wire_buf_data_length(&stream->pers_inbuf));

	// struct wire_buf wb = stream->pers_inbuf;
	if (wire_buf_free_space_length(&stream->pers_inbuf) < len) {
		kr_log_error(DOQ, "wire buf for stream no. %ld ran out of available space needed: %zu, available: %zu\n",
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

/* FIXME: */
#define QBUFSIZE 256u

/** callback of recv_stream_data,
 * data passed to this cb function is the actuall query. */
// int kr_quic_stream_recv_data(struct pl_quic_stream_sess_data *stream,
// 		int64_t stream_id, const uint8_t *data, size_t len, bool fin)
// {
// 	if (len == 0 || data == NULL) {
// 		return KNOT_EINVAL;
// 	}
//
// 	kr_require(stream);
//
// 	// conn->streams_pending++;
// 	if (!stream->pers_inbuf.buf) {
// 		wire_buf_init(&stream->pers_inbuf, /* FIXME */QBUFSIZE);
// 	}
//
// 	// struct iovec in = { (void *)data, len };
// 	// ssize_t prev_ibufs_size = qconn->ibufs_size;
// 	// size_t save_total = qconn->ibufs_size;
//
// 	kr_log_info(DOQ, "about to update stream's %ld, pers_buffer with %zu data\n",
// 			stream_id, len);
// 	int ret;
// 	// TODO:
// 	// if ((ret = update_stream_pers_buffer(data, len, stream, stream_id)) != kr_ok()) {
// 	// 	return ret;
// 	// }
//
//
// 	// if (fin && stream->inbufs == NULL) {
// 	// 	return KNOT_ESEMCHECK;
// 	// }
//
// 	if (fin) {
// 		// stream_inprocess(conn, stream);
// 	}
//
// 	return kr_ok();
// }


// void kr_quic_conn_stream_free(struct pl_quic_stream_sess_data *conn, int64_t stream_id)
// {
//
// 	struct kr_quic_stream *s = kr_quic_conn_get_stream(conn, stream_id, false);
//
// 	if (s != NULL && s->pers_inbuf.buf) {
// 		/* should not happen */
// 		wire_buf_deinit(&s->pers_inbuf);
// 	}
//
// 	if (s != NULL && /* FIXME this condition */ wire_buf_data_length(&s->pers_inbuf) > 0) {
// 		wire_buf_deinit(&s->pers_inbuf);
// 		// TODO
// 		// conn->ibufs_size -= buffer_alloc_size(s->inbuf.iov_len);
// 		// conn->quic_table->ibufs_size -= buffer_alloc_size(s->inbuf.iov_len);
//
// 		// s->pers_inbuf = NULL;
// 	}
//
// 	// knotdns iovec inbufs specific
// 	// while (s != NULL && s->inbufs != NULL) {
// 	// 	void *tofree = s->inbufs;
// 	// 	s->inbufs = s->inbufs->next;
// 	// 	free(tofree);
// 	// }
//
// 	kr_quic_stream_ack_data(conn, stream_id, SIZE_MAX, false);
// }

static int pl_quic_stream_sess_deinit(struct session2 *session, void *sess_data)

{
	kr_log_info(DOQ, "IN CONN DEINIT\n");

	struct pl_quic_conn_sess_data *conn = sess_data;
	queue_deinit(conn->wrap_queue);
	queue_deinit(conn->unwrap_queue);
	wire_buf_deinit(&conn->unwrap_buf);
	ngtcp2_conn_del(conn->conn);

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
	if (event == PROTOLAYER_EVENT_CLOSE) {
		kr_log_info(DOQ, "IM SUPPOSTED TO CLOSE FROM EVENT UNWRAP\n");
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_quic_stream_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	// session2_waitinglist_finalize(session, 0/* FIXME */);
	if (event == PROTOLAYER_EVENT_CLOSE) {
		kr_log_info(DOQ, "IM SUPPOSTED TO CLOSE FROM EVENT WRAP\n");
	}

	// return PROTOLAYER_EVENT_PROPAGATE;
	return PROTOLAYER_EVENT_CONSUME;
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
