/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <stdio.h>
#include "quic_conn.h"
#include "lib/defines.h"
#include "mempattern.h"
#include "session2.h"
#include <ngtcp2/ngtcp2.h>
#include <string.h>

uint64_t quic_timestamp(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;

	return ((uint64_t)ts.tv_sec * NGTCP2_SECONDS) + (uint64_t)ts.tv_nsec;
}

static int handle_packet(struct pl_quic_conn_sess_data *conn,
		struct protolayer_iter_ctx *ctx)
{
	// *action = 0;
	// kr_quic_conn_t *qconn = NULL;
	//
	// // Initial comm processing
	// // ngtcp2_version_cid decoded_cids = { 0 };
	// // FIXME: duplicate read, reread in quic_init_server_conn (accept)
	// int ret = ngtcp2_pkt_decode_version_cid(dec_cids, pkt,
	// 		pktlen, SERVER_DEFAULT_SCIDLEN);
	//
	// /* If Version Negotiation is required, this function
	//  * returns NGTCP2_ERR_VERSION_NEGOTIATION.
	//  * Unlike the other error cases, all fields of dest are assigned
	//  * see https://nghttp2.org/ngtcp2/ngtcp2_pkt_decode_version_cid.html */
	// if (ret != NGTCP2_NO_ERROR && ret != NGTCP2_ERR_VERSION_NEGOTIATION) {
	// 	kr_log_warning(DOQ, "Could not decode pkt header: (%d) %s \n",
	// 			ret, ngtcp2_strerror(ret));
	// 	return kr_ok();
	// }
	// uint32_t supported_quic[1] = { NGTCP2_PROTO_VER_V1 };
	// ngtcp2_cid_init(&target->dcid, dec_cids->dcid, dec_cids->dcidlen);
	// ngtcp2_cid_init(&target->scid, dec_cids->scid, dec_cids->scidlen);
	// if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
	// 	*action = -QUIC_SEND_VERSION_NEGOTIATION;
	// 	return kr_ok();
	// 	// goto finish
	// }
	//
	// qconn = kr_quic_table_lookup(&target->dcid, quic->conn_table);
	// if (!qconn) {
	// 	struct protolayer_data_param data_param = {
	// 		.protocol = PROTOLAYER_TYPE_QUIC,
	// 		.param = NULL /* TODO! */
	// 	};
	//
	// 	struct session2 *conn_sess = session2_new(SESSION2_TRANSPORT_PARENT,
	// 			KR_PROTO_DOQ,
	// 			&data_param,
	// 			0,
	// 			false);
	//
	// 	/* TODO react accordingly to errcodes from accept.
	// 	 * not all errors are terminal nor are all quiet,
	// 	 * see which case warrants the payload to be discarded
	// 	 * (we have to avoid looping over one bad pkt indefinitelly) */
	// 	if ((ret = quic_init_server_conn(quic->conn_table, ctx,
	// 			 UINT64_MAX - 1, &target->scid, &target->dcid,
	// 			 *dec_cids, pkt, pktlen, &qconn)) != kr_ok()) {
	// 		return ret;
	// 	}
	//
	// 	/* Should not happen, if it did we certainly cannot
	// 	 * continue in the communication
	// 	 * Perhaps kr_require is too strong, this situation
	// 	 * shouldn't corelate with kresd run.
	// 	 * TODO: switch to condition and failed resolution */
	// 	kr_require(qconn);
	// 	// continue;
	// }

	uint64_t now = quic_timestamp();
	const ngtcp2_path *path = ngtcp2_conn_get_path(conn->conn);
	ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };

	// while (ngtcp2_conn_read_pkt(qconn->conn, path, &pi, pkt, pktlen, now) == 0);
	int ret = ngtcp2_conn_read_pkt(conn->conn, path, &pi,
			wire_buf_data(ctx->payload.wire_buf),
			wire_buf_data_length(ctx->payload.wire_buf), now);

	// *out_conn = qconn;
	/* FIXME: inacurate error handling */
	if (ret == NGTCP2_ERR_DRAINING) { // doq received CONNECTION_CLOSE from the counterpart
		if (conn->streams_count > 0) {
			kr_log_warning(DOQ, "received connection_close, unsent stream data will be lost\n");
		}

		session2_close(conn->h.session);
		return -1;
		// session2_event(struct session2 *s, enum protolayer_event_type event, void *baton)

		// kr_quic_table_rem(qconn, quic->conn_table);
		// wire_buf_reset(ctx->payload.wire_buf);
		// *action = KR_QUIC_HANDLE_RET_CLOSE;
		// free(*out_conn);
		// return kr_ok();

	} else if (ngtcp2_err_is_fatal(ret)) { // connection doomed
		kr_log_error(DOQ, "fatal error in ngtcp2_conn_read_pkt: %s (%d)", ngtcp2_strerror(ret), ret);
		// if (ret == NGTCP2_ERR_CALLBACK_FAILURE) {
			// ret = kr_error(KNOT_EBADCERT);
		// } else {
		// 	ret = kr_error();
		// }
		// kr_quic_table_rem(qconn, quic->conn_table);
		// return ret;

	} else if (ret == NGTCP2_ERR_RETRY) {
		// kr_log_info(DOQ, "server will perform address validation via Retry packet\n");
		// *action = QUIC_SEND_RETRY;
		// wire_buf_reset(ctx->payload.wire_buf);
		// return kr_ok();

	} else if (ret != NGTCP2_NO_ERROR) { // non-fatal error, discard packet
		// kr_log_error(DOQ, "discarding recieved pkt: %s (%d)", ngtcp2_strerror(ret), ret);
		// ret = KNOT_EOK;
		// return ret;
	}

	// ngtcp2_conn_handle_expiry(conn->conn, now);

	/* given the 0 return value the pkt has been processed */
	wire_buf_reset(ctx->payload.wire_buf);
	return kr_ok();
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	kr_log_info(DOQ, "Handshake completed\n");
	struct pl_quic_conn_sess_data *qconn = user_data;
	qconn->flags |= KR_QUIC_CONN_HANDSHAKE_DONE;
	// TODO
	// kr_quic_conn_t *ctx = (kr_quic_conn_t *)user_data;
	// assert(ctx->conn == conn);
	//
	// assert(!(ctx->flags & kr_QUIC_CONN_HANDSHAKE_DONE));
	// ctx->flags |= KR_QUIC_CONN_HANDSHAKE_DONE;
	//
	// if (!ngtcp2_conn_is_server(conn)) {
	// 	return NGTCP2_NO_ERROR;
	// 	// TODO: Perform certificate pin check
	// 	// return knot_tls_pin_check(ctx->tls_session, ctx->quic_table->creds)
	// 	//        == KNOT_EOK ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
	// 	// return NGTCP2_ERR_CALLBACK_FAILURE;
	// }
	//
	// if (gnutls_session_ticket_send(ctx->tls_session, 1, 0) != GNUTLS_E_SUCCESS) {
	// 	return -1;
	// }
	//
	// uint8_t token[NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN];
	// ngtcp2_path path = *ngtcp2_conn_get_path(ctx->conn);
	// uint64_t ts = quic_timestamp();
	// ngtcp2_ssize tokenlen = ngtcp2_crypto_generate_regular_token(token,
	// 		(uint8_t *)ctx->quic_table->hash_secret,
	// 		sizeof(ctx->quic_table->hash_secret),
	// 		path.remote.addr, path.remote.addrlen, ts);
	//
	// if (tokenlen < 0
	// 	|| ngtcp2_conn_submit_new_token(ctx->conn, token, tokenlen) != 0)
	// 	return NGTCP2_ERR_CALLBACK_FAILURE;

	return 0;
}

struct pl_quic_stream_sess_data *kr_quic_conn_get_stream(
		struct pl_quic_conn_sess_data *conn,
		int64_t stream_id, bool create)
{
	if (stream_id % 4 != 0 || conn == NULL) {
		return NULL;
	}
	stream_id /= 4;

	if (conn->first_stream_id > stream_id) {
		return NULL;
	}
	if (conn->streams_count > stream_id - conn->first_stream_id) {
		return &conn->streams[stream_id - conn->first_stream_id];
	}

	if (create) {
		size_t new_streams_count;
		struct pl_quic_stream_sess_data *new_streams;

		// should we attempt to purge unused streams here?
		// maybe only when we approach the limit
		if (conn->streams_count == 0) {
			new_streams = malloc(sizeof(new_streams[0]));
			if (new_streams == NULL) {
				return NULL;
			}
			new_streams_count = 1;
			conn->first_stream_id = stream_id;
		} else {
			new_streams_count = stream_id + 1 - conn->first_stream_id;
			if (new_streams_count > MAX_STREAMS_PER_CONN) {
				return NULL;
			}
			new_streams = realloc(conn->streams,
					new_streams_count * sizeof(*new_streams));
			if (new_streams == NULL) {
				return NULL;
			}
		}

		for (struct pl_quic_stream_sess_data *si = new_streams;
				si < new_streams + conn->streams_count; si++) {
			if (si->obufs_size == 0) {
				init_list(&si->outbufs);
			} else {
				fix_list(&si->outbufs);
			}
		}

		for (struct pl_quic_stream_sess_data *si = new_streams + conn->streams_count;
				si < new_streams + new_streams_count; si++) {
			memset(si, 0, sizeof(*si));
			init_list(&si->outbufs);
		}

		conn->streams = new_streams;
		conn->streams_count = new_streams_count;

		return &conn->streams[stream_id - conn->first_stream_id];
	}

	return NULL;
}

static int kr_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
	int64_t stream_id, uint64_t offset, const uint8_t *data,
	size_t datalen, void *user_data, void *stream_user_data)
{
	kr_log_info(DOQ, "stream no. %zu recvd data: %zu %s\n",
			stream_id, datalen, data);
	(void)(offset); // QUIC shall ensure that data arrive in-order

	struct pl_quic_conn_sess_data *qconn = user_data;

	struct pl_quic_stream_sess_data *stream = stream_user_data;
		// kr_quic_conn_get_stream(qconn, stream_id, false);
	stream->incflags = flags;
	stream->sdata_offset = offset;

	/* TODO perhaps move this data storing to QUIC_STREAM */
	if (wire_buf_free_space_length(&stream->pers_inbuf) < datalen) {
		kr_log_error(DOQ, "Not enough space in wb of stream %ld\n",
				stream_id);
		return kr_error(ENOMEM);
	}

	/* FIXME Writing into pl_quic_stream_sess_data is a disgusting
	 * breach of protocol separation. Possible fix would be to either
	 * have one large buffer for all streams belonging to this connection
	 * or n per-stream buffers. Since the latter would just add
	 * additional allocations and memcpys (the buffer would only be
	 * used untill pl_quic_conn_unwrap continues to unwrap of
	 * quic_stream layer, i.e. during ngtcp2_conn_read_pkt) this
	 * is for now a "good enough" workaround. */
	memcpy(wire_buf_free_space(&stream->pers_inbuf), data, datalen);
	kr_require(wire_buf_consume(&stream->pers_inbuf, datalen) == kr_ok());

	// int ret = session2_unwrap(stream->h.session,
	// int ret = session2_unwrap_after(qconn->h.session, PROTOLAYER_TYPE_QUIC_STREAM,
	// 			protolayer_payload_wire_buf(&stream->pers_inbuf, false),
	// 		&qconn->comm_storage, NULL, NULL);
			// &qconn->comm_storage, NULL, NULL);

	/* FIXME: ONLY IF streams are async */
	// if (ret == PROTOLAYER_RET_NORMAL) {
	// 	session2_close(stream->h.session);
	// }

	if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
		queue_push(qconn->pending_unwrap, stream);
	}

	// int ret = session2_unwrap(stream->h.session,
	// 		protolayer_payload_wire_buf(&stream->pers_inbuf, false),
	// 		&qconn->comm_storage,
	// 		NULL,
	// 		NULL);

	return kr_ok();
	// int ret = kr_quic_stream_recv_data(qconn, stream_id, data, datalen,
	// 		(flags & NGTCP2_STREAM_DATA_FLAG_FIN));

	// return ret == KNOT_EOK ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int stream_open_cb(ngtcp2_conn *connection, int64_t stream_id, void *user_data)
{
	int ret = NGTCP2_ERR_NOMEM;
	struct pl_quic_conn_sess_data *conn = user_data;
	/* FIXME: send on stack */
	struct kr_quic_stream_param *params = malloc(sizeof(*params));
	kr_require(params);
	params->stream_id = stream_id;
	params->conn = connection;
	params->comm_storage = conn->comm_storage;
	// params->comm_ref = conn->comm;

	struct protolayer_data_param data_param = {
		.protocol = PROTOLAYER_TYPE_QUIC_STREAM,
		.param = params
	};

	struct session2 *new_stream_sess =
		session2_new_child(conn->h.session,
				KR_PROTO_DOQ_STREAM,
				&data_param,
				1 /* FIXME */,
				false);

	/* FIXME: send on stack */
	free(params);
	struct pl_quic_conn_sess_data *stream_sess_data =
		protolayer_sess_data_get_proto(new_stream_sess,
				PROTOLAYER_TYPE_QUIC_STREAM);

	if (!new_stream_sess)
		kr_log_error(DOQ, "Failed to init child session\n");
		
	kr_require(new_stream_sess);


	size_t new_streams_count;
	struct pl_quic_stream_sess_data *new_streams;

	// should we attempt to purge unused streams here?
	// maybe only when we approach the limit
	if (conn->streams_count == 0) {
		// new_streams = malloc(sizeof(new_streams[0]));
		// if (new_streams == NULL) {
		// 	goto fail;
		// }
		// new_streams_count = 1;
		// conn->first_stream_id = stream_id;
	} else {
		new_streams_count = stream_id + 1 - conn->first_stream_id;
		if (new_streams_count > MAX_STREAMS_PER_CONN) {
			goto fail;
		}
		new_streams = realloc(conn->streams,
				new_streams_count * sizeof(*new_streams));
		if (new_streams == NULL) {
			goto fail;
		}
	}

	for (struct pl_quic_stream_sess_data *si = new_streams;
			si < new_streams + conn->streams_count; si++) {
		if (si->obufs_size == 0) {
			init_list(&si->outbufs);
		} else {
			fix_list(&si->outbufs);
		}
	}

	// for (struct pl_quic_stream_sess_data *si = new_streams + conn->streams_count;
	// 		si < new_streams + new_streams_count; si++) {
	// 	memset(si, 0, sizeof(*si));
	// 	init_list(&si->outbufs);
	// }

	kr_require(ngtcp2_conn_set_stream_user_data(connection, stream_id, stream_sess_data)
			== NGTCP2_NO_ERROR);


	// int64_t opened = 0;
	// ret = ngtcp2_conn_open_bidi_stream(conn->conn,
	// 		&opened, new_stream_sess);
	// if (ret != NGTCP2_NO_ERROR) {
	// 	kr_log_warning(DOQ, "remote endpoint isn't ready for streams: %s (%d)\n",
	// 			ngtcp2_strerror(ret), ret);
	// 	return ret;
	// }
	//
	// kr_require(opened == stream_id);
	// kr_require(kr_quic_conn_get_stream(conn, stream_id, false));

	kr_log_info(DOQ, "new stream succesfully inited: %ld\n", stream_id);
	ret = NGTCP2_NO_ERROR;
	return ret;

fail:
	// if (new_stream_sess) {
	// 	session2_close(new_stream_sess);
	// }

	return ret;
}

static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
			 uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	kr_log_info(DOQ, "closing stream no %zu\n", stream_id);
	struct pl_quic_conn_sess_data *qconn = user_data;

	// struct pl_quic_stream_sess_data *s =
	// 	kr_quic_conn_get_stream(qconn, stream_id, false);
	// kr_require(qconn->conn == conn);
	//
	// session2_close(s->h.session);

	return NGTCP2_NO_ERROR;

	//TODO
	// // NOTE possible error is stored in (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)
	// bool keep = !ngtcp2_conn_is_server(conn);
	// if (!keep) {
	// 	kr_quic_conn_stream_free(qconn, stream_id);
	// }
	// return kr_ok();
}

static void kr_quic_rand_cb(uint8_t *dest, size_t destlen,
	const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;
	dnssec_random_buffer(dest, destlen);
}

static void init_random_cid(ngtcp2_cid *cid, size_t len)
{
	if (len == 0)
		len = SERVER_DEFAULT_SCIDLEN;

	cid->datalen = dnssec_random_buffer(cid->data, len) == DNSSEC_EOK ? len : 0;
}

static bool init_unique_cid(ngtcp2_cid *cid, size_t len, kr_quic_table_t *table)
{
	do {
		if (init_random_cid(cid, len), cid->datalen == 0)
			return false;

	} while (false/* FIXME:!!! just for proof of concept purposes! */);
	// } while (kr_quic_table_lookup(cid, table) != NULL);

	return true;
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
		uint8_t *token, size_t cidlen, void *user_data)
{
	kr_log_info(DOQ, "ngtcp2 requested new connection id\n");

	struct pl_quic_conn_sess_data *conn_sess = user_data;
	// kr_quic_conn_t *ctx = (kr_quic_conn_t *)user_data;
	assert(ctx->conn == conn);

	// TODO
	if (!init_unique_cid(cid, cidlen, NULL/*FIXME: ctx->quic_table*/))
		return NGTCP2_ERR_CALLBACK_FAILURE;

	// kr_quic_cid_t **addto = kr_quic_table_insert(ctx, cid, ctx->quic_table);
	// (void)addto;

	// FIXME: remove?
	// ctx->dcid = cid;

	if (token != NULL &&
	    ngtcp2_crypto_generate_stateless_reset_token(
	            token, (uint8_t *)conn_sess->hash_secret/*FIXME: see quic.c*/,
	            sizeof(conn_sess->hash_secret), cid) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int handshake_confirmed_cb(ngtcp2_conn *conn, void *ctx)
{
	(void)conn;
	kr_log_info(DOQ, "Handshake confirmed\n");
	// ctx->state = CONNECTED;
	return kr_ok();
}

static void quic_debug_cb(void *user_data, const char *format, ...)
{
	char buf[256];
	va_list args;
	va_start(args, format);
	(void)vsnprintf(buf, sizeof(buf), format, args);
	kr_log_warning(DOQ, "%s\n", buf);
	va_end(args);
}

static int conn_new_handler(ngtcp2_conn **pconn, const ngtcp2_path *path,
		const ngtcp2_cid *scid, const ngtcp2_cid *dcid,
		const ngtcp2_cid *odcid, uint32_t version,
		uint64_t now, uint64_t idle_timeout_ns,
		bool server, bool retry_sent,
		struct pl_quic_conn_sess_data *conn)
{
	// kr_require(qconn->quic_table != NULL);
	// kr_quic_table_t *qtable = qconn->quic_table;

	const ngtcp2_callbacks callbacks = {
		// .client_initial = ngtcp2_crypto_client_initial_cb, // client side callback
		.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.handshake_completed = handshake_completed_cb, // handshake_completed_cb - OPTIONAL
		// NULL, // recv_version_negotiation not needed on server, nor kxdpgun - OPTIONAL
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.recv_stream_data = kr_recv_stream_data_cb,
		// NULL, // acked_stream_data_offset_cb, TODO - OPTIONAL
		.stream_open = stream_open_cb, // stream_opened - OPTIONAL
		.stream_close = stream_close_cb,
		// NULL,// recv_stateless_rst, TODO - OPTIONAL
		// ngtcp2_crypto_recv_retry_cb, - OPTIONAL
		// NULL, // extend_max_streams_bidi - OPTIONAL
		// NULL, // extend_max_streams_uni - OPTIONAL
		.rand = kr_quic_rand_cb,
		.get_new_connection_id = get_new_connection_id,
		// NULL, // remove_connection_id, TODO - OPTIONAL
		.update_key = ngtcp2_crypto_update_key_cb,
		// NULL, // path_validation, - OPTIONAL
		// NULL, // select_preferred_addr - OPTIONAL
		// NULL,// recv_stream_rst, TODO - OPTIONAL
		// NULL, // extend_max_remote_streams_bidi, might be useful to some allocation optimizations? - OPTIONAL
		// NULL, // extend_max_remote_streams_uni - OPTIONAL
		// NULL, // extend_max_stream_data, - OPTIONAL
		// NULL, // dcid_status - OPTIONAL
		.handshake_confirmed = handshake_confirmed_cb,
			// NULL, // recv_new_token - OPTIONAL
		.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		// NULL, // recv_datagram - OPTIONAL
		// NULL, // ack_datagram - OPTIONAL
		// NULL, // lost_datagram - OPTIONAL
		.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
		// NULL, // stream_stop_sending - OPTIONAL
		.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
		// NULL, // recv_rx_key - OPTIONAL
		// NULL, // recv_rx_key - OPTIONAL
		// .recv_rx_key = recv_rx_key_conf_cb,
		// .recv_tx_key = recv_tx_key_conf_cb,
	};

	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = now;

	if (KR_LOG_LEVEL_IS(LOG_DEBUG)) {
	// if (qtable->log_cb != NULL) {
		settings.log_printf = quic_debug_cb;
	}

	// Probably set by default, set NULL to disable qlog
	// if (qtable->qlog_dir != NULL) {
		// settings.qlog_write = user_printf;
	// }

	size_t limit =
		protolayer_globals[PROTOLAYER_TYPE_QUIC_CONN] .wire_buf_max_overhead;

	if (limit != 0) {
		settings.max_tx_udp_payload_size = limit;
	}

	// settings.handshake_timeout = idle_timeout_ns;
	// NOTE setting handshake timeout to idle_timeout for simplicity
	settings.handshake_timeout = UINT64_MAX; // Do not time out for now
	settings.no_pmtud = true;

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);

	/** This informs peer that active migration might not be available.
	 * Peer might still attempt to migrate. see RFC 9000/5.2.3 */
	params.disable_active_migration = true;

	/** There is no use for unidirectional streams for us */
	params.initial_max_streams_uni = 1024;
	params.initial_max_streams_bidi = 1024;
	params.initial_max_stream_data_bidi_local = NGTCP2_MAX_VARINT;
	params.initial_max_stream_data_bidi_remote = 102400;
	params.initial_max_data = NGTCP2_MAX_VARINT;

	// ignore for now; allow any
	params.max_idle_timeout = 0;

	// params.stateless_reset_token_present = 1;
	// params.active_connection_id_limit = 8;

	if (odcid != NULL) {
		params.original_dcid = *odcid;
		params.original_dcid_present = 1;
	}

	if (retry_sent && scid != NULL) {
		params.retry_scid = *scid;
		params.retry_scid_present = 1;
	}

	// TODO: ngtcp2_server example generates stateles reset token here

	if (retry_sent) {
		assert(scid);
		params.retry_scid_present = 1;
		params.retry_scid = *scid;
	}
	if (dnssec_random_buffer(params.stateless_reset_token, NGTCP2_STATELESS_RESET_TOKENLEN) != kr_ok()) {
		return KNOT_ERROR;
	}

	if (server) {
		// WARNING: scid and dcid have to be swapped here
		// see (https://nghttp2.org/ngtcp2/programmers-guide.html Creating ngtcp2_conn object)
		const ngtcp2_cid *swapped_clients_dcid = scid;
		const ngtcp2_cid *swapped_clients_scid = dcid;
		// return ngtcp2_conn_server_new(pconn, swapped_clients_dcid,
		// 		swapped_clients_scid, path, version,
		// 		&callbacks, &settings, &params, NULL, conn->conn);
		return ngtcp2_conn_server_new(pconn, swapped_clients_dcid,
				swapped_clients_scid, path, version,
				&callbacks, &settings, &params, NULL, conn);
	} else {
		return ngtcp2_conn_client_new(pconn, dcid, scid, path, version, &callbacks,
		                              &settings, &params, NULL, conn);
	}
}

static void kr_quic_set_addrs(struct protolayer_iter_ctx *ctx, ngtcp2_path *path)
{
	const struct sockaddr *remote = NULL;
	const struct sockaddr *local = NULL;

	if (ctx->session->outgoing) {
		remote = ctx->comm->dst_addr;
		local = ctx->comm->src_addr;
	} else {
		remote = ctx->comm->src_addr;
		local = ctx->comm->dst_addr;
	}

	if (local == NULL) {
		local = session2_get_sockname(ctx->session);
		// struct sockaddr_storage ss;
		// memset(&ss, 0, sizeof(ss));
		//
		// struct sockaddr_in *addr = (struct sockaddr_in *)&ss;
		// addr->sin_family = AF_INET;
		// addr->sin_port = htons(8u);
		// inet_pton(AF_INET, "127.0.0.1", &addr->sin_addr);
		//
		// struct sockaddr *nlocal
		// };
		// local =
	}

	path->remote.addr = (struct sockaddr *)remote;
	path->remote.addrlen = kr_sockaddr_len(remote);
	path->local.addr = (struct sockaddr *)local;
	path->local.addrlen = kr_sockaddr_len(local);

	// return kr_ok();
}

int kr_tls_session(struct gnutls_session_int **session,
		struct tls_credentials *creds,
		struct gnutls_priority_st *priority,
		bool quic, // TODO remove, this function will only be used by doq
		bool early_data,
		bool server)
{
	if (session == NULL || creds == NULL || priority == NULL)
		return kr_error(EINVAL);

	// TODO remove, this function will only be used by doq
	const char *alpn = quic ? "\x03""doq" : "\x03""dot";

	gnutls_init_flags_t flags = GNUTLS_NO_SIGNAL;
	if (early_data) {
		flags |= GNUTLS_ENABLE_EARLY_DATA;
#ifdef ENABLE_QUIC // Next flags aren't available in older GnuTLS versions.
		if (quic) {
			flags |= GNUTLS_NO_END_OF_EARLY_DATA;
		}
#endif
	}

	flags |= GNUTLS_SAFE_PADDING_CHECK;

	int ret = gnutls_init(session, (server ? GNUTLS_SERVER : GNUTLS_CLIENT) | flags);
	if (ret == GNUTLS_E_SUCCESS) {
		gnutls_certificate_send_x509_rdn_sequence(*session, 1);
		gnutls_certificate_server_set_request(*session, GNUTLS_CERT_REQUEST);
		ret = gnutls_priority_set(*session, priority);
	}

	// if (server && ret == GNUTLS_E_SUCCESS) {
	// 	kr_log_info(DOQ, "gnutls_ticket sanity: %d %d %d %s\n",
	// 			session == NULL, (&creds->tls_ticket_key) == NULL,
	// 			creds->tls_ticket_key.size != 64, creds->tls_ticket_key.data);
	// 	ret = gnutls_session_ticket_enable_server(*session, &creds->tls_ticket_key);
	// }

	if (ret == GNUTLS_E_SUCCESS) {
		const gnutls_datum_t alpn_datum = { (void *)"doq", '\x03' };
		gnutls_alpn_set_protocols(*session, &alpn_datum, 1, GNUTLS_ALPN_MANDATORY);

		if (early_data) {
			gnutls_record_set_max_early_data_size(*session, 0xffffffffu);
		}

		if (server) {
			gnutls_anti_replay_enable(*session, creds->tls_anti_replay);
		}

		ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE,
				creds->credentials);
	}

	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(DOQ, "tls session init failed: %s (%d)\n",
				gnutls_strerror(ret), ret);
		gnutls_deinit(*session);
		*session = NULL;
	}

	return ret; // == GNUTLS_E_SUCCESS ? KNOT_EOK : KNOT_ERROR;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	return ((struct pl_quic_conn_sess_data *)conn_ref->user_data)->conn;
}

static int tls_init_conn_session(struct pl_quic_conn_sess_data *conn, bool server)
{
	int ret = kr_tls_session(&conn->tls_session, conn->creds,
	                           conn->priority, true, true, server);
	if (ret != KNOT_EOK)
		return kr_error(ret);

	ret = (server)
		? ngtcp2_crypto_gnutls_configure_server_session(conn->tls_session)
		: ngtcp2_crypto_gnutls_configure_client_session(conn->tls_session);
	if (ret != NGTCP2_NO_ERROR) {
		kr_log_info(DOQ, "Failed to configure crypto session\n");
		return kr_error(ret);
	}

	conn->conn_ref = (nc_conn_ref_placeholder_t) {
		.get_conn = get_conn,
		.user_data = conn,
	};

	gnutls_session_set_ptr(conn->tls_session, &conn->conn_ref);
	ngtcp2_conn_set_tls_native_handle(conn->conn, conn->tls_session);

	return kr_ok();
}


int quic_init_server_conn(//kr_quic_table_t *table,
		struct pl_quic_conn_sess_data *conn,
		struct protolayer_iter_ctx *ctx,
		uint64_t idle_timeout)
		// const uint8_t *payload, size_t payload_len,
		// kr_quic_conn_t **out_conn)
{
	if (!ctx) {
		kr_log_error(DOQ, "conn params were null\n");
		return kr_error(EINVAL);
	}

	int ret = EXIT_FAILURE;
	ngtcp2_cid odcid = { 0 };

	uint64_t now = quic_timestamp(); // the timestamps needs to be collected AFTER the check for blocked conn
	ngtcp2_path path;
	kr_quic_set_addrs(ctx, &path);

	// ngtcp2_pkt_hd header = { 0 };
	// ret = ngtcp2_accept(&header,
	// 		payload,
	// 		payload_len);
	// if (ret != 0) {
	// 	ret = -QUIC_SEND_STATELESS_RESET;
	// 	goto finish;
	// }
	//
	// // TODO This never happens (kr_quic_require_retry just returns false)
	// // if (header.tokenlen == 0
	// // 		&& kr_quic_require_retry(table) /* TBD */) {
	// // 	ret = -QUIC_SEND_RETRY;
	// // 	goto finish;
	// // }
	//
	// if (header.tokenlen > 0) {
	// 	if (header.token[0] == NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY) {
	// 		ret = ngtcp2_crypto_verify_retry_token(
	// 			&odcid, header.token, header.tokenlen,
	// 			(const uint8_t *)table->hash_secret,
	// 			sizeof(table->hash_secret), header.version,
	// 			// (const struct sockaddr *)reply->ip_rem,
	// 			path.remote.addr,
	// 			path.remote.addrlen,
	// 			dcid, idle_timeout, now // NOTE setting retry token validity to idle_timeout for simplicity
	// 		);
	// 	} else {
	// 		ret = ngtcp2_crypto_verify_regular_token(
	// 			header.token, header.tokenlen,
	// 			(const uint8_t *)table->hash_secret,
	// 			sizeof(table->hash_secret),
	// 			// (const struct sockaddr *)reply->ip_rem,
	// 			path.remote.addr,
	// 			path.remote.addrlen,
	// 			QUIC_REGULAR_TOKEN_TIMEOUT, now
	// 		);
	// 	}
	//
	// 	if (ret != 0)
	// 		goto finish;
	// }

	ret = conn_new_handler(&conn->conn, &path,
			&conn->scid, &conn->dcid, &conn->odcid,
			conn->dec_cids.version,
			// &header.scid, dcid, &header.dcid,
			now, idle_timeout,
			true, false/* FIXME header->tokenlen > 0 */,
			conn);

	if (ret >= 0) {
		ret = tls_init_conn_session(conn, true);;
	}

	return kr_ok();

finish:
	// WARNING: This looks like it is here for thread return values,
	// therefore useless for us
	// reply->handle_ret = ret;
	return ret;
}

static void copy_comm_storage(
		struct pl_quic_conn_sess_data *conn,
		struct comm_info *comm)
{
	struct comm_addr_storage *addrst = &conn->comm_addr_storage;
	if (comm->src_addr) {
		int len = kr_sockaddr_len(comm->src_addr);
		kr_require(len > 0 && len <= sizeof(union kr_sockaddr));
		memcpy(&addrst->src_addr, comm->src_addr, len);
		conn->comm_storage.src_addr = &addrst->src_addr.ip;
	}
	if (comm->comm_addr) {
		int len = kr_sockaddr_len(comm->comm_addr);
		kr_require(len > 0 && len <= sizeof(union kr_sockaddr));
		memcpy(&addrst->comm_addr, comm->comm_addr, len);
		conn->comm_storage.comm_addr = &addrst->comm_addr.ip;
	}
	if (comm->dst_addr) {
		int len = kr_sockaddr_len(comm->dst_addr);
		kr_require(len > 0 && len <= sizeof(union kr_sockaddr));
		memcpy(&addrst->dst_addr, comm->dst_addr, len);
		conn->comm_storage.dst_addr = &addrst->dst_addr.ip;
	}
}


static enum protolayer_iter_cb_result pl_quic_conn_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret = kr_ok();
	struct pl_quic_conn_sess_data *conn = sess_data;

	// queue_push(conn->unwrap_queue, ctx);

	queue_len(conn->unwrap_queue);
	// while (protolayer_queue_has_payload(&conn->unwrap_queue)) {
		// struct protolayer_iter_ctx *data = queue_head(conn->unwrap_queue);

		struct protolayer_iter_ctx *data = ctx;
		if (!conn->conn) {
			/* here branching for client and server based on outgoing?
			 * It doesn't really make sence for client to ever
			 * receive conn == NULL in unwrap direction */

			// if ((ret = quic_init_server_conn(quic->conn_table, ctx,
			// 		 UINT64_MAX - 1, &target->scid, &target->dcid,
			// 		 *dec_cids, pkt, pktlen, &qconn)) != kr_ok()) {
			if ((ret = quic_init_server_conn(conn, ctx,
					 UINT64_MAX - 1)) != kr_ok()) {
				kr_log_error(DOQ, "Failed to initiate quic server %s (%d)\n",
						ngtcp2_strerror(ret), ret);
				return protolayer_break(data, ret);
			}
		}


		// move to either sess_init or iter_init
		// data->comm->target = malloc(sizeof(int64_t));
		// data->comm->target = mm_alloc(&ctx->pool, sizeof(int64_t));
		// kr_require(data->comm->target);

		copy_comm_storage(conn, &ctx->comm_storage);

		ret = handle_packet(conn, data);
		kr_log_info(DOQ, "handle_packet_result: %d we have %d streams pending\n",
				ret,conn->streams_pending);
		if (ret != kr_ok()) {
			return protolayer_break(ctx, kr_ok());
		}

		if (queue_len(conn->pending_unwrap) != 0) {
			session2_unwrap(queue_head(conn->pending_unwrap)->h.session,
					data->payload,
					&conn->comm_storage,
					data->finished_cb,
					data->finished_cb_baton);
			queue_pop(conn->pending_unwrap);
		} else {
			// const ngtcp2_path *path = ngtcp2_conn_get_path(conn->conn);
			// ngtcp2_pkt_info pi = { 0 };
			// ngtcp2_ssize sent = 0;
			// wire_buf_reset(data->payload.wire_buf);
			// ngtcp2_conn_writev_stream(conn->conn,
			// 		path,
			// 		&pi,
			// 		wire_buf_free_space(data->payload.wire_buf),
			// 		wire_buf_free_space_length(data->payload.wire_buf),
			// 		&sent,
			// 		0/*FIXME:*/,
			// 		-1, NULL, 0, quic_timestamp());
		//
		// 	// return session2_wrap_after(conn->h.session,
		// 	// return session2_wrap_after(data->session,
			ret = session2_wrap(conn->h.session,
					// PROTOLAYER_TYPE_QUIC_DEMUX,
					// data->payload,
					data->payload,
					// protolayer_payload_as_buffer(&data->payload),
					data->comm,
					NULL,
					// data->req,
					data->finished_cb,
					data->finished_cb_baton);

			return protolayer_break(ctx, kr_ok());
			// continue;
		}

	// 	while (conn->streams_pending) {
	// 		// // if ((ret = get_query(data, conn)) <= 0) {
	// 		// // 	kr_log_info(DOQ, "Failed to retrieve query in get_query\n");
	// 		// // 	return protolayer_break(ctx, kr_error(EINVAL));
	// 		// // }
	// 		//
	// 		// // data->payload = protolayer_payload_wire_buf(&conn->unwrap_buf,
	// 		// // 		false);
	// 		// // if (conn->streams_pending == 0) {
	// 		// 	// return protolayer_continue(data);
	// 		// // }
	// 		//
	// 		// // struct iovec *iov = mm_alloc(&ctx->pool,
	// 		// // 		wire_buf_data_length(ctx->payload.wire_buf));
	// 		// // memcpy(&iov->iov_base,
	// 		// // 		wire_buf_data(ctx->payload.wire_buf),
	// 		// // 		wire_buf_data_length(ctx->payload.wire_buf));
	// 		// // iov->iov_len = wire_buf_data_length(ctx->payload.wire_buf);
	// 		// //
	// 		// // ctx->payload = protolayer_payload_iovec(iov, 1, false);
	// 		// // kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_IOVEC);
	// 		//
	// 		// /* FIXME should we ignore the result? */
	// 		//
	// 		// return protolayer_continue(data);
	// 		//
	// 		// // ret = session2_unwrap_after(conn->h.session,
	// 		// session2_unwrap_after(data->session,
	// 		// 		PROTOLAYER_TYPE_QUIC_CONN,
	// 		// 		data->payload,
	// 		// 		data->comm,
	// 		// 		data->finished_cb,
	// 		// 		data->finished_cb_baton);
	// 		// kr_log_info(DOQ, "session2_unwrap_after = %d == NORMAL: %s\n",
	// 		// 	ret, ret == PROTOLAYER_RET_NORMAL ? "true" : "false");
	// 	}
	// }

	// return protolayer_async();
	return protolayer_break(ctx, kr_ok());
	// return protolayer_break(ctx, kr_ok());
}

/* TODO: If there are no resolver queries, just call ngtcp2_with empty,
 * if there are some kr_quic_stream_add_data should append the data
 * and we should retrieve them immediatelly and send out
 *
 * This already has to be done properly because the prototype mentality
 * is cracking */
static enum protolayer_iter_cb_result pl_quic_conn_wrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	// Here we have to differenciate between resolved query returned from
	// stream (finished payload in ...payload) and need to create one
	// This might be as simple as seeing if we have finished handshake
	// (though this handshake trick would only work if streams were async)

	struct pl_quic_conn_sess_data *conn = sess_data;
	kr_log_info(DOQ, "flags: %d, KR: %d equal: %d\n",
			conn->flags, KR_QUIC_CONN_HANDSHAKE_DONE,
			conn->flags == KR_QUIC_CONN_HANDSHAKE_DONE);

	/* HACK: we receive iovec payload only when receiving a finished
	 * query payload. */
	if (ctx->payload.type != PROTOLAYER_PAYLOAD_IOVEC) {
	// if (conn->flags < KR_QUIC_CONN_HANDSHAKE_DONE) {
		ngtcp2_conn_info info = { 0 };
		ngtcp2_conn_get_conn_info(conn->conn, &info);
		const ngtcp2_path *path = ngtcp2_conn_get_path(conn->conn);
		size_t sent = 0;
		ngtcp2_pkt_info pi = { 0 };

		kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF);
		kr_require(wire_buf_data_length(ctx->payload.wire_buf) == 0);

		int nwrite = ngtcp2_conn_writev_stream(conn->conn, path, &pi,
				wire_buf_free_space(ctx->payload.wire_buf),
				wire_buf_free_space_length(ctx->payload.wire_buf),
				&sent, NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL,
				0, quic_timestamp());

		if (nwrite <= 0) {
			kr_log_info(DOQ, "Writev should have produced payload: %d\n", nwrite);
			return protolayer_break(ctx, kr_error(EINVAL));
		}
		kr_log_info(DOQ, "Writev produced payload: %d\n", nwrite);
			
		/* TODO: if written 0 (at least in unlikely) break */
		kr_require(wire_buf_consume(ctx->payload.wire_buf, nwrite) == kr_ok());
		return protolayer_continue(ctx);
	} else {
		return protolayer_continue(ctx);
	}

	// int ret;
	// kr_log_info(DOQ, "in CONN WRAP %s\n", protolayer_payload_name(ctx->payload.type));
	// if (ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF) {
	// 	kr_log_info(DOQ, "CONN WRAP CONTINUING WITH: %s\n",
	// 			protolayer_payload_name(ctx->payload.type));
	// 	return protolayer_continue(ctx);
	// }
	//
	// kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_IOVEC);
	// struct pl_quic_conn_sess_data *conn = sess_data;
	//
	// ngtcp2_vec vec = { .base = NULL, .len = 0 };
	// ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };
	// /* FIXME I could store it and use if from ctx or conn,
	//  * this has warning about discarding const */
	// const ngtcp2_path *path = ngtcp2_conn_get_path(conn->conn);
	// /* struct ngtcp2_path *path = conn->path; ?? */
	//
	// // int new_data = kr_quic_stream_add_data(conn, *(int64_t*)(ctx->comm->target), &ctx->payload);
	//
	// struct wire_buf *wb = mm_alloc(&ctx->pool, sizeof(*wb));
	// char *buf = mm_alloc(&ctx->pool, 1200 /* FIXME this makes no sence */);
	// kr_require(buf);
	// *wb = (struct wire_buf){
	// 	.buf = buf,
	// 	.size = 1200 /* FIXME this makes no sence */
	// };
	//
	// ctx->payload = protolayer_payload_wire_buf(wb, false);
	//
	//
	// // ret = kr_quic_send(conn, ctx, 0/* FIXME action */,
	// // 		QUIC_MAX_SEND_PER_RECV, 0/* no flags */);
	//
	// if (ret > 0) {
	// 	kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF);
	// 	kr_log_info(DOQ, "SENDING PAYLOAD OF SIZE %zu\n",
	// 			wire_buf_data_length(ctx->payload.wire_buf));
	// 	return protolayer_continue(ctx);
	// }
	//
	// kr_log_info(DOQ, "No data to send, breaking\n");
	// return protolayer_break(ctx, kr_ok());
	//





	// size_t sent = 0;
	// ngtcp2_conn_info info = { 0 };
	// ngtcp2_conn_get_conn_info(conn->conn, &info);
	// int nwrite = ngtcp2_conn_writev_stream(conn->conn, path, &pi,
	// 		wire_buf_free_space(ctx->payload.wire_buf),
	// 		wire_buf_free_space_length(ctx->payload.wire_buf),
	// 		&sent, 0, -1, &vec,
	// 		0, quic_timestamp());
	//
	// if (nwrite <= 0) {
	// 	kr_log_error(DOQ, "ngtcp2_writev failed %s (%d)\n",
	// 			ngtcp2_strerror(nwrite), nwrite);
	// 	return protolayer_break(ctx, kr_error(EINVAL));
	// }
	//
	// if (wire_buf_consume(ctx->payload.wire_buf, nwrite) != kr_ok()) {
	// 	kr_log_error(DOQ, "WB too small to take ngtcp2_conn_writev payload\n");
	// }
	//
	// kr_log_info(DOQ, "in CONN WRAP, consumed: %d\n", nwrite);
	//
	// return protolayer_continue(ctx);
	//
	// // int ret = kr_ok();
	// // struct pl_quic_conn_sess_data *quic_conn = sess_data;
	// //
	// // queue_push(quic_conn->wrap_queue, ctx);
	// //
	// // while (protolayer_queue_has_payload(&quic_conn->wrap_queue)) {
	// // 	struct protolayer_iter_ctx *data = queue_head(quic_conn->wrap_queue);
	// // 	queue_pop(quic_conn->wrap_queue);
	// //
	// // 	if (!quic_conn->conn) {
	// // 		/* here branching for client and server based on outgoing?
	// // 		 * It doesn't really make sence for client to ever
	// // 		 * receive conn == NULL in unwrap direction */
	// //
	// // 		// if ((ret = quic_init_server_conn(quic->conn_table, ctx,
	// // 		// 		 UINT64_MAX - 1, &target->scid, &target->dcid,
	// // 		// 		 *dec_cids, pkt, pktlen, &qconn)) != kr_ok()) {
	// // 		// if ((ret = quic_init_server_conn(quic_conn, ctx,
	// // 		// 		 UINT64_MAX - 1)) != kr_ok()) {
	// // 		// 	kr_log_error(DOQ, "Failed to initiate quic server %s (%d)\n",
	// // 		// 			ngtcp2_strerror(ret), ret);
	// // 		// 	return protolayer_break(data, ret);
	// // 		// }
	// //
	// // 		ret = handle_packet(quic_conn, data);
	// // 	}
	// // }
	// //
	// // return protolayer_break(ctx, kr_ok());
}

/* TODO perhaps also move to quic_stream */
// static int send_stream(struct pl_quic_conn_sess_data *conn,
// 		struct protolayer_iter_ctx *ctx,
// 		// struct protolayer_payload *outwb,
// 		int64_t stream_id,
// 		uint8_t *data, size_t len, bool fin, ngtcp2_ssize *sent)
// {
// 	/* require empty wire_buf TODO maybe remove*/
// 	kr_require(wire_buf_data_length(ctx->payload.wire_buf) == 0);
// 	kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF);
// 	// kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_IOVEC);
//
// 	assert(stream_id >= 0 || (data == NULL && len == 0));
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
// 	const ngtcp2_path *path = ngtcp2_conn_get_path(conn->conn);
//
// 	ngtcp2_conn_info info = { 0 };
// 	ngtcp2_conn_get_conn_info(conn->conn, &info);
// 	int nwrite = ngtcp2_conn_writev_stream(conn->conn, path, &pi,
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
//
// 	protolayer_async();
// 	return session2_wrap(conn->h.session,
// 	// return session2_wrap_after(conn->h.session,
// 	// 		PROTOLAYER_TYPE_QUIC_CONN,
// 			ctx->payload,
// 			ctx->comm,
// 			NULL,
// 			// ctx->req,
// 			ctx->finished_cb,
// 			ctx->finished_cb_baton);
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
//
// /* Function for sending speciall packets, requires
//  * a message (which special data are we to send: CONN_CLOSE, RESET, ...)
//  * and a buffer to store the pkt in, for now ctx->payloay.wb
//  * For now only kr_quic_send ever call send_special, though this might proove
//  * to cause issues in situation where the connection has NOT been established
//  * and we still would like to send data (i.e. we do not have decoded cids)
//  * The only time we need to send_special without having at least the cids
//  * is then the decode_v_cid fails with NGTCP2_ERR_VERSION_NEGOTIATION */
// static int send_special(struct pl_quic_conn_sess_data *conn,
// 		struct protolayer_iter_ctx *ctx,
// 		/*kr_quic_table_t *quic_table, */ int action)
// 		/* ngtcp2_version_cid *decoded_cids) */
// 		// kr_quic_conn_t *relay /* only for connection close */)
// {
// 	if (wire_buf_data_length(ctx->payload.wire_buf) != 0) {
// 		kr_log_error(DOQ, "wire_buf in quic/send_special is expected to be empty\n");
// 		return kr_error(EINVAL);
// 	}
//
// 	uint64_t now = quic_timestamp();
// 	int dvc_ret = NGTCP2_ERR_FATAL;
//
// 	// if ((message == -QUIC_SEND_VERSION_NEGOTIATION
// 	// 		|| message == -QUIC_SEND_RETRY)
// 	// 		&& rpl->in_payload != NULL && rpl->in_payload->iov_len > 0) {
// 	// 	dvc_ret = ngtcp2_pkt_decode_version_cid(
// 	// 		&decoded_cids, rpl->in_payload->iov_base,
// 	// 		rpl->in_payload->iov_len, SERVER_DEFAULT_SCIDLEN);
// 	// }
//
// 	uint8_t rnd = 0;
// 	dnssec_random_buffer(&rnd, sizeof(rnd));
// 	uint32_t supported_quic[1] = { NGTCP2_PROTO_VER_V1 };
// 	ngtcp2_cid new_dcid;
// 	uint8_t retry_token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN];
// 	uint8_t stateless_reset_token[NGTCP2_STATELESS_RESET_TOKENLEN];
// 	uint8_t sreset_rand[NGTCP2_MIN_STATELESS_RESET_RANDLEN];
// 	dnssec_random_buffer(sreset_rand, sizeof(sreset_rand));
// 	ngtcp2_ccerr ccerr;
// 	ngtcp2_ccerr_default(&ccerr);
// 	ngtcp2_pkt_info pi = { 0 };
//
// 	// struct sockaddr_storage path_loc = { 0 }, path_rem = { 0 };
// 	// ngtcp2_path path = { .local  = { .addr = (struct sockaddr *)&path_loc, .addrlen = sizeof(path_loc) },
// 	//                      .remote = { .addr = (struct sockaddr *)&path_rem, .addrlen = sizeof(path_rem) },
// 	//                      .user_data = NULL };
// 	// ??
// 	// bool find_path = (rpl->ip_rem == NULL);
// 	// ??
// 	// assert(find_path == (bool)(rpl->ip_loc == NULL));
// 	// ??
// 	// assert(!find_path || rpl->handle_ret == -QUIC_SEND_EXCESSIVE_LOAD);
//
// 	int ret = 0;
// 	switch (action) {
// 	case -QUIC_SEND_VERSION_NEGOTIATION:
// 		ret = ngtcp2_pkt_write_version_negotiation(
// 			wire_buf_free_space(ctx->payload.wire_buf),
// 			wire_buf_free_space_length(ctx->payload.wire_buf),
// 			rnd, conn->dec_cids.scid, conn->dec_cids.scidlen,
// 			conn->dec_cids.dcid, conn->dec_cids.dcidlen, supported_quic,
// 			sizeof(supported_quic) / sizeof(*supported_quic)
// 		);
// 		break;
// 		
// 	/* Returned by ngtcp2_conn_read_pkt
// 	 * Server must perform address validation by sending Retry packet
// 	 * (see `ngtcp2_crypto_write_retry` and `ngtcp2_pkt_write_retry`),
// 	 * and discard the connection state.  Client application does not
// 	 * get this error code. */
// 	case -QUIC_SEND_RETRY:
// 		// ngtcp2_cid_init(&dcid, decoded_cids->dcid, decoded_cids->dcidlen);
// 		// ngtcp2_cid_init(&scid, decoded_cids->scid, decoded_cids->scidlen);
// 		if (!conn || !ctx->comm || ! ctx->comm->target) {
// 			kr_log_error(DOQ, "unable to send Retry packet due to missing data\n");
// 			// return kr_error(EINVAL);
// 			break;
// 		}
//
// 		kr_require(conn && ctx->comm->target);
// 		ngtcp2_addr remote = ngtcp2_conn_get_path(conn->conn)->remote;
// 		struct quic_target *target = ctx->comm->target;
// 		init_random_cid(&new_dcid, 0);
//
// 		/* FIXME: quic_table will probably not be available here, and
// 		 * if it will be it shall be in pl_quic_conn_sess_data */
// 		// ret = ngtcp2_crypto_generate_retry_token(
// 		// 	retry_token, (const uint8_t *)quic_table->hash_secret,
// 		// 	sizeof(quic_table->hash_secret), decoded_cids->version,
// 		// 	(const struct sockaddr *)remote.addr, remote.addrlen,
// 		// 	&new_dcid, &target->dcid, now
// 		// );
//
// 		if (ret >= 0) {
// 			ret = ngtcp2_crypto_write_retry(
// 				wire_buf_free_space(ctx->payload.wire_buf),
// 				wire_buf_free_space_length(ctx->payload.wire_buf),
// 				conn->dec_cids.version, &conn->scid,
// 				&new_dcid, &conn->dcid,
// 				retry_token, ret
// 			);
// 			if (ret == -1) {
// 				// TODO
// 			}
// 		} else {
// 			kr_log_error(DOQ, "failed to generate Retry token\n");
// 			// return kr_error(ret);
// 		}
// 		break;
// 	case -QUIC_SEND_STATELESS_RESET:
// 		ret = ngtcp2_pkt_write_stateless_reset(
// 			wire_buf_free_space(ctx->payload.wire_buf),
// 			wire_buf_free_space_length(ctx->payload.wire_buf),
// 			stateless_reset_token, sreset_rand, sizeof(sreset_rand)
// 		);
// 		break;
// 	case -QUIC_SEND_CONN_CLOSE:
// 		ret = ngtcp2_conn_write_connection_close(
// 			conn->conn, NULL, &pi,
// 			wire_buf_free_space(ctx->payload.wire_buf),
// 			wire_buf_free_space_length(ctx->payload.wire_buf),
// 			&ccerr, now
// 		);
// 		break;
// 	case -QUIC_SEND_EXCESSIVE_LOAD:
// 		ccerr.type = NGTCP2_CCERR_TYPE_APPLICATION;
// 		ccerr.error_code = KR_QUIC_ERR_EXCESSIVE_LOAD;
// 		ret = ngtcp2_conn_write_connection_close(
// 			conn->conn,
// 			/* can this contain nonsence data? */
// 			ngtcp2_conn_get_path(conn->conn),
// 			&pi,
// 			wire_buf_free_space(ctx->payload.wire_buf),
// 			wire_buf_free_space_length(ctx->payload.wire_buf),
// 			&ccerr, now
// 		);
// 		break;
// 	default:
// 		ret = kr_error(EINVAL);
// 		break;
// 	}
//
// 	if (ret < 0) {
// 		wire_buf_reset(ctx->payload.wire_buf);
// 	} else {
// 		// TODO:
// 		// if (wire_buf_consume(ctx->payload.wire_buf, ret) == kr_ok()) {
// 		// 	int wrap_ret = session2_wrap_after(ctx->session,
// 		// 			PROTOLAYER_TYPE_QUIC, ctx->payload, ctx->comm,
// 		// 			// PROTOLAYER_TYPE_QUIC_CONN, ctx->payload, ctx->comm,
// 		// 			ctx->finished_cb, ctx->finished_cb_baton);
// 		// 	if (wrap_ret < 0) {
// 		// 		ret = wrap_ret;
// 		// 	}
// 		//
// 		// } else {
// 		// 	kr_log_error(DOQ, "Wire_buf failed to consume: %s (%d)\n",
// 		// 			ngtcp2_strerror(ret), ret);
// 		// 	// goto exit;
// 		// }
// 	}
//
// 	return ret;
// }

// void kr_quic_stream_mark_sent(struct pl_quic_conn_sess_data *conn,
// 		int64_t stream_id, size_t amount_sent)
// {
// 	struct pl_quic_stream_sess_data *s = kr_quic_conn_get_stream(conn, stream_id, false);
// 	if (s == NULL) {
// 		return;
// 	}
//
// 	s->unsent_offset += amount_sent;
// 	assert(s->unsent_offset <= s->unsent_obuf->len);
// 	if (s->unsent_offset == s->unsent_obuf->len) {
// 		s->unsent_offset = 0;
// 		s->unsent_obuf = (kr_quic_obuf_t *)s->unsent_obuf->node.next;
// 		if (s->unsent_obuf->node.next == NULL) { // already behind the tail of list
// 			s->unsent_obuf = NULL;
// 		}
// 	}
// }
//
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
// 		ret = send_stream(conn, ctx, stream_id, uo->buf + uf,
// 				  uo->len - uf - ignore_last, fin, &sent);
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
// 		ret = send_stream(conn, ctx, -1, NULL, 0, false, &unused);
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

/** buffer resolved payload in wire format, this buffer
 * is used to create quic stream data. Data in this buffer
 * MUST be kept until ack frame confirms their retrieval
 * or the stream gets closed. */

// int kr_quic_stream_add_data(struct pl_quic_conn_sess_data *conn,
// 		int64_t stream_id, struct protolayer_payload *pl)
// {
//
// 	struct pl_quic_stream_sess_data *s = kr_quic_conn_get_stream(conn, stream_id, true);
// 	//FIXME
// 	if (!s)
// 		return 0;
// 	// kr_require(s);
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
// 	list_t *list = (list_t *)&s->outbufs;
// 	if (EMPTY_LIST(*list)) {
// 		s->unsent_obuf = obuf;
// 	}
// 	add_tail((list_t *)&s->outbufs, (node_t *)obuf);
// 	s->obufs_size += obuf->len;
// 	conn->obufs_size += obuf->len;
// 	// conn->quic_table->obufs_size += obuf->len;
//
// 	return len;
// }

static void stream_outprocess(struct pl_quic_conn_sess_data *conn,
		struct pl_quic_stream_sess_data *stream)
{
	if (stream != &conn->streams[conn->stream_inprocess]) {
		return;
	}

	for (int16_t idx = conn->stream_inprocess + 1; idx < conn->streams_count; idx++) {
		stream = &conn->streams[idx];
		if (wire_buf_data_length(&stream->pers_inbuf) != 0) {
			conn->stream_inprocess = stream - conn->streams;
			return;
		}
	}

	conn->stream_inprocess = -1;
	--conn->streams_pending;
}

// struct pl_quic_stream_sess_data *kr_quic_stream_get_process(
// 		struct pl_quic_conn_sess_data *conn, int64_t *stream_id)
// {
// 	if (conn == NULL || conn->stream_inprocess < 0) {
// 		return NULL;
// 	}
//
// 	struct kr_quic_stream *stream = &conn->streams[conn->stream_inprocess];
// 	*stream_id = (conn->first_stream_id + conn->stream_inprocess) * 4;
// 	stream_outprocess(conn, stream);
// 	return stream;
// }

// void kr_quic_stream_ack_data(struct pl_quic_conn_sess_data *conn, int64_t stream_id,
//                                size_t end_acked, bool keep_stream)
// {
// 	struct pl_quic_stream_sess_data *s = kr_quic_conn_get_stream(conn,
// 			stream_id, false);
// 	if (s == NULL) {
// 		return;
// 	}
//
// 	struct list *obs = &s->outbufs;
//
// 	struct kr_quic_obuf *first;
//
// 	while (!EMPTY_LIST(*obs) && end_acked >= (first = HEAD(*obs))->len + s->first_offset) {
// 		rem_node(&first->node);
// 		assert(HEAD(*obs) != first); // help CLANG analyzer understand
// 					     // what rem_node did and that
// 					     // usage of HEAD(*obs) is safe
// 		s->obufs_size -= first->len;
// 		conn->obufs_size -= first->len;
// 		// conn->quic_table->obufs_size -= first->len;
// 		s->first_offset += first->len;
// 		free(first);
// 		if (s->unsent_obuf == first) {
// 			s->unsent_obuf = EMPTY_LIST(*obs) == 0 ? NULL : HEAD(*obs);
// 			s->unsent_offset = 0;
// 		}
// 	}
//
// 	if (EMPTY_LIST(*obs) && !keep_stream) {
// 		stream_outprocess(conn, s);
// 		memset(s, 0, sizeof(*s));
// 		init_list(&s->outbufs);
// 		while (s = &conn->streams[0],
// 				wire_buf_data_length(&s->pers_inbuf) == 0 &&
// 				s->obufs_size == 0) {
// 			kr_assert(conn->streams_count > 0);
// 			conn->streams_count--;
//
// 			if (conn->streams_count == 0) {
// 				free(conn->streams);
// 				conn->streams = 0;
// 				conn->first_stream_id = 0;
// 				break;
// 			} else {
// 				conn->first_stream_id++;
// 				conn->stream_inprocess--;
// 				memmove(s, s + 1, sizeof(*s) * conn->streams_count);
// 				// possible realloc to shrink allocated space,
// 				// but probably useless
// 				for (struct pl_quic_stream_sess_data *si = s;
// 						si < s + conn->streams_count;
// 						si++) {
// 					if (si->obufs_size == 0) {
// 						init_list(&si->outbufs);
// 					} else {
// 						fix_list(&si->outbufs);
// 					}
// 				}
// 			}
// 		}
// 	}
// }

/* store the index of the first stream that has a
 * query ready to be resolved in conn->stream_inprocess */
void stream_inprocess(struct pl_quic_conn_sess_data *conn, struct pl_quic_stream_sess_data *stream)
{
	int16_t idx = stream - conn->streams;
	assert(idx >= 0);
	assert(idx < conn->streams_count);
	if (conn->stream_inprocess < 0 || conn->stream_inprocess > idx) {
		conn->stream_inprocess = idx;
	}
}

// int update_stream_pers_buffer(const uint8_t *data, size_t len,
// 		struct pl_quic_stream_sess_data *stream, int64_t stream_id)
// {
// 	kr_require(len > 0 && data && stream);
//
// 	kr_log_info(DOQ, "updating pers_buffer of stream %ld, with %zu data, it already contained %zu bytes\n",
// 			stream_id, len, wire_buf_data_length(&stream->pers_inbuf));
//
// 	// struct wire_buf wb = stream->pers_inbuf;
// 	if (wire_buf_free_space_length(&stream->pers_inbuf) < len) {
// 		kr_log_error(DOQ, "wire buf for stream no. %ld ran out of available space needed: %zu, available: %zu\n",
// 				stream_id, len,
// 				wire_buf_free_space_length(&stream->pers_inbuf));
// 		return kr_error(ENOMEM);
// 	}
//
// 	// Assert would be better, this happenning is most likely a mistake */
// 	// kr_require(wire_buf_data_length(&stream->pers_inbuf) == 0);
//
// 	memcpy(wire_buf_free_space(&stream->pers_inbuf), data, len);
// 	/* FIXME reqire for now, though this is hardly the desired check */
// 	kr_require(wire_buf_consume(&stream->pers_inbuf, len) == kr_ok());
//
// 	return kr_ok();
// }

/* FIXME: */
#define QBUFSIZE 256u

int kr_quic_stream_recv_data(struct pl_quic_conn_sess_data *conn,
		int64_t stream_id, const uint8_t *data, size_t len, bool fin)
{
	if (len == 0 || conn == NULL || data == NULL) {
		return KNOT_EINVAL;
	}

	struct pl_quic_stream_sess_data *stream = kr_quic_conn_get_stream(conn, stream_id, true);
	if (stream == NULL) {
		return KNOT_ENOENT;
	}

	conn->streams_pending++;
	if (!stream->pers_inbuf.buf) {
		wire_buf_init(&stream->pers_inbuf, /* FIXME */QBUFSIZE);
	}

	// struct iovec in = { (void *)data, len };
	// ssize_t prev_ibufs_size = qconn->ibufs_size;
	// size_t save_total = qconn->ibufs_size;

	kr_log_info(DOQ, "about to update stream's %ld, pers_buffer with %zu data\n",
			stream_id, len);
	int ret;
	// if ((ret = update_stream_pers_buffer(data, len, stream, stream_id)) != kr_ok()) {
	// 	return ret;
	// }

	// int ret = knot_tcp_inbufs_upd(&stream->inbuf, in, true,
	// 		&stream->inbufs, &qconn->ibufs_size);

	// TODO:
	// int ret = kr_tcp_inbufs_upd(&stream->inbuf, in, true,
	//                               &stream->inbufs, &conn->ibufs_size);
	// int ret = KNOT_EOK;

	// qconn->quic_table->ibufs_size += (ssize_t)qconn->ibufs_size - prev_ibufs_size;
	// if (ret != KNOT_EOK) {
	// 	return ret;
	// }

	// if (fin && stream->inbufs == NULL) {
	// 	return KNOT_ESEMCHECK;
	// }

	if (fin) {
		stream_inprocess(conn, stream);
	}

	return kr_ok();
}


// void kr_quic_conn_stream_free(struct pl_quic_conn_sess_data *conn, int64_t stream_id)
// {
//
// 	struct pl_quic_stream_sess_data *s = kr_quic_conn_get_stream(conn, stream_id, false);
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

/* FIXME */
#define OUTBUF_SIZE 131072
static int pl_quic_conn_sess_init(struct session2 *session, void *sess_data, void *param)
{
	struct pl_quic_conn_sess_data *conn = sess_data;
	// conn->h.session = session;
	conn->flags = 0u;
	conn->ibufs_size = 0;
	session->secure = true;
	queue_init(conn->wrap_queue);
	queue_init(conn->unwrap_queue);

	kr_require(param);
	struct kr_quic_conn_param *p = param;
	conn->dcid = p->dcid;
	conn->scid = p->scid;
	conn->odcid = p->odcid;
	memcpy(&conn->dec_cids, p->dec_cids, sizeof(ngtcp2_version_cid));

	struct comm_info *comm = p->comm_storage;
	if (comm->src_addr) {
			int len = kr_sockaddr_len(comm->src_addr);
		kr_require(len > 0 && len <= sizeof(union kr_sockaddr));
		memcpy(&conn->comm_storage.src_addr, comm->src_addr, len);
	}
	if (comm->comm_addr) {
		int len = kr_sockaddr_len(comm->comm_addr);
		kr_require(len > 0 && len <= sizeof(union kr_sockaddr));
		memcpy(&conn->comm_storage.comm_addr, comm->comm_addr, len);
	}
	if (comm->dst_addr) {
		int len = kr_sockaddr_len(comm->dst_addr);
		kr_require(len > 0 && len <= sizeof(union kr_sockaddr));
		memcpy(&conn->comm_storage.dst_addr, comm->dst_addr, len);
	}

	queue_init(conn->pending_unwrap);

	// if (!the_network->tls_credentials) {
	// 	kr_log_info(DOQ, "tls credentials were not present at the start of DoQ iteration\n");
	// 	the_network->tls_credentials = tls_get_ephemeral_credentials();
	// 	if (!the_network->tls_credentials) {
	// 		kr_log_error(TLS, "X.509 credentials are missing, and ephemeral credentials failed; no TLS\n");
	// 		return kr_error(EINVAL);
	// 	}
	//
	// 	kr_log_info(TLS, "Using ephemeral TLS credentials\n");
	// }

	// struct tls_credentials *creds = the_network->tls_credentials;
	// kr_require(creds->credentials != NULL);

	wire_buf_init(&conn->unwrap_buf, OUTBUF_SIZE);

	/* initiate with first payload */
	conn->conn = NULL;

	// TODO set setings?

	return 0;
}


static int pl_quic_conn_sess_deinit(struct session2 *session, void *sess_data)
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

static enum protolayer_event_cb_result pl_quic_conn_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if (event == PROTOLAYER_EVENT_CLOSE) {
		kr_log_info(DOQ, "CONN TO CLOSE FROM EVENT UNWRAP\n");
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_quic_conn_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	// session2_tasklist_finalize(session, 0/* FIXME */);
	// session2_waitinglist_finalize(session, 0/* FIXME */);
	if (event == PROTOLAYER_EVENT_CLOSE) {
		kr_log_info(DOQ, "CONN TO CLOSE FROM EVENT WRAP\n");
		pl_quic_conn_sess_deinit(session, sess_data);
	}

	// return PROTOLAYER_EVENT_PROPAGATE;
	return PROTOLAYER_EVENT_CONSUME;
}

static void pl_quic_request_init(struct session2 *session,
		struct kr_request *req, void *sess_data)
{
	kr_log_warning(DOQ, "IN request init\n");
	req->qsource.comm_flags.quic = true;
	// struct pl_quic_sess_data *quic = sess_data;
	// quic->req = req;

	// req->qsource.stream_id = session->comm_storage.target;
}

__attribute__((constructor))
static void quic_conn_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_QUIC_CONN] = (struct protolayer_globals) {
		.sess_size = sizeof(struct pl_quic_conn_sess_data),
		// .iter_size = sizeof(struct ),
		/* FIXME: change to MAX_QUIC_PKT_SIZE*/
		.wire_buf_overhead = MAX_QUIC_FRAME_SIZE,
		// .iter_init = pl_quic_iter_init,
		// .iter_deinit = pl_quic_iter_deinit,
		.sess_init = pl_quic_conn_sess_init,
		.sess_deinit = pl_quic_conn_sess_deinit,
		.unwrap = pl_quic_conn_unwrap,
		.wrap = pl_quic_conn_wrap,
		.event_unwrap = pl_quic_conn_event_unwrap,
		.event_wrap = pl_quic_conn_event_wrap,
		.request_init = pl_quic_request_init,
	};
}
