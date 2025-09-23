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
#include "quic_stream.h"
#include "session2.h"
#include <ngtcp2/ngtcp2.h>
#include <string.h>


/* Quic connection state set functions */
#define QUIC_SET_DRAINING(conn) { \
	conn->state = DRAINING; \
}
#define QUIC_SET_CLOSING(conn) { \
	conn->state = CLOSING; \
}
#define QUIC_SET_HS_COMPLETED(conn) { \
	conn->state = HANDSHAKE_DONE; \
}

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
	uint64_t now = quic_timestamp();
	const ngtcp2_path *path = ngtcp2_conn_get_path(conn->conn);
	ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };

	// while (ngtcp2_conn_read_pkt(qconn->conn, path, &pi, pkt, pktlen, now) == 0);
	int ret = ngtcp2_conn_read_pkt(conn->conn, path, &pi,
			wire_buf_data(ctx->payload.wire_buf),
			wire_buf_data_length(ctx->payload.wire_buf), now);

	switch (ret) {
	case NGTCP2_ERR_RETRY:
		/* TODO: SERVER must perform address validation
		 * see: https://nghttp2.org/ngtcp2/ngtcp2_conn_read_pkt.html#c.ngtcp2_conn_read_pkt */
		return -1;
	case NGTCP2_ERR_DROP_CONN:
		/* We have to drop the conn silently, hence the force */
		QUIC_SET_CLOSING(conn);
		session2_force_close(conn->h.session);
		break;
	case NGTCP2_ERR_DRAINING:
		QUIC_SET_DRAINING(conn);
		session2_event(conn->h.session->transport.parent,
				PROTOLAYER_EVENT_DISCONNECT, conn);
		// session2_event(conn->h.session, PROTOLAYER_EVENT_DISCONNECT, NULL);
		// session2_close(conn->h.session);
		return -1;
	case NGTCP2_ERR_CLOSING:
		QUIC_SET_CLOSING(conn);
		break;
	case NGTCP2_ERR_CRYPTO:
		/* TODO: set or check that set */
		kr_log_error(DOQ, "TLS stack error %d\n",
				ngtcp2_conn_get_tls_alert(conn->conn));
		/* TODO: close connection? */
		break;
	default:
		/* TODO: call the following to get terminal packet and
		 * and session */
		// ngtcp2_conn_write_connection_close(CONN, PATH, PI, DEST, DESTLEN, CCERR, TS)
		break;
	}

	// ngtcp2_conn_handle_expiry(conn->conn, now);

	/* given the 0 return value the pkt has been processed */
	wire_buf_reset(ctx->payload.wire_buf);
	return kr_ok();
}

static int handshake_completed_cb(ngtcp2_conn *_unused, void *user_data)
{
	(void)_unused;

	kr_log_info(DOQ, "Handshake completed\n");
	struct pl_quic_conn_sess_data *conn = user_data;
	QUIC_SET_HS_COMPLETED(conn);

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
	int count = 2;
	while (count --> 0) {


	int ret = NGTCP2_ERR_NOMEM;
	struct pl_quic_conn_sess_data *conn = user_data;
	/* FIXME: send on stack */

	struct kr_quic_stream_param params = {
		.stream_id = stream_id,
		.conn = connection,
		.comm_storage = conn->comm_storage,
	};
	struct protolayer_data_param data_param = {
		.protocol = PROTOLAYER_TYPE_QUIC_STREAM,
		.param = &params
	};
	struct session2 *new_stream_sess =
		session2_new_child(conn->h.session,
				KR_PROTO_DOQ_STREAM,
				&data_param,
				1 /* FIXME */,
				false);

	struct pl_quic_stream_sess_data *stream_sess_data =
		protolayer_sess_data_get_proto(new_stream_sess,
				PROTOLAYER_TYPE_QUIC_STREAM);

	if (!new_stream_sess)
		kr_log_error(DOQ, "Failed to init child session\n");

	kr_require(new_stream_sess);


	size_t new_streams_count = 0;
	struct pl_quic_stream_sess_data *new_streams;

	// should we attempt to purge unused streams here?
	// maybe only when we approach the limit
	if (conn->streams_count == 0) {
		conn->first_stream_offset = 0;
		new_streams = malloc(sizeof(new_streams[0]));
		if (new_streams == NULL) {
			goto fail;
		}
		new_streams_count = 1;
	} else {
		new_streams_count = stream_id + 1 - conn->first_stream_offset;
		if (new_streams_count > MAX_STREAMS_PER_CONN) {
			goto fail;
		}
		new_streams = realloc(conn->streams,
				new_streams_count * sizeof(*new_streams));
		if (new_streams == NULL) {
			goto fail;
		}
	}

	conn->streams = new_streams;
	conn->streams_count = new_streams_count;
	conn->streams[conn->streams_count] = stream_sess_data;

	// for (struct pl_quic_stream_sess_data *si = new_streams;
	// 		si < new_streams + conn->streams_count; si++) {
	// 	if (si->obufs_size == 0) {
	// 		init_list(&si->outbufs);
	// 	} else {
	// 		fix_list(&si->outbufs);
	// 	}
	// }
		
	// for (struct pl_quic_stream_sess_data *si = new_streams + conn->streams_count;
	// 		si < new_streams + new_streams_count; si++) {
	// 	// memset(si, 0, sizeof(*si));
	// 	init_list(&si->outbufs);
	// }

	kr_require(ngtcp2_conn_set_stream_user_data(connection, stream_id,
				stream_sess_data) == NGTCP2_NO_ERROR);


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

	ret = NGTCP2_NO_ERROR;
	return ret;

fail:
	if (new_stream_sess) {
		session2_close(new_stream_sess);
	}

	return ret;
}

static int stream_close_cb(ngtcp2_conn *_unused, uint32_t flags, int64_t stream_id,
			 uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	(void)_unused;

	kr_log_info(DOQ, "closing stream no %zu\n", stream_id);
	struct pl_quic_conn_sess_data *conn = user_data;
	struct pl_quic_conn_sess_data *stream = stream_user_data;
	/* FIXME: This will currently propagate to event close in conn
	 * but we only want to close the stream here */
	session2_event(stream->h.session, PROTOLAYER_EVENT_CLOSE, NULL);
	// session2_close(stream->h.session);
	--conn->streams_count;

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

/* FIXME: MOVE REMOVE AND USE DIFFERENT VALUE*/
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
	struct pl_quic_conn_sess_data *conn = sess_data;
	queue_deinit(conn->wrap_queue);
	queue_deinit(conn->unwrap_queue);
	wire_buf_deinit(&conn->unwrap_buf);
	kr_require(conn->streams_count == 0);
	free(conn->streams);
	gnutls_deinit(conn->tls_session);
	ngtcp2_conn_del(conn->conn);
	conn->conn = NULL;

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
	struct pl_quic_conn_sess_data *conn = sess_data;
	kr_log_info(DOQ, "entered QUIC CONN E: %d UNWRAP dcid: %s\n",
			event, conn->dcid.data);

	if (event == PROTOLAYER_EVENT_DISCONNECT ||
			event == PROTOLAYER_EVENT_CLOSE ||
			event == PROTOLAYER_EVENT_FORCE_CLOSE) {
		while (conn->streams_count > 0) {
		// for (uint16_t i = 0; i < conn->streams_count; i++) {
			struct pl_quic_stream_sess_data stream =
				conn->streams[conn->first_stream_offset];

			session2_event(stream.h.session,
					PROTOLAYER_EVENT_FORCE_CLOSE,
					NULL);

			--conn->streams_count;
			if (conn->streams_count > 0) {
				conn->first_stream_offset++;
			} else {
				conn->first_stream_offset = 0;
			}
		}

		// session2_close(session);
		pl_quic_conn_sess_deinit(session, sess_data);
		return PROTOLAYER_EVENT_CONSUME;
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_quic_conn_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	struct pl_quic_conn_sess_data *conn = sess_data;
	kr_log_info(DOQ, "entered QUIC CONN E WRAP dcid: %s\n",
			conn->dcid.data);

	if (event == PROTOLAYER_EVENT_CLOSE && *baton) {


	}
	// session2_tasklist_finalize(session, 0/* FIXME */);
	// session2_waitinglist_finalize(session, 0/* FIXME */);
	// if (event == PROTOLAYER_EVENT_DISCONNECT) {
	// 	kr_log_info(DOQ, "CONN TO CLOSE FROM EVENT WRAP\n");
	// 	// pl_quic_conn_sess_deinit(session, sess_data);
	// }

	return PROTOLAYER_EVENT_PROPAGATE;
	// return PROTOLAYER_EVENT_CONSUME;
}

static void pl_quic_request_init(struct session2 *session,
		struct kr_request *req, void *sess_data)
{
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
