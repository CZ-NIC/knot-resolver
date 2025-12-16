/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "quic_conn.h"
#include "network.h"
#include "quic_common.h"
#include "quic_stream.h"
#include "libdnssec/random.h"
#include "libdnssec/error.h"
#include "worker.h"

#define EPHEMERAL_CERT_EXPIRATION_SECONDS_RENEW_BEFORE ((time_t)60*60*24*7)

/* QUIC only works with TLSv1.3, auth KnotDNS have experienced issues
 * likely caused by v1.3 compat mode */
static const char * const tlsv13_priorities =
	"NORMAL:" /* GnuTLS defaults */
	"-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2:+VERS-TLS1.3:" /* TLS 1.3 only */
	"-VERS-SSL3.0:-ARCFOUR-128:-COMP-ALL:+COMP-NULL";


static int pl_quic_conn_sess_deinit(struct session2 *session, void *sess_data);

static int handle_packet(struct pl_quic_conn_sess_data *conn,
		struct protolayer_iter_ctx *ctx, quic_doq_error_t *doq_error)
{
	uint64_t now = quic_timestamp();
	ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };
	*doq_error = DOQ_NO_ERROR;

	int ret = -1;
	if (ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF) {
		ret = ngtcp2_conn_read_pkt(conn->conn, conn->path, &pi,
				wire_buf_data(ctx->payload.wire_buf),
				wire_buf_data_length(ctx->payload.wire_buf), now);
	} else {
		ret = ngtcp2_conn_read_pkt(conn->conn, conn->path, &pi,
				ctx->payload.buffer.buf,
				ctx->payload.buffer.len, now);
	}

	if (ret == 0) {
		/* given the 0 return value the pkt has been processed */
		wire_buf_reset(ctx->payload.wire_buf);
		return kr_ok();
	}

	switch (ret) {
	case NGTCP2_ERR_RETRY:
		/* "Server must perform address validation by sending Retry packet
		 * (see ngtcp2_crypto_write_retry() and ngtcp2_pkt_write_retry()),
		 * and discard the connection state. Client application does
		 * not get this error code." */
		return QUIC_SEND_RETRY;
	case NGTCP2_ERR_DROP_CONN:
	case NGTCP2_ERR_DRAINING:
	case NGTCP2_ERR_CLOSING:
		*doq_error = DOQ_UNSPECIFIED_ERROR;
		QUIC_SET_DRAINING(conn);
		return QUIC_SEND_CONN_CLOSE;
	case NGTCP2_ERR_CRYPTO:
		*doq_error = DOQ_INTERNAL_ERROR;
		kr_log_error(DOQ, "TLS stack error %d\n",
				ngtcp2_conn_get_tls_alert(conn->conn));
		QUIC_SET_DRAINING(conn);
		return QUIC_SEND_CONN_CLOSE;
	default:
		*doq_error = DOQ_UNSPECIFIED_ERROR;
		QUIC_SET_CLOSING(conn);
		return QUIC_SEND_CONN_CLOSE;
	}

	return ret;
}

static struct tls_credentials *tls_credentials_reserve(struct tls_credentials *tls_credentials)
{
	if (!tls_credentials) {
		return NULL;
	}
	tls_credentials->count++;
	return tls_credentials;
}

static int handshake_completed_cb(ngtcp2_conn *ngconn, void *user_data)
{
	(void)ngconn;
	QUIC_SET_HS_COMPLETED((struct pl_quic_conn_sess_data *)user_data);
	return kr_ok();
}

static int kr_recv_stream_data_cb(ngtcp2_conn *ngconn, uint32_t flags,
	int64_t stream_id, uint64_t offset, const uint8_t *data,
	size_t datalen, void *user_data, void *stream_user_data)
{
	struct pl_quic_conn_sess_data *conn = user_data;
	struct pl_quic_stream_sess_data *stream = stream_user_data;

	stream->incflags = flags;
	stream->sdata_offset = offset;

	if (wire_buf_free_space_length(&stream->pers_inbuf) < datalen) {
		char *new_buf = realloc(stream->pers_inbuf.buf,
				wire_buf_data_length(&stream->pers_inbuf) + datalen);
		kr_require(new_buf);
		stream->pers_inbuf.buf = new_buf;
		stream->pers_inbuf.size += datalen;
	}

	if (datalen == 0) {
		/* This is invalid see ngtcp2_recv_stream_data doc */
		if (!(flags & NGTCP2_STREAM_DATA_FLAG_FIN)) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}

		goto finished;
	}

	if (offset == 0) {
		memcpy(wire_buf_free_space(&stream->pers_inbuf), data, datalen);
		wire_buf_consume(&stream->pers_inbuf, datalen);
	} else {
		/* remove size header from new data and add it to the start of wb. */
		memcpy(wire_buf_free_space(&stream->pers_inbuf), data + sizeof(uint16_t), datalen - sizeof(uint16_t));
		knot_wire_write_u16(wire_buf_data(&stream->pers_inbuf),
				knot_wire_read_u16(wire_buf_data(&stream->pers_inbuf)) + datalen - sizeof(uint16_t));
		wire_buf_consume(&stream->pers_inbuf, datalen - sizeof(uint16_t));
	}

	(void)ngtcp2_conn_extend_max_stream_offset(ngconn, stream_id, datalen);
	ngtcp2_conn_extend_max_offset(ngconn, datalen);

finished:
	if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
		queue_push(conn->pending_unwrap, stream);
	}

	return kr_ok();
}

static int acked_stream_data_offset_cb(ngtcp2_conn *ngconn,
		int64_t stream_id, uint64_t offset, uint64_t datalen,
		void *user_data, void *stream_user_data)
{
	(void)ngconn;
	struct pl_quic_stream_sess_data *stream = stream_user_data;
	kr_quic_stream_ack_data(stream, stream_id, offset + datalen, false);
	return NGTCP2_NO_ERROR;
}

static int stream_open_cb(ngtcp2_conn *ngconn,
		int64_t stream_id, void *user_data)
{
	struct pl_quic_conn_sess_data *conn = user_data;
	struct kr_quic_stream_param params = {
		.stream_id = stream_id,
		.conn = ngconn,
		.comm_storage = conn->comm_storage,
	};
	struct protolayer_data_param data_param = {
		.protocol = PROTOLAYER_TYPE_QUIC_STREAM,
		.param = &params
	};
	struct session2 *new_subsession =
		session2_new_child(conn->h.session,
				KR_PROTO_DOQ_STREAM,
				&data_param,
				1,
				false);

	if (!new_subsession) {
		kr_log_error(DOQ, "Failed to create new quic stream session\n");
		return kr_error(ENOMEM);
	}

	struct pl_quic_stream_sess_data *stream =
		protolayer_sess_data_get_proto(new_subsession,
				PROTOLAYER_TYPE_QUIC_STREAM);
	stream->conn_ref = conn;
	if (conn->streams_count <= 0) {
		add_head(&conn->streams, &stream->list_node);
	} else {
		add_tail(&conn->streams, &stream->list_node);
	}

	++conn->streams_count;
	ngtcp2_conn_set_stream_user_data(ngconn, stream_id, stream);

	return NGTCP2_NO_ERROR;
}

static int stream_close_cb(ngtcp2_conn *ngconn, uint32_t flags,
		int64_t stream_id, uint64_t app_error_code,
		void *user_data, void *stream_user_data)
{
	ngtcp2_conn_extend_max_streams_bidi(ngconn, 1);
	struct pl_quic_conn_sess_data *conn = user_data;
	struct pl_quic_stream_sess_data *stream = stream_user_data;
	rem_node(&stream->list_node);
	session2_close(stream->h.session);
	--conn->streams_count;
	++conn->finished_streams;

	return NGTCP2_NO_ERROR;
}

static void kr_quic_rand_cb(uint8_t *dest, size_t destlen,
	const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;
	dnssec_random_buffer(dest, destlen);
}

static int get_new_connection_id_cb(ngtcp2_conn *ngconn, ngtcp2_cid *cid,
		uint8_t *token, size_t cidlen, void *user_data)
{
	(void)ngconn;
	struct pl_quic_conn_sess_data *conn = user_data;
	session2_event(conn->h.session->transport.parent,
			PROTOLAYER_EVENT_CONNECT_UPDATE, conn);
	memcpy(cid, &conn->dcid, sizeof(ngtcp2_cid));

	if (ngtcp2_crypto_generate_stateless_reset_token(token, conn->secret,
				sizeof(conn->secret), cid) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

int remove_connection_id_cb(ngtcp2_conn *ngconn,
		const ngtcp2_cid *cid, void *user_data)
{
	(void)ngconn;
	struct pl_quic_conn_sess_data *conn = user_data;
	ngtcp2_cid save_cid = conn->dcid;
	memcpy(&conn->dcid, cid, sizeof(ngtcp2_cid));
	session2_event(conn->h.session->transport.parent,
			PROTOLAYER_EVENT_CONNECT_RETIRE,
			conn);
	conn->dcid = save_cid;
	return 0;
}

static void quic_debug_cb(void *user_data, const char *format, ...)
{
	char buf[256];
	va_list args;
	va_start(args, format);
	(void)vsnprintf(buf, sizeof(buf), format, args);
	kr_log_debug(DOQ_LIBNGTCP2, "%s\n", buf);
	va_end(args);
}

static int conn_new_handler(ngtcp2_conn **pconn, const ngtcp2_path *path,
		const ngtcp2_cid *scid, const ngtcp2_cid *dcid,
		const ngtcp2_cid *odcid, uint32_t version,
		uint64_t now, bool server, bool retry_sent,
		struct pl_quic_conn_sess_data *conn)
{
	const ngtcp2_callbacks callbacks = {
		// .client_initial = ngtcp2_crypto_client_initial_cb, // client side callback
		.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.handshake_completed = handshake_completed_cb,
		// .recv_version_negotiation,
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.recv_stream_data = kr_recv_stream_data_cb,
		.acked_stream_data_offset = acked_stream_data_offset_cb,
		.stream_open = stream_open_cb,
		.stream_close = stream_close_cb,
		// .recv_stateless_reset, - OPTIONAL
		// .ngtcp2_crypto_recv_retry_cb, - OPTIONAL
		// .extend_max_streams_bidi - OPTIONAL
		// .extend_max_streams_uni - OPTIONAL
		.rand = kr_quic_rand_cb,
		.get_new_connection_id = get_new_connection_id_cb,
		.remove_connection_id = remove_connection_id_cb,
		.update_key = ngtcp2_crypto_update_key_cb,
		// .path_validation, - OPTIONAL
		// .select_preferred_addr - OPTIONAL
		// .stream_rst, - OPTIONAL
		// .extend_max_remote_streams_bidi - OPTIONAL
		// .extend_max_remote_streams_uni - OPTIONAL
		// .extend_max_stream_data, - OPTIONAL
		// .dcid_status - OPTIONAL
		// .handshake_confirmed - OPTIONAL
		// .recv_new_token - OPTIONAL
		.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		// .recv_datagram - OPTIONAL
		// .ack_datagram - OPTIONAL
		// .lost_datagram - OPTIONAL
		.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
		// .stream_stop_sending - OPTIONAL
		.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
		// .recv_rx_key - OPTIONAL
		// .recv_tx_key - OPTIONAL
	};

	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = now;

	if (KR_LOG_LEVEL_IS(LOG_DEBUG)) {
		settings.log_printf = quic_debug_cb;
	}

	size_t limit =
		protolayer_globals[PROTOLAYER_TYPE_QUIC_CONN].wire_buf_max_overhead;

	if (limit != 0) {
		settings.max_tx_udp_payload_size = limit;
	}
	
	settings.handshake_timeout = QUIC_HS_IDLE_TIMEOUT;
	settings.no_pmtud = true;

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);

	/** This informs peer that active migration might not be available.
	 * Peer might still attempt to migrate. see RFC 9000/5.2.3 */
	params.disable_active_migration = true;

	/* We have no use for unidirectional streams */
	params.initial_max_streams_uni = 0;

	if (unlikely(kr_fails_assert(the_network && the_network->quic_params))) {
		kr_log_debug(DOQ, "Missing network struct or network quic_parameters\n");
		return kr_error(EINVAL);
	}
	params.initial_max_streams_bidi = the_network->quic_params->max_streams;
	params.initial_max_stream_data_bidi_local = MAX_QUIC_FRAME_SIZE;
	params.initial_max_stream_data_bidi_remote = MAX_QUIC_FRAME_SIZE;
	params.initial_max_data = MAX_QUIC_PKT_SIZE;
	params.max_idle_timeout = QUIC_CONN_IDLE_TIMEOUT;
	params.stateless_reset_token_present = 1;
	// params.active_connection_id_limit = 8;

	if (odcid != NULL) {
		params.original_dcid = *odcid;
		params.original_dcid_present = 1;
	}

	if (retry_sent) {
		/* retry scid is retrieved from the
		 * ngtcp2_crypto_verify_retry_roken2 as the odcid
		 * used by the client. */
		params.retry_scid = *dcid;
		params.retry_scid_present = 1;
	}

	if (dnssec_random_buffer(params.stateless_reset_token,
				NGTCP2_STATELESS_RESET_TOKENLEN) != DNSSEC_EOK) {
		return kr_error(DNSSEC_ERROR);
	}

	if (server) {
		return ngtcp2_conn_server_new(pconn, scid, dcid, path, version,
				&callbacks, &settings, &params, NULL, conn);
	} else {
		kr_log_warning(DOQ, "Client side is not implemented\n");
		return kr_error(EINVAL);
		// return ngtcp2_conn_client_new(pconn, dcid, scid, path, version, &callbacks,
		//                               &settings, &params, NULL, conn);
	}
}

static void kr_quic_set_addrs(struct protolayer_iter_ctx *ctx, ngtcp2_path **path)
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
	}

	(*path)->remote.addr = (struct sockaddr *)remote;
	(*path)->remote.addrlen = kr_sockaddr_len(remote);
	(*path)->local.addr = (struct sockaddr *)local;
	(*path)->local.addrlen = kr_sockaddr_len(local);
}

int kr_tls_server_session(struct pl_quic_conn_sess_data *conn)
{
	if (conn == NULL) {
		return kr_error(EINVAL);
	}

	time_t now = time(NULL);
	if (the_network->tls_credentials->valid_until != GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION) {
		if (the_network->tls_credentials->ephemeral_servicename) {
			/* ephemeral cert: refresh if due to expire within a week */
			if (now >= the_network->tls_credentials->valid_until - EPHEMERAL_CERT_EXPIRATION_SECONDS_RENEW_BEFORE) {
				struct tls_credentials *newcreds = tls_get_ephemeral_credentials();
				if (newcreds) {
					tls_credentials_release(the_network->tls_credentials);
					the_network->tls_credentials = newcreds;
					kr_log_info(TLS, "Renewed expiring ephemeral X.509 cert\n");
				} else {
					kr_log_error(TLS, "Failed to renew expiring ephemeral X.509 cert, using existing one\n");
				}
			}
		/* non-ephemeral cert: warn once when certificate expires */
		} else if (now >= the_network->tls_credentials->valid_until) {
			kr_log_error(TLS, "X.509 certificate has expired!\n");
			the_network->tls_credentials->valid_until =
				GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION;
		}
	}

	gnutls_priority_init2(&conn->priority, NULL, NULL, 0);

	int flags = GNUTLS_SERVER | GNUTLS_NONBLOCK;
#if GNUTLS_VERSION_NUMBER >= 0x030705
	if (gnutls_check_version("3.7.5"))
		flags |= GNUTLS_NO_TICKETS_TLS12;
#endif
	int ret = gnutls_init(&conn->tls_session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_init(): %s (%d)\n", gnutls_strerror_name(ret), ret);
		return ret;
	}

	gnutls_certificate_send_x509_rdn_sequence(conn->tls_session, 1);
	gnutls_certificate_server_set_request(conn->tls_session, GNUTLS_CERT_IGNORE);
	ret = gnutls_priority_set(conn->tls_session, conn->priority);

	conn->server_credentials = tls_credentials_reserve(the_network->tls_credentials);
	ret = gnutls_credentials_set(conn->tls_session, GNUTLS_CRD_CERTIFICATE,
				     conn->server_credentials->credentials);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_credentials_set(): %s (%d)\n", gnutls_strerror_name(ret), ret);
		return ret;
	}

	const char *errpos = NULL;
	int err = gnutls_set_default_priority_append(conn->tls_session,
			tlsv13_priorities, &errpos, 0);
	if (err != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "setting priority '%s' failed at character %zd (...'%s') with %s (%d)\n",
			     tlsv13_priorities, errpos - tlsv13_priorities,
			     errpos, gnutls_strerror_name(err), err);
		return kr_error(EINVAL);
	}

	if (the_network->tls_session_ticket_ctx) {
		tls_session_ticket_enable(the_network->tls_session_ticket_ctx,
					  conn->tls_session);
	}

	const gnutls_datum_t alpn_datum = {
		.data = (void *)"doq",
		.size = 3
	};
	gnutls_alpn_set_protocols(conn->tls_session, &alpn_datum, 1,
			GNUTLS_ALPN_MANDATORY);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_alpn_set_protocols(): %s (%d)\n", gnutls_strerror_name(ret), ret);
	}

	return ret;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	return ((struct pl_quic_conn_sess_data *)conn_ref->user_data)->conn;
}

static int tls_init_conn_session(struct pl_quic_conn_sess_data *conn, bool server)
{
	if (!server) {
		kr_log_error(DOQ, "Client side of QUIC is not implemented\n");
		return kr_error(EINVAL);
	}

	int ret;
	if (server) {
		ret = kr_tls_server_session(conn);
	} else {
		ret = kr_error(EINVAL);
	}

	if (ret != 0)
		return ret;

	ret = (server)
		? ngtcp2_crypto_gnutls_configure_server_session(conn->tls_session)
		: ngtcp2_crypto_gnutls_configure_client_session(conn->tls_session);
	if (ret != NGTCP2_NO_ERROR) {
		kr_log_info(DOQ, "Failed to configure crypto session %s (%d)\n",
				ngtcp2_strerror(ret), ret);
		return kr_error(EINVAL);
	}

	conn->conn_ref = (nc_conn_ref_placeholder_t) {
		.get_conn = get_conn,
		.user_data = conn,
	};

	gnutls_session_set_ptr(conn->tls_session, &conn->conn_ref);
	ngtcp2_conn_set_tls_native_handle(conn->conn, conn->tls_session);

	return kr_ok();
}

int quic_init_server_conn(struct pl_quic_conn_sess_data *conn,
		struct protolayer_iter_ctx *ctx)
{
	if (!ctx) {
		return kr_error(EINVAL);
	}

	uint64_t now = quic_timestamp();

	int ret = conn_new_handler(&conn->conn, conn->path,
			&conn->scid, &conn->dcid, &conn->odcid,
			conn->dec_cids.version,
			now, true, conn->retry_sent,
			conn);

	if (ret >= 0) {
		ret = tls_init_conn_session(conn, true);;
	}

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

int send_special(ngtcp2_version_cid *dec_cids,
		kr_quic_table_t *table,
		struct protolayer_iter_ctx *ctx, int action,
		struct pl_quic_conn_sess_data *conn,
		struct session2 *session, quic_doq_error_t *doq_error)
{
	char *err_buf = mm_alloc(&ctx->pool, NGTCP2_MAX_UDP_PAYLOAD_SIZE);
	if (!err_buf)
		return kr_error(ENOMEM);
	struct wire_buf err_wb = {
		.buf = err_buf,
		.end = 0,
		.size = NGTCP2_MAX_UDP_PAYLOAD_SIZE,
		.start = 0,
	};
	struct wire_buf *save = ctx->payload.wire_buf;
	ctx->payload.wire_buf = &err_wb;

	uint64_t now = quic_timestamp();

	uint8_t sreset_rand[NGTCP2_MIN_STATELESS_RESET_RANDLEN];
	dnssec_random_buffer(sreset_rand, sizeof(sreset_rand));
	ngtcp2_ccerr ccerr;
	ngtcp2_ccerr_default(&ccerr);
	ngtcp2_pkt_info pi = { 0 };
	uint8_t rnd = 0;

	int ret = 0;
	switch (action) {
	case QUIC_SEND_VERSION_NEGOTIATION:
		kr_require(!conn);
		dnssec_random_buffer(&rnd, sizeof(rnd));
		uint32_t supported_quic[1] = { NGTCP2_PROTO_VER_V1 };
		ret = ngtcp2_pkt_write_version_negotiation(
			wire_buf_free_space(ctx->payload.wire_buf),
			wire_buf_free_space_length(ctx->payload.wire_buf),
			rnd, dec_cids->scid, dec_cids->scidlen,
			dec_cids->dcid, dec_cids->dcidlen, supported_quic,
			sizeof(supported_quic) / sizeof(*supported_quic)
		);
	case QUIC_SEND_RETRY:
		kr_require(dec_cids);
		ret = write_retry_packet(ctx->payload.wire_buf,
				table, dec_cids,
				ctx->comm->src_addr,
				(uint8_t *)table->hash_secret,
				sizeof(table->hash_secret));
		if (conn) {
			QUIC_SET_CLOSING(conn);
		}
		break;
	case QUIC_SEND_CONN_CLOSE:
		if (!conn || !QUIC_CAN_SEND(conn)) {
			break;
		}

		if (doq_error != NULL) {
			ngtcp2_ccerr_set_application_error(&ccerr,
					*doq_error, NULL, 0);
		}

		ret = ngtcp2_conn_write_connection_close(
			conn->conn, NULL, &pi,
			wire_buf_free_space(ctx->payload.wire_buf),
			wire_buf_free_space_length(ctx->payload.wire_buf),
			&ccerr, now);

		QUIC_SET_CLOSING(conn);
		break;
	/* Unused for now */
	// case QUIC_SEND_STATELESS_RESET:
	default:
		ret = kr_error(EINVAL);
		break;
	}

	if (ret > 0) {
		wire_buf_consume(ctx->payload.wire_buf, ret);
		session2_wrap(session,
				ctx->payload,
				ctx->comm,
				NULL,
				ctx->finished_cb,
				ctx->finished_cb_baton);
		ret = kr_ok();
	}

	mm_free(&ctx->pool, ctx->payload.wire_buf);
	ctx->payload.wire_buf = save;

	return ret;
}

static enum protolayer_iter_cb_result pl_quic_conn_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret = kr_ok();
	struct pl_quic_conn_sess_data *conn = sess_data;
	if (ctx->payload.type == PROTOLAYER_PAYLOAD_BUFFER) {
		struct wire_buf *wb = mm_alloc(&ctx->pool, sizeof(struct wire_buf));
		wb->size = ctx->payload.buffer.len;
		wb->buf = ctx->payload.buffer.buf;
		wb->end = wb->size;
		wb->start = 0;
		ctx->payload = protolayer_payload_wire_buf(wb, false);
	}

	kr_quic_set_addrs(ctx, &conn->path);

	if (!conn->conn) {
		copy_comm_storage(conn, &ctx->comm_storage);

		if ((ret = quic_init_server_conn(conn, ctx)) != kr_ok()) {
			kr_log_error(DOQ, "Failed to initiate quic connection (%d)\n", ret);
			session2_force_close(conn->h.session);
			return protolayer_break(ctx, ret);
		}
	}

	quic_doq_error_t doq_error;
	uv_timer_again(&conn->h.session->timer);
	ret = handle_packet(conn, ctx, &doq_error);
	if (ret != kr_ok()) {
		ret = send_special(&conn->dec_cids,
				conn->table_ref, ctx, ret, conn,
				conn->h.session, &doq_error);
		if (ret == kr_ok()) {
			ngtcp2_conn_update_pkt_tx_time(conn->conn,
					quic_timestamp());
		}
		return protolayer_break(ctx, kr_ok());
	}

	if (queue_len(conn->pending_unwrap) == 0) {
		ret = session2_wrap(conn->h.session,
				ctx->payload,
				ctx->comm,
				NULL,
				ctx->finished_cb,
				ctx->finished_cb_baton);

		return protolayer_break(ctx, kr_ok());
	}

	while (queue_len(conn->pending_unwrap) > 0) {
		session2_unwrap(queue_head(conn->pending_unwrap)->h.session,
				ctx->payload,
				NULL /* &conn->comm_storage */,
				ctx->finished_cb,
				ctx->finished_cb_baton);
		queue_pop(conn->pending_unwrap);
	}

	return protolayer_break(ctx, kr_ok());
}

static enum protolayer_iter_cb_result pl_quic_conn_wrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	struct pl_quic_conn_sess_data *conn = sess_data;

	if (!QUIC_CAN_SEND(conn)) {
		return protolayer_break(ctx, kr_ok());
	}

	if (ctx->payload.type != PROTOLAYER_PAYLOAD_IOVEC) {
		ngtcp2_ssize sent = 0;
		ngtcp2_conn_info info = { 0 };
		ngtcp2_conn_get_conn_info(conn->conn, &info);
		ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };

		if (wire_buf_data_length(ctx->payload.wire_buf) > 0) {
			return protolayer_continue(ctx);
		}

		int nwrite = ngtcp2_conn_writev_stream(conn->conn,
				conn->path,
				&pi, wire_buf_free_space(ctx->payload.wire_buf),
				wire_buf_free_space_length(ctx->payload.wire_buf),
				&sent, NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL,
				0, quic_timestamp());

		if (nwrite <= 0) {
			if (nwrite == NGTCP2_ERR_NOMEM) {
				 size_t inc = MIN(ctx->payload.wire_buf->size, 1024);
				char *new_buf = realloc(ctx->payload.wire_buf->buf, inc);
				kr_require(new_buf);

				ctx->payload.wire_buf->buf = new_buf;
				ctx->payload.wire_buf->end += inc;
				ctx->payload.wire_buf->size += inc;
			}

			return protolayer_break(ctx, kr_error(EINVAL));
		}

		wire_buf_consume(ctx->payload.wire_buf, nwrite);
	}

	ngtcp2_conn_update_pkt_tx_time(conn->conn, quic_timestamp());
	if (conn->state & QUIC_STATE_CLOSING) {
		QUIC_SET_DRAINING(conn);
	}

	return protolayer_continue(ctx);
}

int quic_generate_secret(uint8_t *buf, size_t buflen)
{
	if (unlikely(buf == NULL || buflen > 32)) {
		return kr_error(EINVAL);
	}
	uint8_t rand[16], hash[32];
	int ret = dnssec_random_buffer(rand, sizeof(rand));
	if (ret != DNSSEC_EOK) {
		kr_log_error(DOQ, "Failed to init dnssec random buffer");
		return kr_error(EINVAL);
	}

	ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, rand, sizeof(rand), hash);
	if (ret != 0) {
		return kr_error(EINVAL);
	}

	memcpy(buf, hash, buflen);
	return kr_ok();
}

static int pl_quic_conn_sess_init(struct session2 *session, void *sess_data, void *param)
{
	struct pl_quic_conn_sess_data *conn = sess_data;
	conn->state = 0;
	conn->path = calloc(1, sizeof(ngtcp2_path));
	if (!conn->path) {
		return kr_error(ENOMEM);
	}

	struct kr_quic_conn_param *p = param;
	conn->dcid = p->dcid;
	conn->scid = p->scid;
	conn->odcid = p->odcid;
	conn->retry_sent = p->retry_sent;
	conn->table_ref = p->table;

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

	conn->comm_storage = *comm;
	session->comm_storage = conn->comm_storage;
	queue_init(conn->pending_unwrap);
	conn->is_server = !session->outgoing;

	init_list(&conn->streams);

	conn->conn = NULL;
	conn->priority = NULL;
	conn->streams_count = 0;
	conn->tls_session = NULL;
	conn->server_credentials = NULL;
	if (unlikely(quic_generate_secret(conn->secret, sizeof(conn->secret)) != kr_ok())) {
		pl_quic_conn_sess_deinit(conn->h.session, conn);
		kr_log_error(DOQ, "Failed to init connection session\n");
		return kr_error(EINVAL);
	}

	session2_timer_start(session, PROTOLAYER_EVENT_CONNECT_TIMEOUT,
			QUIC_CONN_IDLE_TIMEOUT / NGTCP2_MILLISECONDS,
			QUIC_CONN_IDLE_TIMEOUT / NGTCP2_MILLISECONDS);

	return kr_ok();
}

static int pl_quic_conn_sess_deinit(struct session2 *session, void *sess_data)
{
	struct pl_quic_conn_sess_data *conn = sess_data;
	while (session2_tasklist_del_first(session, false) != NULL);

	struct pl_quic_stream_sess_data *s_node;
	WALK_LIST_FIRST(s_node, conn->streams) {
		struct pl_quic_stream_sess_data *s =
			container_of(s_node, struct pl_quic_stream_sess_data, list_node);
		rem_node(&s->list_node);
		session2_close(s->h.session);
		/* These streams die with the connection, stream_close_cb
		 * will not be called so adjust counters here. */
		--conn->streams_count;
		++conn->finished_streams;
	}

	kr_log_info(DOQ, "Closing connection, %s useful, served %zu streams\n",
			conn->finished_streams ? "was" : "wasn't",
			conn->finished_streams);

	if (conn->priority) {
		gnutls_priority_deinit(conn->priority);
	}

	if (conn->tls_session) {
		gnutls_deinit(conn->tls_session);
	}

	if (conn->is_server) {
		tls_credentials_release(conn->server_credentials);
	} else {
		kr_log_error(DOQ, "Client side of QUIC is not implemented\n");
	}

	if (conn->path) {
		free(conn->path);
	}

	conn->priority = NULL;
	conn->tls_session = NULL;
	conn->server_credentials = NULL;

	ngtcp2_conn_del(conn->conn);
	conn->conn = NULL;

	session2_timer_stop(session);
	return kr_ok();
}

static enum protolayer_event_cb_result pl_quic_conn_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	struct pl_quic_conn_sess_data *conn = sess_data;
	if (event == PROTOLAYER_EVENT_CONNECT_TIMEOUT) {
		session2_event(conn->h.session->transport.parent, event, conn);
		return PROTOLAYER_EVENT_CONSUME;
	}

	if (event == PROTOLAYER_EVENT_DISCONNECT ||
			event == PROTOLAYER_EVENT_CLOSE ||
			event == PROTOLAYER_EVENT_FORCE_CLOSE) {
		session2_dec_refs(session);
		return PROTOLAYER_EVENT_CONSUME;
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

__attribute__((constructor))
static void quic_conn_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_QUIC_CONN] = (struct protolayer_globals) {
		.sess_size = sizeof(struct pl_quic_conn_sess_data),
		.sess_init = pl_quic_conn_sess_init,
		.sess_deinit = pl_quic_conn_sess_deinit,
		.unwrap = pl_quic_conn_unwrap,
		.wrap = pl_quic_conn_wrap,
		.event_unwrap = pl_quic_conn_event_unwrap,
	};
}
