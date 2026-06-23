/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "quic_conn.h"
#include "lib/proto.h"
#include "network.h"
#include "quic_common.h"
#include "quic_demux.h"
#include "quic_stream.h"
#include "lib/dnssec.h"
#include "session2.h"
#include "worker.h"
#include <gnutls/gnutls.h>
#include <libknot/wire.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <sched.h>
#include <stdlib.h>
#include <uv.h>

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
		wire_buf_reset(ctx->payload.wire_buf);
		return kr_ok();
	}

	/* Avoid overwriting any more specific DoQ error codes. */
	if (ret < 0 && conn->ccerr.error_code == DOQ_NO_ERROR) {
		ngtcp2_ccerr_set_liberr(&conn->ccerr, ret, NULL, 0);
	}

	ngtcp2_duration pto_ns = 0;
	switch (ret) {
	case NGTCP2_ERR_RETRY:
		/* "Server must perform address validation by sending Retry packet
		 * (see ngtcp2_crypto_write_retry() and ngtcp2_pkt_write_retry()),
		 * and discard the connection state. Client application does
		 * not get this error code." */
		return QUIC_SEND_RETRY;

	case NGTCP2_ERR_DROP_CONN:
		*doq_error = DOQ_UNSPECIFIED_ERROR;
		QUIC_SET_DRAINING(conn);
		kr_log_debug(DOQ, "Connection was dropped, waiting 1 PTO before termination\n");
		pto_ns = ngtcp2_conn_get_pto(conn->conn);
		quic_set_idle_timeout(conn->h.session,
				quic_ns_to_ms_ceil(pto_ns));
		return QUIC_SEND_NONE;

	case NGTCP2_ERR_DRAINING:
		*doq_error = DOQ_UNSPECIFIED_ERROR;
		QUIC_SET_DRAINING(conn);
		kr_log_debug(DOQ, "Connection entered draining state, waiting 3 PTO\n");
		pto_ns = ngtcp2_conn_get_pto(conn->conn);
		quic_set_idle_timeout(conn->h.session,
				quic_get_closing_timeout(pto_ns));
		return QUIC_SEND_NONE;

	case NGTCP2_ERR_CLOSING:
		*doq_error = DOQ_UNSPECIFIED_ERROR;
		QUIC_SET_CLOSING(conn);
		kr_log_debug(DOQ, "Connection entered closing state, waiting 3 PTO\n");
		pto_ns = ngtcp2_conn_get_pto(conn->conn);
		quic_set_idle_timeout(conn->h.session,
				quic_get_closing_timeout(pto_ns));
		return QUIC_SEND_NONE;

	case NGTCP2_ERR_CRYPTO:
		/* see RFC 9001 4.8. TLS Errors */
		set_tls_error(conn, doq_error, NULL, 0);
		kr_log_error(DOQ, "TLS stack alert: %d\n",
				ngtcp2_conn_get_tls_alert(conn->conn));

		return QUIC_SEND_CONN_CLOSE;

	default:
		*doq_error = DOQ_UNSPECIFIED_ERROR;
		kr_log_debug(DOQ, "Unspecified error (%d), sending connection close\n",
				ret);
		return QUIC_SEND_CONN_CLOSE;
	}

	return ret;
}

static struct tls_credentials *tls_credentials_reserve(
		struct tls_credentials *tls_credentials)
{
	if (!tls_credentials) {
		return NULL;
	}
	tls_credentials->count++;
	return tls_credentials;
}

static int handshake_completed_cb(ngtcp2_conn *ngconn, void *user_data)
{
	struct pl_quic_conn_sess_data *conn = user_data;
	QUIC_SET_HS_COMPLETED(conn);

	if (conn->h.session->outgoing) {
		// pass
	} else {
		quic_reset_expiry(conn);
	}

	return NGTCP2_NO_ERROR;
}

static int kr_recv_stream_data_cb(ngtcp2_conn *ngconn, uint32_t flags,
	int64_t stream_id, uint64_t offset, const uint8_t *data,
	size_t datalen, void *user_data, void *stream_user_data)
{
	/* Stream session was already terminated because the connection closed */
	if (stream_user_data == NULL) {
		return NGTCP2_NO_ERROR;
	}

	(void)ngtcp2_conn_extend_max_stream_offset(ngconn, stream_id, datalen);
	ngtcp2_conn_extend_max_offset(ngconn, datalen);

	const uint8_t msg[] = "malformed data";
	struct pl_quic_conn_sess_data *conn = user_data;
	struct pl_quic_stream_sess_data *stream = stream_user_data;

	/* just to be safe, ngtcp2 guarantees in order data with no gaps */
	if (unlikely(kr_fails_assert(offset == wire_buf_data_length(
						&stream->pers_inbuf)))) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	stream->incflags = flags;
	stream->sdata_offset = offset;

	if (wire_buf_data_length(&stream->pers_inbuf) < sizeof(uint16_t)) {
		if (datalen == 0) {
			goto malformed;
		}
		if (datalen == 1 && wire_buf_data_length(&stream->pers_inbuf) == 0) {
			/* received only the first length prefix octet */
			stream->pers_inbuf.buf[0] = data[0];
			wire_buf_consume(&stream->pers_inbuf, 1);
			goto finished;
		}
		if (wire_buf_data_length(&stream->pers_inbuf) == 1) {
			/* finish partial length prefix octet
			 * (previous first stream payload had datalen == 1) */
			stream->pers_inbuf.buf[1] = data[0];
			wire_buf_consume(&stream->pers_inbuf, 1);
			data += 1;
			datalen--;
		} else {
			/* length prefix arrived in one piece */
			knot_wire_write_u16(wire_buf_data(&stream->pers_inbuf),
						knot_wire_read_u16(data));
			wire_buf_consume(&stream->pers_inbuf, sizeof(uint16_t));
			data += sizeof(uint16_t);
			datalen -= sizeof(uint16_t);
		}

		uint32_t qsize =
			knot_wire_read_u16(wire_buf_data(&stream->pers_inbuf));
		uint32_t qsize_prefixed = qsize + sizeof(uint16_t);
		if (qsize > wire_buf_free_space_length(&stream->pers_inbuf)) {
			uint32_t qsize_prefixed_safe = qsize_prefixed + 16;
			wire_buf_reserve(&stream->pers_inbuf,
					qsize_prefixed_safe);
		}
		if (datalen == 0) {
			goto finished;
		}
	}

	if (datalen == 0) {
		/* This is invalid see ngtcp2_recv_stream_data doc */
		if (!(flags & NGTCP2_STREAM_DATA_FLAG_FIN)) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}

		goto finished;
	}

	/* the peer sent more data than declared but the length prefix.
	 * close the connection with EPROTO and report malformed data */
	if (wire_buf_free_space_length(&stream->pers_inbuf) < datalen) {
		uint32_t query_size = sizeof(uint16_t) +
			knot_wire_read_u16(wire_buf_data(&stream->pers_inbuf));
		uint32_t payload_size = wire_buf_data_length(&stream->pers_inbuf);
		kr_log_debug(DOQ, "invalid payload size, malformed data (%hu != %ju)\n",
				query_size, payload_size + datalen);
		goto malformed;

	}
	memcpy(wire_buf_free_space(&stream->pers_inbuf), data, datalen);
	wire_buf_consume(&stream->pers_inbuf, datalen);

finished:
	if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
		if (wire_buf_data_length(&stream->pers_inbuf) < sizeof(uint16_t)) {
			kr_log_debug(DOQ, "invalid payload size, malformed data (payload < 2)\n");
			goto malformed;
		}
		uint32_t query_size = sizeof(uint16_t) +
			knot_wire_read_u16(wire_buf_data(&stream->pers_inbuf));
		uint32_t payload_size = wire_buf_data_length(&stream->pers_inbuf);

		if (query_size != payload_size) {
			kr_log_debug(DOQ, "invalid payload size, malformed data (%hu != %hu)\n",
					query_size, payload_size);
			goto malformed;
		}
		session2_inc_refs(stream->h.session);
		queue_push(conn->pending_unwrap, stream);
	}

	return NGTCP2_NO_ERROR;
/* a remote endpoint might maliciously or accidentally send
 * less that advertised by the length prefix => malformed data.
 * respond by closing the connection forcefully.
 * (see: RFC 9250 4.3.3. Protocol Errors) */
malformed:
	QUIC_SET_CLOSING(conn);
	set_application_error(conn, DOQ_PROTOCOL_ERROR,
			msg, sizeof(msg) - 1);
	return NGTCP2_ERR_CALLBACK_FAILURE;

}

static int acked_stream_data_offset_cb(ngtcp2_conn *ngconn,
		int64_t stream_id, uint64_t offset, uint64_t datalen,
		void *user_data, void *stream_user_data)
{
	(void)ngconn;
	/* Stream session was already terminated because the connection closed */
	if (stream_user_data == NULL) {
		return NGTCP2_NO_ERROR;
	}
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
		session2_new_child(conn->h.session, KR_PROTO_DOQ_STREAM,
				&data_param, 1, false);

	if (!new_subsession) {
		kr_log_error(DOQ, "Failed to create new quic stream session\n");
		/* TODO could use EXCESSIVE_LOAD */
		set_application_error(conn, DOQ_INTERNAL_ERROR, NULL, 0);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	struct pl_quic_stream_sess_data *stream =
		protolayer_sess_data_get_proto(new_subsession,
				PROTOLAYER_TYPE_QUIC_STREAM);
	kr_require(stream);
	stream->conn_ref = conn;
	if (conn->streams_count <= 0) {
		add_head(&conn->streams, &stream->list_node);
	} else {
		add_tail(&conn->streams, &stream->list_node);
	}

	++conn->streams_count;
	ngtcp2_conn_set_stream_user_data(ngconn, stream_id, stream);

	session2_event(stream->h.session, PROTOLAYER_EVENT_CONNECT, NULL);

	return NGTCP2_NO_ERROR;
}

static int stream_close_cb(ngtcp2_conn *ngconn, uint32_t flags,
		int64_t stream_id, uint64_t app_error_code,
		void *user_data, void *stream_user_data)
{
	/* Stream session was already terminated because the connection closed */
	if (stream_user_data == NULL) {
		return NGTCP2_NO_ERROR;
	}

	struct pl_quic_conn_sess_data *conn = user_data;
	struct pl_quic_stream_sess_data *stream = stream_user_data;

	stream->closed = true;

	session2_close(stream->h.session);
	++conn->finished_streams;

	return NGTCP2_NO_ERROR;
}

static void kr_quic_rand_cb(uint8_t *dest, size_t destlen,
	const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;
	(void)dnssec_random_buffer(dest, destlen);
}

static int get_new_connection_id_cb(ngtcp2_conn *ngconn, ngtcp2_cid *cid,
		uint8_t *token, size_t cidlen, void *user_data)
{
	(void)ngconn;
	struct pl_quic_conn_sess_data *conn = user_data;
	if (init_unique_cid(cid, cidlen, conn->table_ref) != 0) {
		kr_log_error(DOQ, "Failed to create init new cid\n");
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	memcpy(&conn->dcid, cid, sizeof(ngtcp2_cid));
	if (ngtcp2_crypto_generate_stateless_reset_token(token, conn->secret,
				sizeof(conn->secret), cid) != 0) {
		kr_log_error(DOQ, "Failed to generate stateless reset token\n");
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (kr_quic_table_insert(conn, cid, conn->table_ref) == NULL) {
		kr_log_error(DOQ, "Failed to add new cid to conn map\n");
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return NGTCP2_NO_ERROR;
}

int remove_connection_id_cb(ngtcp2_conn *ngconn,
		const ngtcp2_cid *cid, void *user_data)
{
	(void)ngconn;
	struct pl_quic_conn_sess_data *conn = user_data;

	kr_quic_cid_t **pcid = kr_quic_table_lookup2(cid, conn->table_ref);
	if (!pcid || !*pcid) {
		kr_log_error(DOQ, "Table doesn't contain cid that is to be removed\n");
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if ((*pcid)->conn_sess->cid_pointers <= 1) {
		kr_log_error(DOQ, "Cannot remove all connection ids, protocol error\n");
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return kr_quic_table_rem2(pcid, conn->table_ref);
}

#if DEBUG_NGTCP2
static void quic_debug_cb(void *user_data, const char *format, ...)
{
	char buf[256];
	va_list args;
	va_start(args, format);
	(void)vsnprintf(buf, sizeof(buf), format, args);
	kr_log_debug(DOQ_LIBNGTCP2, "%s\n", buf);
	va_end(args);
}
#endif /* DEBUG_NGTCP2 */

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
		// .stream_stop_sending - OPTIONAL
		// .stream_reset - OPTIONAL
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
		.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
		// .recv_rx_key - OPTIONAL
		// .recv_tx_key - OPTIONAL
	};

	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = now;
	settings.max_tx_udp_payload_size = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
	settings.handshake_timeout = QUIC_HS_IDLE_TIMEOUT;
#if DEBUG_NGTCP2
	settings.log_printf = quic_debug_cb;
#endif /* DEBUG_NGTCP2 */
	settings.no_pmtud = true;

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	if (unlikely(kr_fails_assert(the_network && the_network->quic_params))) {
		kr_log_debug(DOQ, "Missing network struct or network quic_parameters\n");
		return kr_error(EINVAL);
	}
	params.initial_max_streams_bidi = the_network->quic_params->max_streams;
	/* DoQ has no use for unidirectional streams */
	params.initial_max_streams_uni = 0;
	params.initial_max_stream_data_bidi_local = MAX_QUIC_FRAME_SIZE;
	params.initial_max_stream_data_bidi_remote = MAX_QUIC_FRAME_SIZE;
	params.initial_max_data = MAX_QUIC_PKT_SIZE;
	/** This informs peer that active migration might not be available.
	 * Peer might still attempt to migrate.
	 * see RFC 9000 5.2.3 Considerations for Simple Load Balancers */
	params.disable_active_migration = true;
	params.max_idle_timeout = QUIC_CONN_IDLE_TIMEOUT;
	params.stateless_reset_token_present =
		NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;

	if (odcid != NULL) {
		params.original_dcid = *odcid;
		params.original_dcid_present = 1;
	}

	if (retry_sent) {
		/* retry scid is retrieved from
		 * ngtcp2_crypto_verify_retry_roken2 as the odcid
		 * used by the client. */
		params.retry_scid = *dcid;
		params.retry_scid_present = 1;
	}

	int ret = dnssec_random_buffer(params.stateless_reset_token,
					NGTCP2_STATELESS_RESET_TOKENLEN);
	if (ret != KNOT_EOK) {
		return kr_error(ret);
	}

	if (server) {
		const ngtcp2_cid *client_dcid = scid;
		const ngtcp2_cid *client_scid = dcid;
		return ngtcp2_conn_server_new(pconn, client_dcid, client_scid,
				path, version, &callbacks, &settings, &params,
				NULL, conn);
	} else {
		kr_log_warning(DOQ, "Client side is not implemented\n");
		return kr_error(EINVAL);
		// return ngtcp2_conn_client_new(pconn, dcid, scid, path, version,
		// 		&callbacks, &settings, &params, NULL, conn);
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
	if (the_network->tls_credentials->valid_until
			!= GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION) {
		if (the_network->tls_credentials->ephemeral_servicename) {
			/* ephemeral cert: refresh if due to expire within a week */
			if (now >= the_network->tls_credentials->valid_until
					- EPHEMERAL_CERT_EXPIRATION_SECONDS_RENEW_BEFORE) {
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

	int ret = gnutls_priority_init2(&conn->priority, NULL, NULL, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_priority_init2(): %s (%d)\n",
				gnutls_strerror_name(ret), ret);
		return ret;
	}

	int flags = GNUTLS_SERVER | GNUTLS_NONBLOCK;
#if GNUTLS_VERSION_NUMBER >= 0x030705
	if (gnutls_check_version("3.7.5"))
		flags |= GNUTLS_NO_TICKETS_TLS12;
#endif
	ret = gnutls_init(&conn->tls_session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_init(): %s (%d)\n",
				gnutls_strerror_name(ret), ret);
		return ret;
	}

	gnutls_certificate_send_x509_rdn_sequence(conn->tls_session, 1);
	gnutls_certificate_server_set_request(conn->tls_session, GNUTLS_CERT_IGNORE);
	ret = gnutls_priority_set(conn->tls_session, conn->priority);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_priority_set(): %s (%d)\n",
				gnutls_strerror_name(ret), ret);
		return ret;
	}

	conn->server_credentials = tls_credentials_reserve(the_network->tls_credentials);
	ret = gnutls_credentials_set(conn->tls_session, GNUTLS_CRD_CERTIFICATE,
				     conn->server_credentials->credentials);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_credentials_set(): %s (%d)\n",
				gnutls_strerror_name(ret), ret);
		return ret;
	}

	const char *errpos = NULL;
	int err = gnutls_set_default_priority_append(conn->tls_session,
			tlsv13_priorities, &errpos, 0);
	if (err != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "setting priority '%s' failed at character %zd (...'%s') with %s (%d)\n",
			     tlsv13_priorities, errpos - tlsv13_priorities,
			     errpos, gnutls_strerror_name(err), err);
		return ret;
	}

	if (the_network->tls_session_ticket_ctx) {
		tls_session_ticket_enable(the_network->tls_session_ticket_ctx,
					  conn->tls_session);
	}

	const gnutls_datum_t alpn_datum = {
		.data = (void *)"doq",
		.size = 3
	};
	ret = gnutls_alpn_set_protocols(conn->tls_session, &alpn_datum, 1,
			GNUTLS_ALPN_MANDATORY);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(TLS, "gnutls_alpn_set_protocols(): %s (%d)\n", gnutls_strerror_name(ret), ret);
	}

	return ret;
}

ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
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
	if (ret == 0) {
		ret = tls_init_conn_session(conn, true);
	}

	return ret;
}

int quic_flush_streams(struct pl_quic_conn_sess_data *conn)
{
	kr_require(conn);
	node_t *s_node = 0, *next = 0;
	bool sent = false;
	WALK_LIST_DELSAFE(s_node, next, conn->streams) {
		struct pl_quic_stream_sess_data *s =
			container_of(s_node, struct pl_quic_stream_sess_data,
					list_node);
		/* Skip streams that have no data to send */
		if (s->write_closed || s->unsent_obuf == NULL) {
			continue;
		}

		s->skip_update_time = true;
		if (session2_wrap_after(s->h.session,
				PROTOLAYER_TYPE_DNS_SINGLE_STREAM,
				protolayer_payload_wire_buf(
					&s->h.session->wire_buf, true),
				&conn->comm_storage,
				NULL,
				NULL) < 0) {
			/* Either closing or invalid */
		}

		s->skip_update_time = false;
		sent = true;
	}

	if (sent) {
		ngtcp2_conn_update_pkt_tx_time(conn->conn, quic_timestamp());
	}

	return kr_ok();
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

int send_special(ngtcp2_version_cid *dec_cids, kr_quic_table_t *table,
		struct protolayer_iter_ctx *ctx, int action,
		struct pl_quic_conn_sess_data *conn,
		struct session2 *session, quic_doq_error_t *doq_error)
{
	if (kr_fails_assert(ctx)) {
		return kr_error(EINVAL);
	}
	char *err_buf = mm_alloc(&ctx->pool, NGTCP2_MAX_UDP_PAYLOAD_SIZE);
	if (!err_buf)
		return kr_error(ENOMEM);

	struct wire_buf err_wb = {
		.buf = err_buf,
		.end = 0,
		.size = NGTCP2_MAX_UDP_PAYLOAD_SIZE,
		.start = 0,
	};
	struct wire_buf *save_wb = ctx->payload.wire_buf;
	ctx->payload.wire_buf = &err_wb;

	uint64_t now = quic_timestamp();

	uint8_t sreset_rand[NGTCP2_MIN_STATELESS_RESET_RANDLEN];
	dnssec_random_buffer(sreset_rand, sizeof(sreset_rand));
	ngtcp2_pkt_info pi = { 0 };
	uint8_t rnd = 0;

	int ret = kr_error(EINVAL);
	switch (action) {
	case QUIC_SEND_VERSION_NEGOTIATION:
		if (kr_fails_assert(!conn && dec_cids)) {
			break;
		}
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
		break;
	case QUIC_SEND_RETRY:
		if (kr_fails_assert(dec_cids && table)) {
			break;
		}
		ret = write_retry_packet(ctx->payload.wire_buf,
				table, dec_cids,
				ctx->comm->src_addr);

		if (conn) {
			QUIC_SET_HS_ABORT(conn);
		}
		break;
	case QUIC_SEND_CONN_CLOSE:
		if (kr_fails_assert(conn && session)) {
			break;
		}
		if (!QUIC_CAN_SEND(conn)) {
			ret = kr_ok();
			break;
		}

		/* Keep the more specific last error */
		if (conn->ccerr.error_code == DOQ_NO_ERROR) {
			set_application_error(conn, *doq_error, NULL, 0);
		}

		ret = ngtcp2_conn_write_connection_close(
			conn->conn, NULL, &pi,
			wire_buf_free_space(ctx->payload.wire_buf),
			wire_buf_free_space_length(ctx->payload.wire_buf),
			&conn->ccerr, now);

		kr_log_debug(DOQ, "Connection entered closing state, waiting 3 PTO\n");
		QUIC_SET_CLOSING(conn);
		quic_set_idle_timeout(conn->h.session, quic_get_closing_timeout(
					ngtcp2_conn_get_pto(conn->conn)));
		break;
	/* Unused for now */
	// case QUIC_SEND_STATELESS_RESET:
	default:
		break;
	}

	if (ret > 0) {
		wire_buf_consume(ctx->payload.wire_buf, ret);
		if (session->proto == KR_PROTO_DOQ_CONN) {
			session2_wrap_after(session, PROTOLAYER_TYPE_QUIC_CONN,
					ctx->payload, ctx->comm,
					ctx->finished_cb,
					ctx->finished_cb_baton);
		} else {
			/* send special can be called from demux layer
			 * where the conn session might not exist yet. */
			session2_wrap(session, ctx->payload, ctx->comm,
					NULL, ctx->finished_cb,
					ctx->finished_cb_baton);
		}
		ret = kr_ok();
	}

	mm_free(&ctx->pool, ctx->payload.wire_buf->buf);
	ctx->payload.wire_buf = save_wb;

	return ret;
}

/* If the packet is INITIAL and the connection setup fails simply setting the
 * conn->state to DRAINING will result in session teardown. */
static enum protolayer_iter_cb_result pl_quic_conn_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret = kr_ok();
	struct pl_quic_conn_sess_data *conn = sess_data;
	if (conn->state & (QUIC_STATE_DRAINING | QUIC_STATE_HS_ABORT)) {
		return protolayer_break(ctx, kr_ok());
	}

	/* Deferred payload (async processing) switches the buffer type
	 * (see protolayer_payload_ensure_long_lived) */
	if (ctx->payload.type == PROTOLAYER_PAYLOAD_BUFFER) {
		struct wire_buf *wb = mm_alloc(&ctx->pool, sizeof(struct wire_buf));
		if (!wb) {
			return protolayer_break(ctx, kr_error(ENOMEM));
		}
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
			QUIC_SET_DRAINING(conn);
			return protolayer_break(ctx, ret);
		}
	}

	quic_doq_error_t doq_error;
	ret = handle_packet(conn, ctx, &doq_error);
	if (ret != kr_ok()) {
		if (ret != QUIC_SEND_NONE) {
			(void)send_special(&conn->dec_cids,
					conn->table_ref, ctx, ret, conn,
					conn->h.session, &doq_error);
		}

		return protolayer_break(ctx, kr_ok());
	}

	quic_reset_expiry(conn);

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
		struct session2 *s = queue_head(conn->pending_unwrap)->h.session;
		session2_unwrap(s,
				ctx->payload,
				NULL /* &conn->comm_storage */,
				ctx->finished_cb,
				ctx->finished_cb_baton);
		session2_dec_refs(s);
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

	kr_quic_set_addrs(ctx, &conn->path);

	/* Flush bye message and promote state to DRAINING */
	if (conn->state & QUIC_STATE_CLOSING) {
		quic_doq_error_t doq_error = DOQ_NO_ERROR;
		int ret = send_special(&conn->dec_cids,
				conn->table_ref,
				ctx,
				QUIC_SEND_CONN_CLOSE,
				conn,
				conn->h.session,
				&doq_error);
		if (ret < 0) {
			kr_log_debug(DOQ, "sending CONNECTION_CLOSE failed: %d\n",
					ret);
		}
		QUIC_SET_DRAINING(conn);
		return protolayer_break(ctx, ret < 0 ? ret : 0);
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
				conn->path, &pi,
				wire_buf_free_space(ctx->payload.wire_buf),
				wire_buf_free_space_length(ctx->payload.wire_buf),
				&sent, NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL,
				0, quic_timestamp());

		if (nwrite > 0)
			ngtcp2_conn_update_pkt_tx_time(conn->conn, quic_timestamp());
		if (nwrite == 0) {
			quic_reset_expiry(conn);
			return protolayer_break(ctx, kr_ok());
		}

		if (nwrite < 0) {
			ngtcp2_ccerr_set_liberr(&conn->ccerr, nwrite, NULL, 0);
			return protolayer_break(ctx, kr_ok());
		}

		wire_buf_consume(ctx->payload.wire_buf, nwrite);
	}

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
	if (ret != KNOT_EOK) {
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

static int pl_quic_conn_sess_init(struct session2 *session, void *sess_data,
		void *param)
{
	struct pl_quic_conn_sess_data *conn = sess_data;
	conn->state = 0;
	conn->disconnected = false;
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
	ngtcp2_ccerr_default(&conn->ccerr);

	memcpy(&conn->dec_cids, p->dec_cids, sizeof(ngtcp2_version_cid));

	struct comm_info *comm = p->comm_storage;

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
		kr_log_error(DOQ, "Failed to init connection session\n");
		return kr_error(EINVAL);
	}

	return kr_ok();
}

static int pl_quic_conn_sess_deinit(struct session2 *session, void *sess_data)
{
	struct pl_quic_conn_sess_data *conn = sess_data;
	while (session2_tasklist_del_first(session, false) != NULL);

	session2_timer_stop(session);

	kr_require(session2_is_empty(session));
	kr_require(EMPTY_LIST(conn->streams)); // NOLINT(bugprone-casting-through-void)
	kr_require(conn->cid_pointers == 0);
	kr_require(conn->streams_count == 0);

	if (conn->state & QUIC_STATE_HANDSHAKE_DONE) {
		kr_log_debug(DOQ, "Closing established connection, [%s] useful, served %zu streams\n",
				conn->finished_streams ? "was" : "was not",
				conn->finished_streams);
	} else {
		kr_log_debug(DOQ, "Closing connection with unfinished HS, wasn't useful, [%s] send retry\n",
				conn->retry_sent ? "did" : "did not");
	}

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

	return kr_ok();
}

static int quic_bye(struct pl_quic_conn_sess_data *conn)
{
	if (!conn || !conn->conn) {
		return kr_error(EINVAL);
	}

	struct protolayer_payload payload =
		protolayer_payload_wire_buf(&conn->h.session->wire_buf, true);

	return session2_wrap(conn->h.session,
			payload,
			&conn->comm_storage,
			NULL,
			/* finished_cb: Free to be used */NULL,
			/* finished_cb_baton: Free to be used */NULL);
}

static enum protolayer_event_cb_result pl_quic_conn_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	struct pl_quic_conn_sess_data *conn = sess_data;
	switch (event) {
	case PROTOLAYER_EVENT_CLOSE:
		QUIC_SET_CLOSING(conn);
		(void)quic_bye(conn);
		/* fallthrough */
	case PROTOLAYER_EVENT_FORCE_CLOSE:
	case PROTOLAYER_EVENT_CONNECT_TIMEOUT:
	case PROTOLAYER_EVENT_GENERAL_TIMEOUT:
		while (queue_len(conn->pending_unwrap) > 0) {
			struct session2 *s =
				queue_head(conn->pending_unwrap)->h.session;
			queue_pop(conn->pending_unwrap);
			session2_dec_refs(s);
		}

		node_t *s_node;
		node_t *temp_ptr;
		WALK_LIST_DELSAFE(s_node, temp_ptr, conn->streams) {
			struct pl_quic_stream_sess_data *s =
				container_of(s_node,
						struct pl_quic_stream_sess_data,
						list_node);


			session2_close(s->h.session);
			s = NULL;
		}

		kr_require(EMPTY_LIST(conn->streams)); // NOLINT(bugprone-casting-through-void)

		if (!conn->disconnected) {
			if (event == PROTOLAYER_EVENT_CLOSE) {
				QUIC_SET_CLOSING(conn);
			} else {
				QUIC_SET_DRAINING(conn);
			}
			conn->disconnected = true;
		}
		/* fallthrough */
	default:
		/* Propagate into wrap direction of quic_conn session.
		 * If possible we will unref the session and free it.
		 * (in the unwrap direction the event propagation works only
		 * within the session, subsessions were handled manually) */
		return PROTOLAYER_EVENT_PROPAGATE;
	}
}

static enum protolayer_event_cb_result pl_quic_conn_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	struct pl_quic_conn_sess_data *conn = sess_data;
	if (event == PROTOLAYER_EVENT_FORCE_CLOSE
			|| event == PROTOLAYER_EVENT_CLOSE
			|| event == PROTOLAYER_EVENT_GENERAL_TIMEOUT
			|| event == PROTOLAYER_EVENT_CONNECT_TIMEOUT) {
		if (baton && *baton) {
			struct pl_quic_stream_sess_data *stream = *baton;
			rem_node(&stream->list_node);
			stream->conn_ref->streams_count--;
			ngtcp2_conn_extend_max_streams_bidi(stream->conn, 1);
			ngtcp2_conn_shutdown_stream(stream->conn, 0,
					stream->stream_id, 0);
			ngtcp2_conn_set_stream_user_data(conn->conn,
					stream->stream_id, NULL);
			stream->conn = NULL;
			stream->conn_ref = NULL;
			uv_close((uv_handle_t *)&stream->h.session->timer,
					on_session2_timer_close);
			return PROTOLAYER_EVENT_CONSUME;
		}

		// NOLINTNEXTLINE(bugprone-casting-through-void)
		if (baton && EMPTY_LIST(conn->streams) && conn->disconnected) {
			/* Connection can be terminated */
			*baton = conn;
			return PROTOLAYER_EVENT_PROPAGATE;
		}
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
		.event_wrap = pl_quic_conn_event_wrap,
	};
}
