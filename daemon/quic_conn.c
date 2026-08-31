/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "quic_conn.h"
#include "lib/defines.h"
#include "lib/layer.h"
#include "lib/proto.h"
#include "lib/selection.h"
#include "network.h"
#include "defer.h"
#include "quic_common.h"
#include "quic_demux.h"
#include "quic_stream.h"
#include "lib/dnssec.h"
#include "session2.h"
#include "tls.h"
#include "worker.h"
#include <gnutls/gnutls.h>
#include <libknot/wire.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define EPHEMERAL_CERT_EXPIRATION_SECONDS_RENEW_BEFORE ((time_t)60*60*24*7)

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
		if (ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF)
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
		kr_log_debug(DOQCLIENT, "TLS session to '%s' %s\n",
				kr_straddr(conn->comm_storage.comm_addr),
				gnutls_session_is_resumed(conn->tls_session) ? "resumed" : "full handshake");
		doq_on_connect(conn, kr_ok());
	} else {
		kr_log_debug(DOQ, "TLS session to '%s' %s\n",
				kr_straddr(conn->comm_storage.comm_addr),
				gnutls_session_is_resumed(conn->tls_session) ? "resumed" : "full handshake");
		quic_reset_expiry(conn);
	}

	return NGTCP2_NO_ERROR;
}

static int kr_recv_stream_data_cb(ngtcp2_conn *ngconn, uint32_t flags,
	int64_t stream_id, uint64_t offset, const uint8_t *data,
	size_t datalen, void *user_data, void *stream_user_data)
{
	(void)ngtcp2_conn_extend_max_stream_offset(ngconn, stream_id, datalen);
	ngtcp2_conn_extend_max_offset(ngconn, datalen);

	/* Stream session was already terminated because the connection closed */
	if (stream_user_data == NULL) {
		return NGTCP2_NO_ERROR;
	}

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
					/* limit to 4KB */
					MIN(qsize_prefixed_safe, 1 << 12));
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

	/* the peer sent more data than declared in the length prefix.
	 * close the connection with EPROTO and report malformed data */
	if (wire_buf_free_space_length(&stream->pers_inbuf) < datalen) {
		uint32_t query_size = sizeof(uint16_t) +
			knot_wire_read_u16(wire_buf_data(&stream->pers_inbuf));
		if (query_size > stream->pers_inbuf.size) {
			wire_buf_reserve(&stream->pers_inbuf,
					MIN(query_size,
						MAX(stream->pers_inbuf.size + datalen,
							stream->pers_inbuf.size + (1<<12))));
		} else {
			uint32_t payload_size = wire_buf_data_length(&stream->pers_inbuf);
			kr_log_debug(DOQ, "invalid payload size, malformed data (%hu != %ju)\n",
					query_size, payload_size + datalen);
			goto malformed;
		}

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
	kr_quic_stream_ack_data(stream, stream_id, offset + datalen);
	return NGTCP2_NO_ERROR;
}

static void copy_comm_storage(struct comm_info *dst, struct comm_addr_storage *st,
		const struct comm_info *src)
{
	*dst = *src;
	dst->proxy = NULL;
	dst->target = NULL;
	dst->src_addr = dst->comm_addr = dst->dst_addr = NULL;
	if (src->src_addr) {
		int len = kr_sockaddr_len(src->src_addr);
		kr_require(len > 0 && (size_t)len <= sizeof(st->src_addr));
		memcpy(&st->src_addr, src->src_addr, len);
		dst->src_addr = &st->src_addr.ip;
	}
	if (src->dst_addr) {
		int len = kr_sockaddr_len(src->dst_addr);
		kr_require(len > 0 && (size_t)len <= sizeof(st->dst_addr));
		memcpy(&st->dst_addr, src->dst_addr, len);
		dst->dst_addr = &st->dst_addr.ip;
	}
	if (src->comm_addr) {
		int len = kr_sockaddr_len(src->comm_addr);
		kr_require(len > 0 && (size_t)len <= sizeof(st->comm_addr));
		memcpy(&st->comm_addr, src->comm_addr, len);
		dst->comm_addr = &st->comm_addr.ip;
	}
}

static int create_stream_session(struct pl_quic_conn_sess_data *conn,
		int64_t stream_id, struct pl_quic_stream_sess_data **out_stream)
{
	struct kr_quic_stream_param params = {
		.stream_id = stream_id,
		.conn = conn->conn,
	};
	struct protolayer_data_param data_param = {
		.protocol = PROTOLAYER_TYPE_QUIC_STREAM,
		.param = &params
	};
	struct session2 *new_subsession = 
		session2_new_child(conn->h.session, KR_PROTO_DOQ_STREAM,
				&data_param, 1, conn->h.session->outgoing);

	if (!new_subsession) {
		/* TODO could use EXCESSIVE_LOAD? */
		set_application_error(conn, DOQ_INTERNAL_ERROR, NULL, 0);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	struct pl_quic_stream_sess_data *stream =
		protolayer_sess_data_get_proto(new_subsession,
				PROTOLAYER_TYPE_QUIC_STREAM);
	kr_require(stream);
	stream->conn_ref = conn;
	new_subsession->comm_storage = (struct comm_info) { 0 };
	copy_comm_storage(&new_subsession->comm_storage,
			&stream->comm_addr_storage,
			&conn->comm_storage);
	if (conn->streams_count <= 0) {
		add_head(&conn->streams, &stream->list_node);
	} else {
		add_tail(&conn->streams, &stream->list_node);
	}

	++conn->streams_count;
	ngtcp2_conn_set_stream_user_data(conn->conn, stream_id, stream);
	session2_event(stream->h.session, PROTOLAYER_EVENT_CONNECT, NULL);

	/* server side doesn't need the out parameter; allow NULL */
	if (out_stream) {
		*out_stream = stream;
	}

	return kr_ok();
}

static int stream_open_cb(ngtcp2_conn *ngconn,
		int64_t stream_id, void *user_data)
{
	if (!user_data || ! ngconn) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	struct pl_quic_stream_sess_data *out_stream = NULL;
	return create_stream_session(user_data, stream_id, &out_stream);
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
	stream->terminated_gracefully = true;

	stream->state &= ~QUIC_STREAM_BIDI_OPEN;
	stream->closed = true;

	if (conn->is_server) {
		session2_close(stream->h.session);
	} else {
		if (ngtcp2_conn_get_streams_bidi_left(ngconn)) {
			send_waiting_subsession(conn->h.session);
		}
	}
	++conn->finished_streams;

	return NGTCP2_NO_ERROR;
}

static int stream_reset_cb(ngtcp2_conn* ngconn, int64_t stream_id,
		uint64_t final_size, uint64_t app_error_code, void* user_data,
		void* stream_user_data)
{
	if (stream_user_data == NULL) {
		return NGTCP2_NO_ERROR;
	}
	(void)ngconn;
	(void)final_size;

	struct pl_quic_conn_sess_data *conn = user_data;
	if (conn->is_server)
		kr_log_debug(DOQ, "RESET_STREAM received, abandonning transaction (error code: %zu)\n",
				app_error_code);
	else
		kr_log_debug(DOQCLIENT, "RESET_STREAM received, abandonning transaction (error code: %zu)\n",
				app_error_code);

	struct pl_quic_stream_sess_data *stream = stream_user_data;
	session2_force_close(stream->h.session);
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

static int remove_connection_id_cb(ngtcp2_conn *ngconn,
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

/* Remote has extended the maximum allowed number of streams,
 * trigger query flush for waiting tasks. */
static int extend_max_local_streams_bidi_cb(ngtcp2_conn* ngconn,
		uint64_t max_streams, void* user_data)
{
	struct pl_quic_conn_sess_data *conn = user_data;
	if (!conn->is_server) {
		kr_log_debug(DOQCLIENT, "quic stream capacity increased, flushing tasks\n");
		send_waiting_subsession(conn->h.session);
	}
	return NGTCP2_NO_ERROR;
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

/* Invocation of this callback marks the earliest point when a client
 * implemention can open streams, not used now, present just as a reminder. */
// static int recv_rx_key_cb(struct ngtcp2_conn *ngconn,
// 		enum ngtcp2_encryption_level enc_level, void *user_data)
// {
// }

static int conn_new_handler(ngtcp2_conn **pconn, const ngtcp2_path *path,
		const ngtcp2_cid *scid, const ngtcp2_cid *dcid,
		const ngtcp2_cid *odcid, uint32_t version,
		uint64_t now, bool server, bool retry_sent,
		struct pl_quic_conn_sess_data *conn)
{
	const ngtcp2_callbacks callbacks = {
		.client_initial = server // client side callback
			? NULL
			: ngtcp2_crypto_client_initial_cb,
		.recv_client_initial = server // server side callback
			? ngtcp2_crypto_recv_client_initial_cb
			: NULL,
		.recv_retry = server // client side callback
			? NULL
			: ngtcp2_crypto_recv_retry_cb,
		.delete_crypto_cipher_ctx =
			ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.get_path_challenge_data =
			ngtcp2_crypto_get_path_challenge_data_cb,
		.delete_crypto_aead_ctx =
			ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.extend_max_local_streams_bidi =
			extend_max_local_streams_bidi_cb,
		.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
		.acked_stream_data_offset = acked_stream_data_offset_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.get_new_connection_id = get_new_connection_id_cb,
		.remove_connection_id = remove_connection_id_cb,
		.handshake_completed = handshake_completed_cb,
		.recv_stream_data = kr_recv_stream_data_cb,
		.update_key = ngtcp2_crypto_update_key_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.stream_close = stream_close_cb,
		.stream_reset = stream_reset_cb,
		.stream_open = stream_open_cb,
		.rand = kr_quic_rand_cb,
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
	if (unlikely(kr_fails_assert(the_network && the_network->quic_params.max_conns != 0))) {
		kr_log_debug(DOQ, "Missing network struct or network quic_parameters\n");
		return kr_error(EINVAL);
	}
	params.initial_max_streams_bidi = server
		? the_network->quic_params.max_streams : 0;
	/* DoQ has no use for unidirectional streams */
	params.initial_max_streams_uni = 0;
	params.initial_max_stream_data_bidi_local = DOQ_MAX_STREAM_DATA;
	// params.initial_max_stream_data_bidi_remote = DOQ_MAX_STREAM_DATA;
	params.initial_max_stream_data_bidi_remote = 1 << 12;
	params.initial_max_data =
		DOQ_MAX_STREAM_DATA * the_network->quic_params.max_streams;

	/** This informs peer that active migration might not be available.
	 * Peer might still attempt to migrate.
	 * see RFC 9000 5.2.3 Considerations for Simple Load Balancers */
	params.disable_active_migration = true;
	params.max_idle_timeout = QUIC_CONN_IDLE_TIMEOUT;
	params.stateless_reset_token_present = conn->token_present;
	params.active_connection_id_limit =
		NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;

	if (server) {
		ngtcp2_crypto_generate_stateless_reset_token(
				params.stateless_reset_token, conn->secret,
				sizeof(conn->secret), scid);
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

		return ngtcp2_conn_server_new(pconn, scid, dcid, path, version,
				&callbacks, &settings, &params, NULL, conn);
	} else {
		return ngtcp2_conn_client_new(pconn, dcid, scid, path, version,
				&callbacks, &settings, &params, NULL, conn);
	}
}

/* Once handshake finishes the client side of DoQ will immediatelly
 * attempt to open a stream. This way the worker can handle DoQ traffic
 * similarly to DoT with the difference being that the protolayergroup
 * opening the connection is NOT the one it passes the query to once connected */
struct session2 *setup_quic_stream(struct pl_quic_conn_sess_data *conn)
{
	if (!conn || !conn->h.session->outgoing) {
		return NULL;
	}

	struct pl_quic_stream_sess_data *new_stream;
	/* Forwarding bottleneck based on negotiated concurrent stream limit
	 * is desired and protects both sides from resource exhaustion. */
	if (ngtcp2_conn_get_streams_bidi_left(conn->conn) <= 0) {
		kr_log_debug(DOQCLIENT, "Stream capacity exhausted\n");
		return NULL;
	}

	int64_t stream_id;
	int ret = ngtcp2_conn_open_bidi_stream(conn->conn,
			&stream_id, NULL);
	if (ret != 0) {
		kr_log_debug(DOQCLIENT, "Unknown error when opening stream: %s (%d)\n",
				ngtcp2_strerror(ret), ret);
		return NULL;
	}

	ret = create_stream_session(conn, stream_id, &new_stream);
	if (ret != 0) {
		kr_log_debug(DOQCLIENT, "Failed to initiate stream session\n");
		ngtcp2_conn_shutdown_stream(conn->conn, 0,
				stream_id, DOQ_INTERNAL_ERROR);
		return NULL;
	}

	new_stream->state |= QUIC_STREAM_BIDI_OPEN;
	if (session2_timer_start(new_stream->h.session,
				PROTOLAYER_EVENT_GENERAL_TIMEOUT,
				KR_RESOLVE_TIME_LIMIT, 0) != 0) {
		kr_log_debug(DOQCLIENT, "Failed to start timer for DoQ stream session, abort stream setup\n");
		session2_force_close(new_stream->h.session);
		return NULL;
	}
	new_stream->state |= QUIC_STREAM_HAS_TIMER;

	return new_stream->h.session;
}

static int kr_quic_set_session_addrs(struct session2 *s, ngtcp2_path **path)
{
	const struct sockaddr *remote = s->comm_storage.dst_addr;
	const struct sockaddr *local  = s->comm_storage.src_addr;
	if (!remote || !local) {
		return kr_error(EINVAL);
	}

	int rlen = kr_sockaddr_len(remote);
	int llen = kr_sockaddr_len(local);
	if (rlen <= 0 || llen <= 0) {
		return kr_error(EINVAL);
	}

	(*path)->remote.addr = (struct sockaddr *)remote;
	(*path)->remote.addrlen = rlen;
	(*path)->local.addr = (struct sockaddr *)local;
	(*path)->local.addrlen = llen;
	return kr_ok();
}

static void kr_quic_set_addrs(struct protolayer_iter_ctx *ctx, ngtcp2_path **path)
{
	const struct sockaddr *remote = NULL;
	struct sockaddr *local = NULL;

	if (ctx->session->outgoing) {
		local = (struct sockaddr *)ctx->comm->src_addr;
		remote = ctx->comm->dst_addr;
	} else {
		local = (struct sockaddr *)ctx->comm->src_addr;
		remote = ctx->comm->comm_addr;
	}

	if (local == NULL) {
		local = session2_get_sockname(ctx->session);
	}

	(*path)->remote.addr = (struct sockaddr *)remote;
	(*path)->remote.addrlen = kr_sockaddr_len(remote);
	(*path)->local.addr = local;
	(*path)->local.addrlen = kr_sockaddr_len(local);
}

static int quic_hs_hook(gnutls_session_t session, unsigned int htype,
		unsigned when, unsigned int incoming, const gnutls_datum_t *msg)
{
	if (htype != GNUTLS_HANDSHAKE_NEW_SESSION_TICKET || !incoming)
		return 0;

	nc_conn_ref_placeholder_t *ref = gnutls_session_get_ptr(session);
	struct pl_quic_conn_sess_data *conn = ref->user_data;
	if (!conn->client_params)
		return 0;

	gnutls_datum_t d = { NULL, 0 };
	if (gnutls_session_get_data2(session, &d) == GNUTLS_E_SUCCESS) {
		gnutls_free(conn->client_params->quic_session_data.data);
		conn->client_params->quic_session_data = d;
	}
	return 0;
}

int kr_quic_tls_session(struct pl_quic_conn_sess_data *conn)
{
	if (!conn || !conn->table_ref || !conn->table_ref->priority) {
		kr_log_error(DOQ, "Missing connection table TLS priority\n");
		return kr_error(EINVAL);
	}

	int flags = (conn->is_server ? GNUTLS_SERVER : GNUTLS_CLIENT) | GNUTLS_NONBLOCK;
	
#if GNUTLS_VERSION_NUMBER >= 0x030705
	if (gnutls_check_version("3.7.5"))
		flags |= GNUTLS_NO_TICKETS_TLS12;
#endif
	int ret = gnutls_init(&conn->tls_session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(DOQ, "gnutls_init(): %s (%d)\n",
				gnutls_strerror_name(ret), ret);
		return ret;
	}

	ret = gnutls_priority_set(conn->tls_session, conn->table_ref->priority);
	if (ret != GNUTLS_E_SUCCESS) {
		kr_log_error(DOQ, "gnutls_priority_set(): %s (%d)\n",
				gnutls_strerror_name(ret), ret);
		return ret;
	}

	if (conn->is_server) {
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
						kr_log_info(DOQ, "Renewed expiring ephemeral X.509 cert\n");
					} else {
						kr_log_error(DOQ, "Failed to renew expiring ephemeral X.509 cert, using existing one\n");
					}
				}
			/* non-ephemeral cert: warn once when certificate expires */
			} else if (now >= the_network->tls_credentials->valid_until) {
				kr_log_error(DOQ, "X.509 certificate has expired!\n");
				the_network->tls_credentials->valid_until =
					GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION;
			}
		}

		conn->server_credentials = tls_credentials_reserve(the_network->tls_credentials);
		ret = gnutls_credentials_set(conn->tls_session, GNUTLS_CRD_CERTIFICATE,
					     conn->server_credentials->credentials);
		if (ret != GNUTLS_E_SUCCESS) {
			kr_log_error(DOQ, "gnutls_credentials_set(): %s (%d)\n",
					gnutls_strerror_name(ret), ret);
			return ret;
		}

		gnutls_certificate_send_x509_rdn_sequence(conn->tls_session, 1);
		gnutls_certificate_server_set_request(conn->tls_session, GNUTLS_CERT_IGNORE);
		if (conn->is_server && the_network->tls_session_ticket_ctx) {
			tls_session_ticket_enable(the_network->tls_session_ticket_ctx,
						  conn->tls_session);
		}
	} else {
		conn->client_params =
			tls_client_param_get(the_network->tls_client_params,
				conn->comm_storage.dst_addr);
		if (!conn->client_params) {
			/* TODO: deal with this cleanly */
			kr_log_error(DOQCLIENT, "tls_client_param_new returned NULL\n");
			kr_require(false);
		}
		conn->client_params->refs++;

		ret = gnutls_credentials_set(conn->tls_session, GNUTLS_CRD_CERTIFICATE,
				conn->client_params->credentials);
		if (ret == GNUTLS_E_SUCCESS && conn->client_params->hostname) {
			ret = gnutls_server_name_set(conn->tls_session,
					GNUTLS_NAME_DNS,
					conn->client_params->hostname,
					strlen(conn->client_params->hostname));
			kr_log_debug(DOQCLIENT, "set hostname, ret = %d\n", ret);
		} else if (!conn->client_params->hostname) {
			kr_log_debug(DOQCLIENT, "no hostname\n");
		}
		if (ret != GNUTLS_E_SUCCESS) {
			kr_log_error(DOQ, "gnutls_credentials_set(): %s (%d)\n",
					gnutls_strerror_name(ret), ret);
			return ret;
		}

		if (conn->client_params->quic_session_data.data) {
			(void)gnutls_session_set_data(conn->tls_session,
					conn->client_params->quic_session_data.data,
					conn->client_params->quic_session_data.size);
		}

		gnutls_handshake_set_hook_function(conn->tls_session,
			GNUTLS_HANDSHAKE_NEW_SESSION_TICKET, GNUTLS_HOOK_POST,
			quic_hs_hook);
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

static int quic_tls_init_conn_session(struct pl_quic_conn_sess_data *conn)
{
	int ret = kr_quic_tls_session(conn);
	if (ret != 0)
		return ret;

	ret = (conn->is_server)
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
	if (!conn->is_server)
		kr_tls_session_set_verify(conn->tls_session, true);
	ngtcp2_conn_set_tls_native_handle(conn->conn, conn->tls_session);

	return kr_ok();
}

int quic_init_conn(struct pl_quic_conn_sess_data *conn,
		struct protolayer_iter_ctx *ctx, bool server)
{
	if (!ctx) {
		return kr_error(EINVAL);
	}

	uint64_t now = quic_timestamp();

	int ret = conn_new_handler(&conn->conn, conn->path,
			&conn->scid, &conn->dcid, &conn->odcid,
			server ? conn->version : 0x01u,
			now, server, conn->retry_sent,
			conn);
	if (ret == 0) {
		ret = quic_tls_init_conn_session(conn);
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

		size_t payload_len = s->unsent_obuf->len - s->unsent_offset;
		uint64_t conn_max_send =
			ngtcp2_conn_get_max_data_left(conn->conn);
		uint64_t stream_max_send =
			ngtcp2_conn_get_max_stream_data_left(conn->conn,
					s->stream_id);
		/* break, the connection cannot send any more data at this time */
		if (conn_max_send < payload_len) {
			break;
		}
		/* proceed to the next stream, this limit applies to each
		 * stream separately */
		if (stream_max_send < payload_len) {
			continue;
		}
		/* we will not be able to send any more data until
		 * the congestion window grows. */
		if (ngtcp2_conn_get_cwnd_left(conn->conn) < payload_len) {
			break;
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

	struct protolayer_payload orig_pld = ctx->payload;
	ctx->payload = protolayer_payload_wire_buf(&err_wb, true);

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
		if (kr_fails_assert(table && (dec_cids || conn)))
			break;

		ret = write_retry_packet(ctx->payload.wire_buf, table,
				ctx->comm->src_addr, dec_cids, conn);
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
					NULL, NULL);
		} else {
			/* send special can be called from demux layer
			 * where the conn session might not exist yet. */
			session2_wrap(session, ctx->payload, ctx->comm,
					NULL,
					NULL, NULL);
		}
		ret = kr_ok();
	}

	mm_free(&ctx->pool, ctx->payload.wire_buf->buf);
	ctx->payload = orig_pld;

	return ret;
}

/* If the packet is INITIAL and the connection setup fails simply setting the
 * conn->state to DRAINING will result in session teardown. */
static int quic_bye(struct pl_quic_conn_sess_data *conn)
{
	if (!conn) {
		return kr_error(EINVAL);
	}

	wire_buf_reset(&conn->h.session->wire_buf);
	struct protolayer_payload payload =
		protolayer_payload_wire_buf(&conn->h.session->wire_buf, true);

	return session2_wrap(conn->h.session, payload, &conn->comm_storage,
			NULL, NULL, NULL);
}

static enum protolayer_iter_cb_result pl_quic_conn_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret = kr_ok();
	struct pl_quic_conn_sess_data *conn = sess_data;
	if (conn->state & (QUIC_STATE_DRAINING | QUIC_STATE_HS_ABORT)) {
		return protolayer_break(ctx, kr_ok());
	}

	if (!conn->h.session->outgoing) {
		kr_quic_set_addrs(ctx, &conn->path);
	}

	if (!conn->conn) {
		kr_require(!ctx->session->outgoing);

		if ((ret = quic_init_conn(conn, ctx, true)) != kr_ok()) {
			kr_log_error(DOQ, "Failed to initiate quic connection (%d)\n", ret);
			QUIC_SET_DRAINING(conn);
			return protolayer_break(ctx, ret);
		}
	}

	quic_doq_error_t doq_error;
	ret = handle_packet(conn, ctx, &doq_error);
	if (ret != kr_ok()) {
		if (ret != QUIC_SEND_NONE) {
			(void)send_special(NULL,
					conn->table_ref, ctx, ret, conn,
					conn->h.session, &doq_error);
		}

		return protolayer_break(ctx, kr_ok());
	}

	quic_reset_expiry(conn);

	if (queue_len(conn->pending_unwrap) == 0) {
		wire_buf_reset(&conn->h.session->wire_buf);
		ret = session2_wrap(conn->h.session,
				protolayer_payload_wire_buf(&conn->h.session->wire_buf, false),
				ctx->comm,
				NULL,
				ctx->finished_cb,
				ctx->finished_cb_baton);

		return protolayer_break(ctx, kr_ok());
	}

	bool first = true;
	while (queue_len(conn->pending_unwrap) > 0) {
		struct session2 *s = queue_head(conn->pending_unwrap)->h.session;
		queue_pop(conn->pending_unwrap);
		/* Should not happen */
		if (kr_fails_assert(s->ref_count > 1)) {
			kr_log_warning(DOQ, "terminated session in unwrap queue\n");
			session2_close(s);
			continue;
		}
		session2_dec_refs(s);
		if (conn->h.session->outgoing && !first)
			defer_sample_restart();
		first = false;
		session2_unwrap(s,
				ctx->payload,
				NULL /* &conn->comm_storage */,
				ctx->finished_cb,
				ctx->finished_cb_baton);

		if (s->outgoing) {
			session2_close(s);
		}
	}

	return protolayer_break(ctx, kr_ok());
}

static enum protolayer_iter_cb_result pl_quic_conn_wrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret = 0;
	struct pl_quic_conn_sess_data *conn = sess_data;

	if (!conn->conn) {
		if (likely(conn->h.session->outgoing)) {
			ret = kr_quic_set_session_addrs(conn->h.session, &conn->path);
			if (kr_fails_assert(ret == 0))
				return protolayer_break(ctx, ret);
		} else {
			/* Rare situation caused by the task finishing
			 * after the peer already terminated the connection. */
			return protolayer_break(ctx, 0);
			// kr_quic_set_addrs(ctx, &conn->path);
		}

		if ((ret = quic_init_conn(conn, ctx, false)) != kr_ok()) {
			kr_log_error(DOQ, "Failed to create QUIC connection %d\n",
					ret);
			return protolayer_break(ctx, ret);
		}
	}

	if (!quic_not_draining(conn)) {
		return protolayer_break(ctx, kr_ok());
	}
	ngtcp2_tstamp now = quic_timestamp();

	if (conn->is_server) {
		kr_quic_set_addrs(ctx, &conn->path);
	}

	/* Flush bye message and promote state to DRAINING */
	if (conn->state & QUIC_STATE_CLOSING) {
		quic_doq_error_t doq_error = DOQ_NO_ERROR;
		ret = send_special(NULL,
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
			quic_reset_expiry(conn);
			return protolayer_continue(ctx);
		}

		int nwrite = ngtcp2_conn_writev_stream(conn->conn,
				conn->path, &pi,
				wire_buf_free_space(ctx->payload.wire_buf),
				wire_buf_free_space_length(ctx->payload.wire_buf),
				&sent, NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL,
				0, now);

		if (nwrite > 0)
			ngtcp2_conn_update_pkt_tx_time(conn->conn, quic_timestamp());
		if (nwrite == 0) {
			quic_reset_expiry(conn);
			return protolayer_break(ctx, kr_ok());
		}

		if (nwrite < 0) {
			ngtcp2_ccerr_set_liberr(&conn->ccerr, nwrite, NULL, 0);
			quic_reset_expiry(conn);
			return protolayer_break(ctx, kr_ok());
		}

		wire_buf_consume(ctx->payload.wire_buf, nwrite);
	}

	quic_reset_expiry(conn);
	if (conn->state & QUIC_STATE_CLOSING) {
		quic_set_draining(conn);
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
	int ret = kr_error(ENOMEM);
	struct pl_quic_conn_sess_data *conn = sess_data;
	conn->state = 0;
	conn->disconnected = false;
	conn->term_event = PROTOLAYER_EVENT_NULL;
	conn->path = calloc(1, sizeof(ngtcp2_path));
	if (!conn->path) {
		return kr_error(ENOMEM);
	}

	kr_require(wire_buf_free_space_length(&session->wire_buf) <= 1<<12);

	struct kr_quic_conn_param *p = param;
	conn->dcid = p->dcid;
	conn->scid = p->scid;
	conn->armed_expiry = 0;
	conn->odcid = p->odcid;
	conn->retry_sent = p->retry_sent;
	conn->table_ref = p->table;
	conn->token_present = p->token_present;
	ngtcp2_ccerr_default(&conn->ccerr);

	conn->version = p->dec_cids ? p->dec_cids->version : NGTCP2_PROTO_VER_V1;


	copy_comm_storage(&session->comm_storage, &conn->comm_addr_storage,
			p->comm_storage);

	conn->comm_storage = session->comm_storage;

	queue_init(conn->pending_unwrap);
	conn->is_server = !session->outgoing;

	init_list(&conn->streams);

	conn->conn = NULL;
	conn->streams_count = 0;
	conn->tls_session = NULL;
	conn->server_credentials = NULL;
	if (unlikely(quic_generate_secret(conn->secret,
					sizeof(conn->secret)) != kr_ok())) {
		kr_log_error(DOQ, "Failed to init connection session\n");
		queue_deinit(conn->pending_unwrap);
		ret = kr_error(EINVAL);
		goto failed;
	}

	return kr_ok();
failed:
	session->comm_storage.dst_addr = NULL;
	session->comm_storage.src_addr = NULL;
	session->comm_storage.comm_addr = NULL;
	conn->comm_storage = (struct comm_info){ 0 };
	free(conn->path);
	conn->path = NULL;

	return ret;
}

static int pl_quic_conn_sess_deinit(struct session2 *session, void *sess_data)
{
	struct pl_quic_conn_sess_data *conn = sess_data;

	session2_timer_stop(session);


	while (!session2_waitinglist_is_empty(session)) {
		session2_waitinglist_finalize(session, KR_STATE_FAIL);
	}

	kr_require(session2_is_empty(session));
	kr_require(EMPTY_LIST(conn->streams)); // NOLINT(bugprone-casting-through-void)
	kr_require(conn->cid_pointers == 0);
	kr_require(conn->streams_count == 0);

	if (conn->state & QUIC_STATE_HANDSHAKE_DONE) {
		kr_log_debug(DOQ, "Closing established connection to: '%s', [%s] useful, served %zu streams\n",
				kr_straddr(conn->comm_storage.comm_addr),
				conn->finished_streams ? "was" : "was not",
				conn->finished_streams);
	} else {
		kr_log_debug(DOQ, "Closing connection with unfinished HS to: '%s', wasn't useful, [%s] send retry\n",
				kr_straddr(conn->comm_storage.comm_addr),
				conn->retry_sent ? "did" : "did not");
	}

	if (conn->tls_session) {
		gnutls_deinit(conn->tls_session);
	}

	if (conn->is_server) {
		tls_credentials_release(conn->server_credentials);
	} else {
		if (conn->client_params) {
			tls_client_param_unref(conn->client_params);
		}
	}


	if (conn->path) {
		free(conn->path);
	}

	conn->tls_session = NULL;
	conn->server_credentials = NULL;
	ngtcp2_conn_del(conn->conn);
	conn->conn = NULL;

	return kr_ok();
}

static enum protolayer_event_cb_result pl_quic_conn_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	struct pl_quic_conn_sess_data *conn = sess_data;
	switch (event) {
	case PROTOLAYER_EVENT_CONNECT_TIMEOUT:
		if (session->outgoing)
			worker_remove_quic_conn(session, quic_get_peer(session));
		quic_handshake_timeout(session, KR_SELECTION_TLS_HANDSHAKE_FAILED);
		kr_require(session2_waitinglist_is_empty(session)
				&& session2_tasklist_is_empty(session));
		/* fallthrough */
	case PROTOLAYER_EVENT_CLOSE:
		QUIC_SET_CLOSING(conn);
		(void)quic_bye(conn);
		/* fallthrough */
	case PROTOLAYER_EVENT_FORCE_CLOSE:
	case PROTOLAYER_EVENT_GENERAL_TIMEOUT:
		if (event != PROTOLAYER_EVENT_CONNECT_TIMEOUT && session->outgoing) {
			worker_remove_quic_conn(session, quic_get_peer(session));
		}

		while (queue_len(conn->pending_unwrap) > 0) {
			struct pl_quic_stream_sess_data *stream =
				queue_head(conn->pending_unwrap);
			struct session2 *s = stream->h.session;
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
			session2_event(s->h.session, event, NULL);
			s = NULL;
		}

		// NOLINTNEXTLINE(bugprone-casting-through-void)
		if (!EMPTY_LIST(conn->streams)) {
			kr_log_notice(DEVEL, "Streams list not empty: %hd\n",
					conn->streams_count);
		}
		//
		// NOLINTNEXTLINE(bugprone-casting-through-void)
		kr_require(EMPTY_LIST(conn->streams));

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
		 * within the session, subsessions were handled manually). */
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
			if (!ngtcp2_conn_is_local_stream(stream->conn,
						stream->stream_id))
				ngtcp2_conn_extend_max_streams_bidi(
						stream->conn, 1);
			if (!stream->closed) {
				ngtcp2_conn_shutdown_stream(stream->conn, 0,
						stream->stream_id,
						DOQ_REQUEST_CANCELLED);
				ngtcp2_conn_set_stream_user_data(conn->conn,
						stream->stream_id, NULL);
			}
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
		.wire_buf_overhead = 1 << 12,
		.sess_init = pl_quic_conn_sess_init,
		.sess_deinit = pl_quic_conn_sess_deinit,
		.unwrap = pl_quic_conn_unwrap,
		.wrap = pl_quic_conn_wrap,
		.event_unwrap = pl_quic_conn_event_unwrap,
		.event_wrap = pl_quic_conn_event_wrap,
	};
}
