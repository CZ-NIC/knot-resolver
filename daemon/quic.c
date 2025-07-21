/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <bits/types/struct_iovec.h>
#include <errno.h>
#include <gnutls/x509.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "lib/defines.h"
#include "lib/log.h"
#include "lib/resolve-impl.h"
#include "session2.h"
#include "network.h"
#include "lib/resolve.h"
// #include "libknot/quic/quic.h"
#include "libdnssec/random.h"
#include <libknot/xdp/tcp_iobuf.h>
#include <stdint.h>
#include <contrib/ucw/heap.h>
#include <contrib/ucw/lists.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include "contrib/openbsd/siphash.h"
#include "lib/utils.h"
#include "libdnssec/error.h"

#include <stddef.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <worker.h>

// FIXME: For now just to perform the pin check once HS finishes
#include <libknot/quic/tls_common.h>

#include "quic.h"
#include "quic_stream.h"

/** Implementation overview
 * From a very high standpoint a DoQ query is handled as follows:
 * As a server side we only react to incoming communication from
 * the client. Every time client flushes his prepared pkt, we try
 * to respond by either:
 *   1. Driving the handshake process forward or
 *   2. resolving the query and provinding the response.
 *
 * In other words any time pl_quic_unwrap is invoked, we:
 * 1. Check the connection table to either resume a connection or
 *   create a new one.
 *
 * 2. Read all the data provided in the protolayer_payload.
 *   2.1. If the read data contains any ACK frames (i.e. the pkt is not 0RTT)
 *     we shift the left side of "send but not acked" buffer.
 *
 * 3. Attempt to create a response.
 *   3.1. In case the query has not been as of yet fully received and acked.
 *     we just call ngtcp2_conn_writev_stream with no data (see ngtcp2 doc.).
 *     ngtcp2 takes care of all that is neccesary for a succesful conclusion
 *     of a quic HS.
 *   3.2. In case we received STREAM FIN we know that client has no more data
 *     to send and we can begin resolving the query. RFC 9250 requires
 *     a stream to be used for exactly one query. Since the client has
 *     closed his write endpoint and we have send all we had, we can
 *     now close the entire stream.
 *
 * 4. The connection will remain in memory, allowing the user
 *   to simply open a new stream and send the next query.
 *
 * This overview ignores crutial details, special cases, and whole
 * sections of the implementation. Refer to RFC 9000, RF 9001, RFC 9250, 
 * https://nghttp2.org/ngtcp2/index.html, and the code itself
 * for a comprehensive understanding.
 */

static uint64_t cid2hash(const ngtcp2_cid *cid, kr_quic_table_t *table);
kr_quic_conn_t *kr_quic_table_lookup(const ngtcp2_cid *cid, kr_quic_table_t *table);
kr_quic_cid_t **kr_quic_table_lookup2(const ngtcp2_cid *cid, kr_quic_table_t *table);
kr_quic_cid_t **kr_quic_table_insert(kr_quic_conn_t *conn, const ngtcp2_cid *cid,
                                    kr_quic_table_t *table);
static int pl_quic_client_init(struct session2 *session,
			       pl_quic_sess_data_t *quic,
			       tls_client_param_t *param);

int kr_quic_send(kr_quic_table_t *quic_table, kr_quic_conn_t *conn,
                   /* kr_quic_reply_t *reply */void *sess_data,
		   struct protolayer_iter_ctx *ctx,
		   unsigned max_msgs, kr_quic_send_flag_t flags);
uint64_t quic_timestamp(void);

#define set_application_error(ctx, error_code, reason, reason_len) \
	ngtcp2_ccerr_set_application_error(&(ctx)->last_err, \
	        error_code, reason, reason_len)
#define set_transport_error(ctx, error_code, reason, reason_len) \
	ngtcp2_ccerr_set_transport_error(&(ctx)->last_err, \
	        error_code, reason, reason_len)

static int cmp_expiry_heap_nodes(void *c1, void *c2)
{
	if (((kr_quic_conn_t *)c1)->next_expiry < ((kr_quic_conn_t *)c2)->next_expiry)
		return -1;

	if (((kr_quic_conn_t *)c1)->next_expiry > ((kr_quic_conn_t *)c2)->next_expiry)
		return 1;

	return 0;
}

static void kr_quic_rand_cb(uint8_t *dest, size_t destlen,
	const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;
	dnssec_random_buffer(dest, destlen);
}

uint64_t quic_timestamp(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;

	return ((uint64_t)ts.tv_sec * NGTCP2_SECONDS) + (uint64_t)ts.tv_nsec;
}

// ngtcp2_conn *get_ngtcp2_conn(void *user_data)
// {
// 	if (!user_data)
// 		return NULL;
//
// 	pl_quic_sess_data_t *ctx = (pl_quic_sess_data_t *)user_data;
// 	return ctx->conn;
// }

static void init_random_cid(ngtcp2_cid *cid, size_t len)
{
	if (len == 0)
		len = SERVER_DEFAULT_SCIDLEN;

	cid->datalen = dnssec_random_buffer(cid->data, len) == DNSSEC_EOK ? len : 0;
}

static bool init_unique_cid(ngtcp2_cid *cid, size_t len, kr_quic_table_t *table)
{
	do {
		if (init_random_cid(cid, len), cid->datalen == kr_ok())
			return false;

	} while (kr_quic_table_lookup(cid, table) != NULL);

	return true;
}

kr_quic_conn_t *kr_quic_table_add(ngtcp2_conn *ngconn, const ngtcp2_cid *cid,
                                 kr_quic_table_t *table)
{
	kr_quic_conn_t *conn = calloc(1, sizeof(*conn));
	if (conn == NULL)
		return NULL;

	conn->conn = ngconn;
	conn->quic_table = table;
	conn->stream_inprocess = -1;
	conn->qlog_fd = -1;

	conn->next_expiry = UINT64_MAX;
	if (!heap_insert(table->expiry_heap, (heap_val_t *)conn)) {
		free(conn);
		return NULL;
	}

	kr_quic_cid_t **addto = kr_quic_table_insert(conn, cid, table);
	if (addto == NULL) {
		heap_delete(table->expiry_heap, heap_find(table->expiry_heap, (heap_val_t *)conn));
		free(conn);
		return NULL;
	}

	table->usage++;

	return conn;
}

kr_quic_cid_t **kr_quic_table_insert(kr_quic_conn_t *conn, const ngtcp2_cid *cid,
                                    kr_quic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	kr_quic_cid_t *cidobj = malloc(sizeof(*cidobj));
	if (cidobj == NULL)
		return NULL;

	static_assert(sizeof(*cid) <= sizeof(cidobj->cid_placeholder),
			"insufficient placeholder for CID struct");
	memcpy(cidobj->cid_placeholder, cid, sizeof(*cid));
	cidobj->conn = conn;

	kr_quic_cid_t **addto = table->conns + (hash % table->size);
	cidobj->next = *addto;
	*addto = cidobj;
	table->pointers++;

	return addto;
}

static int kr_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
	int64_t stream_id, uint64_t offset, const uint8_t *data,
	size_t datalen, void *user_data, void *stream_user_data)
{
	(void)(stream_user_data); // always NULL
	(void)(offset); // QUIC shall ensure that data arrive in-order

	struct kr_quic_conn *qconn = (struct kr_quic_conn *)user_data;
	assert(ctx->conn == conn);
	kr_log_info(DOQ, "recved stream data: %s\n", data);

	int ret = kr_quic_stream_recv_data(qconn, stream_id, data, datalen,
			(flags & NGTCP2_STREAM_DATA_FLAG_FIN));

	return ret == KNOT_EOK ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}


// TODO Will likely be removed once the proper buffer scheme for
// pl is figured out
uint64_t buffer_alloc_size(uint64_t buffer_len)
{
	if (buffer_len == 0) {
		return 0;
	}
	buffer_len -= 1;
	buffer_len |= 0x3f; // the result will be at least 64
	buffer_len |= (buffer_len >> 1);
	buffer_len |= (buffer_len >> 2);
	buffer_len |= (buffer_len >> 4);
	buffer_len |= (buffer_len >> 8);
	buffer_len |= (buffer_len >> 16);
	buffer_len |= (buffer_len >> 32);
	return buffer_len + 1;
}

void kr_quic_table_rem2(kr_quic_cid_t **pcid, kr_quic_table_t *table)
{
	kr_quic_cid_t *cid = *pcid;
	*pcid = cid->next;
	free(cid);
	table->pointers--;
}

void kr_quic_table_rem(kr_quic_conn_t *conn, kr_quic_table_t *table)
{
	if (conn == NULL || conn->conn == NULL || table == NULL)
		return;

	for (ssize_t i = conn->streams_count - 1; i >= 0; i--)
		kr_quic_conn_stream_free(conn, (i + conn->first_stream_id) * 4);

	assert(conn->streams_count <= 0);
	assert(conn->obufs_size == 0);

	size_t num_scid = ngtcp2_conn_get_scid(conn->conn, NULL);
	ngtcp2_cid *scids = calloc(num_scid, sizeof(*scids));
	ngtcp2_conn_get_scid(conn->conn, scids);

	for (size_t i = 0; i < num_scid && scids; i++) {
		kr_quic_cid_t **pcid = kr_quic_table_lookup2(&scids[i], table);
		assert(pcid != NULL);
		if (*pcid == NULL)
			continue;

		assert((*pcid)->conn == conn);
		kr_quic_table_rem2(pcid, table);
	}

	int pos = heap_find(table->expiry_heap, (heap_val_t *)conn);
	heap_delete(table->expiry_heap, pos);

	free(scids);

	gnutls_deinit(conn->tls_session);
	ngtcp2_conn_del(conn->conn);
	conn->conn = NULL;

	table->usage--;
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 uint8_t *token, size_t cidlen,
                                 void *user_data)
{
	kr_log_info(DOQ, "Get new connection id\n");

	kr_quic_conn_t *ctx = (kr_quic_conn_t *)user_data;
	assert(ctx->conn == conn);

	if (!init_unique_cid(cid, cidlen, ctx->quic_table))
		return NGTCP2_ERR_CALLBACK_FAILURE;

	kr_quic_cid_t **addto = kr_quic_table_insert(ctx, cid, ctx->quic_table);
	(void)addto;

	// FIXME: remove?
	// ctx->dcid = cid;

	if (token != NULL &&
	    ngtcp2_crypto_generate_stateless_reset_token(
	            token, (uint8_t *)ctx->quic_table->hash_secret,
	            sizeof(ctx->quic_table->hash_secret), cid) != 0) {
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

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	kr_log_info(DOQ, "Handshake completed\n");
	kr_quic_conn_t *ctx = (kr_quic_conn_t *)user_data;
	assert(ctx->conn == conn);

	assert(!(ctx->flags & kr_QUIC_CONN_HANDSHAKE_DONE));
	ctx->flags |= KR_QUIC_CONN_HANDSHAKE_DONE;

	if (!ngtcp2_conn_is_server(conn)) {
		return NGTCP2_NO_ERROR;
		// TODO: Perform certificate pin check
		// return knot_tls_pin_check(ctx->tls_session, ctx->quic_table->creds)
		//        == KNOT_EOK ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
		// return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (gnutls_session_ticket_send(ctx->tls_session, 1, 0) != GNUTLS_E_SUCCESS) {
		return -1;
	}

	uint8_t token[NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN];
	ngtcp2_path path = *ngtcp2_conn_get_path(ctx->conn);
	uint64_t ts = quic_timestamp();
	ngtcp2_ssize tokenlen = ngtcp2_crypto_generate_regular_token(token,
			(uint8_t *)ctx->quic_table->hash_secret,
			sizeof(ctx->quic_table->hash_secret),
			path.remote.addr, path.remote.addrlen, ts);

	if (tokenlen < 0
		|| ngtcp2_conn_submit_new_token(ctx->conn, token, tokenlen) != 0)
		return NGTCP2_ERR_CALLBACK_FAILURE;

	return 0;
}

static int recv_rx_key_conf_cb(struct ngtcp2_conn *c,
		enum ngtcp2_encryption_level el, void* _undef)
{
	kr_log_info(DOQ, "Decryption key has been installed!\n");
	return kr_ok();
}

static int recv_tx_key_conf_cb(struct ngtcp2_conn *c,
		enum ngtcp2_encryption_level el, void* _undef)
{
	kr_log_info(DOQ, "Encryption key has been installed!\n");
	/*
	 * Here we can now begin trasmiting non-confidential data
	 * all sensitive data SHOULD be transfered after the handshake
	 * completes (after it really gets authenticated)
	 */
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

int recv_crypto_data(ngtcp2_conn *conn,
		 ngtcp2_encryption_level encryption_level, uint64_t offset,
		 const uint8_t *data, size_t datalen, void *user_data) {
	kr_log_debug(DOQ, "Crypto data: %d %s %ld\n", encryption_level, data, datalen);

	return ngtcp2_crypto_recv_crypto_data_cb(conn, encryption_level, offset, data,
		 datalen, user_data);
}

int do_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
		const ngtcp2_crypto_cipher_ctx *hp_ctx, const uint8_t *sample) {
	if (ngtcp2_crypto_hp_mask(dest, hp, hp_ctx, sample) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	kr_log_debug(DOQ, "hp mask installed %s %d %s %d\n", dest, NGTCP2_HP_MASKLEN, sample, NGTCP2_HP_SAMPLELEN);

	return 0;
}

static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
	kr_log_info(DOQ, "remote endpoint has opened a stream: %ld\n", stream_id);

	// knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;
	// assert(ctx->conn == conn);
	//
	// // NOTE possible error is stored in (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)
	//
	// bool keep = !ngtcp2_conn_is_server(conn); // kxdpgun: process incomming reply after recvd&closed
	// if (!keep) {
	// 	knot_quic_conn_stream_free(ctx, stream_id);
	// }
	return kr_ok();
}

// static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
// 			 uint64_t app_error_code, void *user_data, void *stream_user_data)
// {
// 	struct kr_quic_conn *qconn = (struct kr_quic_conn *)user_data;
// 	assert(qconn->conn == conn);
//
// 	struct kr_quic_stream *stream = kr_quic_conn_get_stream(qconn, stream_id, true);
//
// 	if (stream == NULL) {
// 		return KNOT_ENOENT;
// 	}
//
// 	// TODO resolve
//
// 	//
// 	// // NOTE possible error is stored in (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)
// 	//
// 	// bool keep = !ngtcp2_conn_is_server(conn); // kxdpgun: process incomming reply after recvd&closed
// 	// if (!keep) {
// 	// 	knot_quic_conn_stream_free(ctx, stream_id);
// 	// }
// 	return kr_ok();
// }


// TODO: Perhaps move path creating here, It would make sence even though
// it is just a simple function call
static int conn_new_handler(ngtcp2_conn **pconn, const ngtcp2_path *path,
		const ngtcp2_cid *scid, const ngtcp2_cid *dcid,
		const ngtcp2_cid *odcid, uint32_t version,
		uint64_t now, uint64_t idle_timeout_ns,
		kr_quic_conn_t *qconn, bool server, bool retry_sent)
{
	kr_require(qconn->quic_table != NULL);
	kr_quic_table_t *qtable = qconn->quic_table;

	const ngtcp2_callbacks callbacks = {
		// .client_initial = ngtcp2_crypto_client_initial_cb, // client side callback
		.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.handshake_completed = handshake_completed_cb, // handshake_completed_cb - OPTIONAL
		// NULL, // recv_version_negotiation not needed on server, nor kxdpgun - OPTIONAL
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.recv_stream_data = kr_recv_stream_data_cb, // recv_stream_data, TODO? - OPTIONAL
		// NULL, // acked_stream_data_offset_cb, TODO - OPTIONAL
		.stream_open = stream_open_cb, // stream_opened - OPTIONAL
		// .stream_close = stream_close_cb, // stream_closed, TODO - OPTIONAL
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
		.recv_rx_key = recv_rx_key_conf_cb,
		.recv_tx_key = recv_tx_key_conf_cb,
	};

	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = now;

	if (KR_LOG_LEVEL_IS(LOG_DEBUG)) {
	// if (qtable->log_cb != NULL) {
		settings.log_printf = quic_debug_cb;
	}

	// Probablu set bu default, set NULL to disable qlog
	// if (qtable->qlog_dir != NULL) {
		// settings.qlog_write = user_printf;
	// }

	if (qtable->udp_payload_limit != 0) {
		settings.max_tx_udp_payload_size = qtable->udp_payload_limit;
	}

	// settings.handshake_timeout = idle_timeout_ns; // NOTE setting handshake timeout to idle_timeout for simplicity
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

	params.stateless_reset_token_present = 1;
	params.active_connection_id_limit = 8;

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
		return ngtcp2_conn_server_new(pconn, swapped_clients_dcid,
				swapped_clients_scid, path, version,
				&callbacks, &settings, &params, NULL, qconn);
	} else {
		return ngtcp2_conn_client_new(pconn, dcid, scid, path, version, &callbacks,
		                              &settings, &params, NULL, qconn);
	}
}


int kr_tls_session(struct gnutls_session_int **session,
		struct tls_credentials *creds,
		struct gnutls_priority_st *priority,
		bool quic, // TODO remove, this function will only be used by doq
		bool early_data,
		bool server)
{
	if (session == NULL || creds == NULL || priority == NULL)
		return KNOT_EINVAL;

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
	return ((kr_quic_conn_t *)conn_ref->user_data)->conn;
}

static int tls_init_conn_session(kr_quic_conn_t *conn, bool server)
{
	int ret = kr_tls_session(&conn->tls_session, conn->quic_table->creds,
	                           conn->quic_table->priority, true, true, server);
	if (ret != KNOT_EOK) {
		kr_log_warning(DOQ, "kr_tls_session Failed :%d %s %s\n",
				ret, ngtcp2_strerror(ret), gnutls_strerror(ret));
		return kr_error(ret);
	}

	if (server) {
		ret = ngtcp2_crypto_gnutls_configure_server_session(conn->tls_session);
		kr_log_info(DOQ, "configuring crypto server: %s (%d)\n", ngtcp2_strerror(ret), ret);
	} else {
		ret = ngtcp2_crypto_gnutls_configure_client_session(conn->tls_session);
	}

	if (ret != NGTCP2_NO_ERROR) {
		kr_log_warning(DOQ, "Failed to configure gnutls session (%d) %s\n",
				ret, ngtcp2_strerror(ret));
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

kr_quic_table_t *kr_quic_table_new(size_t max_conns, size_t max_ibufs, size_t max_obufs,
                                       size_t udp_payload, struct tls_credentials *creds)
{
#define BUCKETS_PER_CONNS 8
	size_t table_size = max_conns * BUCKETS_PER_CONNS;

	kr_quic_table_t *new_table = calloc(1, sizeof(*new_table) + (table_size * sizeof(new_table->conns[0])));
	if (new_table == NULL || creds == NULL) {
		kr_log_error(DOQ, "Calloc in kr_quic_table_new_failed %d %d\n",
				new_table == NULL, creds == NULL);
		return NULL;
	}

	new_table->size = table_size;
	new_table->max_conns = max_conns;
	new_table->ibufs_max = max_ibufs;
	new_table->obufs_max = max_obufs;
	new_table->obufs_size = 0;
	new_table->udp_payload_limit = udp_payload;

	// int ret = gnutls_certificate_allocate_credentials(&new_table->creds->credentials);
	// if (ret != GNUTLS_E_SUCCESS) {
	// 	kr_log_error(DOQ, "Failed to allocate TLS credentials (%d) %s\n",
	// 			ret, gnutls_strerror(ret));
	// 	goto failed;
	// }


	// NOTE: Taken from tls-proxy.c/96, we might need to use this
	// to enforce the use of tls1.3 (tls1.3 compat mode might be problematic)
	// knot-dns has experienced issues with it in the past
	//
	// static const char * const tlsv13_priorities =
	// 	"NORMAL:" /* GnuTLS defaults */
	// 	"-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2:+VERS-TLS1.3:" /* TLS 1.3 only */
	// 	"-VERS-SSL3.0:-ARCFOUR-128:-COMP-ALL:+COMP-NULL";

	int ret = gnutls_priority_init2(&new_table->priority, NULL, NULL, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		free(new_table);
		return NULL;
	}

	new_table->expiry_heap = malloc(sizeof(struct heap));
	if (new_table->expiry_heap == NULL
		|| !heap_init(new_table->expiry_heap, cmp_expiry_heap_nodes, 0)) {
		gnutls_priority_deinit(new_table->priority);
		free(new_table->expiry_heap);
		free(new_table);
		kr_log_error(DOQ, "Expiry heap malloc in kr_quic_table_new_failed\n");
		return NULL;
	}

	new_table->creds = creds;

	new_table->hash_secret[0] = dnssec_random_uint64_t();
	new_table->hash_secret[1] = dnssec_random_uint64_t();
	new_table->hash_secret[2] = dnssec_random_uint64_t();
	new_table->hash_secret[3] = dnssec_random_uint64_t();

	return new_table;
}

static int pl_quic_sess_init(struct session2 *session, void *sess_data, void *param)
{
	pl_quic_sess_data_t *quic = sess_data;
	session->secure = true;
	queue_init(quic->wrap_queue);
	queue_init(quic->unwrap_queue);

	if (!the_network->tls_credentials) {
		kr_log_info(DOQ, "tls credentials were not present at the start of DoQ iteration\n");
		the_network->tls_credentials = tls_get_ephemeral_credentials();
		if (!the_network->tls_credentials) {
			kr_log_error(TLS, "X.509 credentials are missing, and ephemeral credentials failed; no TLS\n");
			return kr_error(EINVAL);
		}

		kr_log_info(TLS, "Using ephemeral TLS credentials\n");
	}

	struct tls_credentials *creds = the_network->tls_credentials;
	kr_require(creds->credentials != NULL);

	if (!quic->conn_table) {
		// 9000/4.6: only streams with a stream ID less than
		// (max_streams * 4 + first_stream_id_of_type) can be opened
		// bufsizes -> magic nums from knot (see: libknot/.../quic-requestor.c)
		quic->conn_table = kr_quic_table_new(
			1024, 4096, 4096, NGTCP2_MAX_UDP_PAYLOAD_SIZE, creds);

		if (!quic->conn_table) {
			kr_log_error(DOQ, "Failed to create QUIC connection table\n");
			return kr_error(ENOMEM);
		}

		kr_require(quic->conn_table);

		quic->conn_count = 0;
	}

	return 0;
}

void kr_quic_cleanup(kr_quic_conn_t *conns[], size_t n_conns)
{
	for (size_t i = 0; i < n_conns; i++) {
		if (conns[i] != NULL && conns[i]->conn == NULL) {
			free(conns[i]);
			for (size_t j = i + 1; j < n_conns; j++) {
				if (conns[j] == conns[i]) {
					conns[j] = NULL;
				}
			}
		}
	}
}

void kr_quic_table_free(kr_quic_table_t *table)
{
	if (table != NULL) {
		while (!EMPTY_HEAP(table->expiry_heap)) {
			kr_quic_conn_t *c = *(kr_quic_conn_t **)HHEAD(table->expiry_heap);
			kr_quic_table_rem(c, table);
			kr_quic_cleanup(&c, 1);
		}
		assert(table->usage == 0);
		assert(table->pointers == 0);
		assert(table->ibufs_size == 0);
		assert(table->obufs_size == 0);

		gnutls_priority_deinit(table->priority);
		heap_deinit(table->expiry_heap);
		free(table->expiry_heap);
		free(table);
	}
}

static int pl_quic_sess_deinit(struct session2 *session, void *data)
{
	pl_quic_sess_data_t *quic = data;
	queue_deinit(quic->unwrap_queue);
	queue_deinit(quic->wrap_queue);
	// heap_deinit(quic->conn_table->expiry_heap);
	kr_quic_table_free(quic->conn_table);

	return kr_ok();
}

static int pl_quic_client_init(struct session2 *session,
			       pl_quic_sess_data_t *quic,
			       tls_client_param_t *param)
{
	// knot_quic_conn_t *cl_conn = NULL;
	//
	// knot_quic_conn_t *out_conn;
	//
	// // calls conn new
	// int ret = knot_quic_client((knot_quic_table_t *)quic->conn_table,
	// 			   (struct sockaddr_in6 *)session->comm_storage.dst_addr,
	// 			   (struct sockaddr_in6 *)session->comm_storage.comm_addr,
	// 			   NULL, /* server_name - I do not see the point for this arg */
	// 			   &out_conn);
	// if (ret == KNOT_EOK) {
	// 	// kr_log_warning(DOQ, "Failed to create quic client");
	// 	return -1;
	// }

	return kr_ok();
}

static uint64_t cid2hash(const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	SIPHASH_CTX ctx;
	kr_require(table->hash_secret != NULL);
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)(table->hash_secret));
	SipHash24_Update(&ctx, cid->data, MIN(cid->datalen, 8));
	uint64_t ret = SipHash24_End(&ctx);
	return ret;
}

kr_quic_cid_t **kr_quic_table_lookup2(const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	kr_quic_cid_t **res = table->conns + (hash % table->size);
	while (*res != NULL && !ngtcp2_cid_eq(cid, (const ngtcp2_cid *)(*res)->cid_placeholder)) {
		res = &(*res)->next;
	}
	return res;
}

kr_quic_conn_t *kr_quic_table_lookup(const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	kr_quic_cid_t **pcid = kr_quic_table_lookup2(cid, table);
	assert(pcid != NULL);
	return *pcid == NULL ? NULL : (*pcid)->conn;
}

bool kr_quic_require_retry(kr_quic_table_t *table)
{
	(void)table;
	return false;
}

static void kr_conn_heap_reschedule(kr_quic_conn_t *conn, kr_quic_table_t *table)
{
	heap_replace(table->expiry_heap, heap_find(table->expiry_heap, (heap_val_t *)conn), (heap_val_t *)conn);
}

static void kr_quic_conn_mark_used(kr_quic_conn_t *conn, kr_quic_table_t *table)
{
	conn->next_expiry = ngtcp2_conn_get_expiry(conn->conn);
	kr_conn_heap_reschedule(conn, table);
}

static int kr_quic_set_addrs(struct protolayer_iter_ctx *ctx, ngtcp2_path *path)
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

	return kr_ok();
}

static int quic_init_server_conn(kr_quic_table_t *table,
		struct protolayer_iter_ctx *ctx,
		uint64_t idle_timeout,
		ngtcp2_cid *scid, ngtcp2_cid *dcid, ngtcp2_version_cid decoded_cids,
		const uint8_t *payload, size_t payload_len,
		kr_quic_conn_t **out_conn)
{
	if (!table || !ctx|| !out_conn || !scid || !dcid) {
		kr_log_error(DOQ, "conn params were null\n");
		return kr_error(EINVAL);
	}

	int ret = EXIT_FAILURE;
	ngtcp2_cid odcid = { 0 };

	uint64_t now = quic_timestamp(); // the timestamps needs to be collected AFTER the check for blocked conn
	ngtcp2_path path;
	kr_quic_set_addrs(ctx, &path);

	if ((*out_conn) == NULL) {
		ngtcp2_pkt_hd header = { 0 };
		ret = ngtcp2_accept(&header,
				payload,
				payload_len);

		if (ret == NGTCP2_ERR_RETRY) {
			ret = -QUIC_SEND_RETRY;
			goto finish;
		} else if (ret != NGTCP2_NO_ERROR) {
			goto finish;
		} else if (ret != 0 || !payload) {
			kr_log_error(DOQ, "ngtcp2_accept failed: (%d) %s\n",
					ret, ngtcp2_strerror(ret));
			goto finish;
		}

		if (header.tokenlen == 0 && kr_quic_require_retry(table)) {
			ret = -QUIC_SEND_RETRY;
			goto finish;
		}

		if (header.tokenlen > 0) {
			if (header.token[0] == NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY) {
				ret = ngtcp2_crypto_verify_retry_token(
					&odcid, header.token, header.tokenlen,
					(const uint8_t *)table->hash_secret,
					sizeof(table->hash_secret), header.version,
					// (const struct sockaddr *)reply->ip_rem,
					path.remote.addr,
					path.remote.addrlen,
					dcid, idle_timeout, now // NOTE setting retry token validity to idle_timeout for simplicity
				);
			} else {
				ret = ngtcp2_crypto_verify_regular_token(
					header.token, header.tokenlen,
					(const uint8_t *)table->hash_secret,
					sizeof(table->hash_secret),
					// (const struct sockaddr *)reply->ip_rem,
					path.remote.addr,
					path.remote.addrlen,
					QUIC_REGULAR_TOKEN_TIMEOUT, now
				);
			}

			if (ret != 0)
				goto finish;

		} else {
			// ngtcp2_cid_init(&odcid, dcid->data, dcid->datalen);
			memcpy(&odcid, dcid, sizeof(odcid));
			kr_assert(ngtcp2_cid_eq(&odcid, dcid));
		}

		// server chooses his CID to his liking
		if (!init_unique_cid(dcid, 0, table)) {
			kr_log_error(DOQ, "Failed to initialize unique cid (servers choice)\n");
			ret = KNOT_ERROR;
			goto finish;
		}

		*out_conn= kr_quic_table_add(NULL, dcid, table);
		if (*out_conn == NULL) {
			kr_log_error(DOQ, "Failed to create new connection\n");
			ret = kr_error(ENOMEM);
			goto finish;
		}

		// (*out_conn)->dcid = dcid;
		// (*out_conn)->scid = scid;

		ret = conn_new_handler(&(*out_conn)->conn, &path,
				&header.scid, dcid, &header.dcid,
				decoded_cids.version, now, idle_timeout,
				*out_conn, true, header.tokenlen > 0);

		if (ret >= 0) {
			ret = tls_init_conn_session(*out_conn, true);
		} else {
			kr_quic_table_rem(*out_conn, table);
			// *out_conn = conn; // TODO: Implement a cleanup
					  // orig:{we need knot_quic_cleanup()
					  // by the caller afterwards}
			kr_log_error(DOQ, "Failed to create new server connection\n");
			goto finish;
		}
	} else {
		// should not happen
		kr_log_info(DOQ, "Called quic_init_server_conn with NON NULL out_conn");
		return kr_error(EINVAL);
	}

	return kr_ok();

finish:
	// WARNING: This looks like it is here for thread return values,
	// therefore useless for us
	// reply->handle_ret = ret;
	return ret;
}

// void handle_quic_streams(kr_quic_conn_t *conn, knotd_qdata_params_t *params,
//                          kr_layer_t *layer)
// {
// 	uint8_t ans_buf[KNOT_WIRE_MAX_PKTSIZE];
//
// 	params_update_quic(params, conn);
//
// 	int64_t stream_id;
// 	kr_quic_stream_t *stream;
// 	while (conn != NULL && (stream = kr_quic_stream_get_process(conn, &stream_id)) != NULL) {
// 		assert(stream->inbufs != NULL);
// 		assert(stream->inbufs->n_inbufs > 0);
// 		struct iovec *inbufs = stream->inbufs->inbufs;
// 		params_update_quic_stream(params, stream_id);
// 		// NOTE: only the first msg in the stream is used, the rest is dropped.
// 		handle_quic_stream(conn, stream_id, &inbufs[0], layer, params,
// 		                   ans_buf, sizeof(ans_buf));
// 		while (stream->inbufs != NULL) {
// 			knot_tcp_inbufs_upd_res_t *tofree = stream->inbufs;
// 			stream->inbufs = tofree->next;
// 			free(tofree);
// 		}
// 	}
// }

/**
 */
static int handle_packet(struct pl_quic_sess_data *quic,
		struct protolayer_iter_ctx *pkt_ctx,
		const uint8_t *pkt, size_t pktlen, ngtcp2_cid *dcid,
		struct kr_quic_conn **out_conn)
{
	kr_quic_conn_t *qconn = NULL;

	// Initial comm processing
	ngtcp2_version_cid decoded_cids = { 0 };
	ngtcp2_cid scid = { 0 }/*, dcid = { 0 } , odcid = { 0 } */;

	// FIXME: duplicate read, reread in quic_init_server_conn (accept)
	int ret = ngtcp2_pkt_decode_version_cid(&decoded_cids, pkt,
			pktlen, SERVER_DEFAULT_SCIDLEN);

	uint32_t supported_quic[1] = { NGTCP2_PROTO_VER_V1 };
	if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
		// FIXME: This will be broken by trimming the pkt below
		ngtcp2_pkt_write_version_negotiation(
			wire_buf_free_space(pkt_ctx->payload.wire_buf),
			wire_buf_free_space_length(pkt_ctx->payload.wire_buf),
			random(),
			// FIXME: Maybe switch
			decoded_cids.scid,
			decoded_cids.scidlen,
			decoded_cids.dcid,
			decoded_cids.dcidlen,
			supported_quic,
			sizeof(supported_quic) / sizeof(*supported_quic));

		ret = -QUIC_SEND_VERSION_NEGOTIATION;
		return PROTOLAYER_ITER_CB_RESULT_MAGIC;
		// goto finish;
	} else if (ret != NGTCP2_NO_ERROR) {
		kr_log_warning(DOQ, "Could not decode pkt header: (%d) %s \n",
				ret, ngtcp2_strerror(ret));

		return -1;
		// goto finish;
	}

	ngtcp2_cid_init(dcid, decoded_cids.dcid, decoded_cids.dcidlen);
	ngtcp2_cid_init(&scid, decoded_cids.scid, decoded_cids.scidlen);

	qconn = kr_quic_table_lookup(dcid, quic->conn_table);

	if (!qconn) {
		if ((ret = quic_init_server_conn(quic->conn_table, pkt_ctx,
				 UINT64_MAX - 1, &scid, dcid, decoded_cids,
				 pkt, pktlen, &qconn)) != kr_ok()) {
			return ret;
		}

		// if ((ret = wire_buf_trim(pkt_ctx->payload.wire_buf, pktlen)) != 0) {
		// 	kr_log_error(DOQ, "wirebuf failed to trim: %s (%d)\n",
		// 			kr_strerror(ret), ret);
		// 	return kr_error(ret);
		// }
		//
		// kr_log_info(DOQ, "trimmed %zu sum: %zu\n", pktlen, sum);

		/* Should not happen, if it did we certainly cannot
		 * continue in the communication
		 * Perhaps kr_require is too strong, this situation
		 * shouldn't corelate with kresd run.
		 * TODO: switch to condition and failed resolution */
		kr_require(qconn);
		// continue;
	}

	*out_conn = qconn;

	uint64_t now = quic_timestamp();
	const ngtcp2_path *path = ngtcp2_conn_get_path(qconn->conn);
	ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };

	ret = ngtcp2_conn_read_pkt(qconn->conn,
			path,
			&pi,
			wire_buf_data(pkt_ctx->payload.wire_buf),
			wire_buf_data_length(pkt_ctx->payload.wire_buf),
			now);

	if (ret == NGTCP2_ERR_DRAINING) { // doq received CONNECTION_CLOSE from the counterpart
		kr_quic_table_rem(qconn, quic->conn_table);
		ret = KNOT_EOK;
		return ret;

	} else if (ngtcp2_err_is_fatal(ret)) { // connection doomed
		kr_log_error(DOQ, "fatal error in ngtcp2_conn_read_pkt: %s (%d)", ngtcp2_strerror(ret), ret);
		if (ret == NGTCP2_ERR_CALLBACK_FAILURE) {
			ret = KNOT_EBADCERTKEY;
		} else {
			ret = KNOT_ECONN;
		}

		kr_quic_table_rem(qconn, quic->conn_table);
		return ret;

	} else if (ret != NGTCP2_NO_ERROR) { // non-fatal error, discard packet
		kr_log_error(DOQ, "discarding recieved pkt: %s (%d)", ngtcp2_strerror(ret), ret);
		ret = KNOT_EOK;
		return ret;
	}

	ngtcp2_conn_handle_expiry(qconn->conn, now);

	if (wire_buf_trim(pkt_ctx->payload.wire_buf, wire_buf_data_length(pkt_ctx->payload.wire_buf))) {
		kr_log_error(DOQ, "Failed to trim wire_buf\n");
		return ret;
	}

	if (kr_fails_assert(wire_buf_data_length(pkt_ctx->payload.wire_buf) == 0)) {
		kr_log_error(DOQ, "read pkt should consume the entire packet\n");
		return -1; /* TODO errcode */
	}

	// pkt_ctx->comm->target = &dcid;

	// kr_quic_send(quic->conn_table, qconn, quic, ctx, QUIC_MAX_SEND_PER_RECV, 0);
	return kr_ok();
}

void __attribute__ ((noinline)) empty_call(void) { }

static enum protolayer_iter_cb_result pl_quic_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret;
	struct pl_quic_sess_data *quic = sess_data;
	kr_quic_conn_t *qconn = NULL;

	queue_push(quic->unwrap_queue, ctx);

	while (protolayer_queue_has_payload(&quic->unwrap_queue)) {
		struct protolayer_iter_ctx *pkt_ctx = queue_head(quic->unwrap_queue);

		queue_pop(quic->unwrap_queue);

		kr_assert(pkt_ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF);
		size_t pktlen = wire_buf_data_length(pkt_ctx->payload.wire_buf);
		const uint8_t *pkt = wire_buf_data(pkt_ctx->payload.wire_buf);
		ngtcp2_cid dcid = { 0 };

		ret = handle_packet(quic,
				/** FIXME */pkt_ctx,
				pkt, pktlen, &dcid, &qconn);
		if (ret != kr_ok()) {
			protolayer_break(ctx, ret);
		}

		/* TODO Verify this doesn't leak */
		pkt_ctx->comm->target = mm_calloc(&ctx->pool, sizeof(ngtcp2_cid), 1);
		/* TODO log failed allocation "iteration ctx ran out of memory" */
		kr_require(pkt_ctx->comm->target);
		memcpy(pkt_ctx->comm->target, &dcid, sizeof(ngtcp2_cid));

		if (qconn->stream_inprocess >= 0) {
			// This branch is only accessed once a stream has
			// finished receiving a query (stream_inprocess received FIN)
			// TODO: protolayer_continue with the query in the first finished stream
			empty_call();
			struct kr_quic_stream *stream = kr_quic_conn_get_stream(
				qconn, qconn->stream_inprocess, true
			);

			if (stream == NULL) {
				return KNOT_ENOENT;
			}

			pkt_ctx->payload.wire_buf = &stream->pers_inbuf;
			kr_log_info(DOQ, "Proceeding protolayer_continue in quic\n");
			return protolayer_continue(pkt_ctx);
		}

		// ctx->comm->target = pkt_ctx->comm->target;

		if (qconn->flags & KR_QUIC_CONN_HANDSHAKE_DONE) {
				// && qconn->flags & ) {
			// kr_log_info(DOQ, "Proceeding to next layer\n");
			kr_quic_send(quic->conn_table, qconn, quic, ctx, QUIC_MAX_SEND_PER_RECV, 0);
			// return protolayer_continue(pkt_ctx);
		} else {
			// proceed with nodata handshake process
			kr_quic_send(quic->conn_table, qconn, quic, ctx, QUIC_MAX_SEND_PER_RECV, 0);
		}
	}

	// return protolayer_break(ctx, 0);
	return protolayer_continue(ctx);
}

/* TODO perhaps also move to quic_stream */
static int send_stream(struct protolayer_iter_ctx *ctx,
                       kr_quic_conn_t *qconn, int64_t stream_id,
                       uint8_t *data, size_t len, bool fin, ngtcp2_ssize *sent,
		       )
{
	assert(stream_id >= 0 || (data == NULL && len == 0));

	while (stream_id >= 0 && !kr_quic_stream_exists(qconn, stream_id)) {
		int64_t opened = 0;
		kr_log_info(DOQ, "Openning bidirectional stream no: %zu\n",
				stream_id);

		int ret = ngtcp2_conn_open_bidi_stream(qconn->conn, &opened, NULL);
		if (ret != kr_ok()) {
			/** This should not happen */
			kr_log_info(DOQ, "remote endpoint isn't ready for streams: %s (%d)\n",
					ngtcp2_strerror(ret), ret);
			return ret;
		}
		assert((bool)(opened == stream_id) == kr_quic_stream_exists(qconn, stream_id));
	}

	uint32_t fl = ((stream_id >= 0 && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN :
	                                         NGTCP2_WRITE_STREAM_FLAG_NONE);
	ngtcp2_vec vec = { .base = data, .len = len };
	ngtcp2_pkt_info pi = { 0 };

	const ngtcp2_path *path = ngtcp2_conn_get_path(qconn->conn);

	ngtcp2_conn_info info = { 0 };
	ngtcp2_conn_get_conn_info(qconn->conn, &info);

	int nwrite = 0;
	nwrite = ngtcp2_conn_writev_stream(qconn->conn, path, &pi,
			wire_buf_free_space(ctx->payload.wire_buf),
			wire_buf_free_space_length(ctx->payload.wire_buf),
			sent, fl, stream_id, &vec,
			(stream_id >= 0 ? 1 : 0), quic_timestamp());

	/* TODO:
	 * This packet may contain frames other than STREAM frame. The
	 * packet might not contain STREAM frame if other frames
	 * occupy the packet. In that case, *pdatalen would
	 * be -1 if pdatalen is not NULL.
	 */
	// TODO: abstract error printing, likely shared across mane ngtcp2_ calls
	if (nwrite < 0) {
		switch (nwrite) {
			case NGTCP2_ERR_NOMEM:
				kr_log_error(DOQ, "write failed: %s (%d)",
						ngtcp2_strerror(nwrite), nwrite);
				// TODO terminal

			case NGTCP2_ERR_STREAM_NOT_FOUND:
				kr_log_error(DOQ, "write stream failed to find: %s (%d)\n",
						ngtcp2_strerror(nwrite), nwrite);
				// TODO terminal

			case NGTCP2_ERR_STREAM_SHUT_WR:
				kr_log_error(DOQ, "local write endpoint is shut or stream is beeing reset: %s (%d)\n",
						ngtcp2_strerror(nwrite), nwrite);
				// TODO attempt later once (if reset)

			case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
				kr_log_error(DOQ, "no more pkt numbers available: %s (%d)\n",
						ngtcp2_strerror(nwrite), nwrite);
				// TODO terminal or reset pktn

			case NGTCP2_ERR_CALLBACK_FAILURE:
				kr_log_error(DOQ, "user callback failed: %s (%d)\n",
						ngtcp2_strerror(nwrite), nwrite);
				// TODO attempt later

			case NGTCP2_ERR_INVALID_ARGUMENT:
				kr_log_error(DOQ, "The total length of stream data is too large: %s (%d)\n",
						ngtcp2_strerror(nwrite), nwrite);
				// TODO attempt differently

			case NGTCP2_ERR_STREAM_DATA_BLOCKED:
				kr_log_error(DOQ, "stream is blocked due to flow controll: %s (%d)\n",
						ngtcp2_strerror(nwrite), nwrite);
				// TODO attempt later

			 /* only when NGTCP2_WRITE_STREAM_FLAG_MORE (currently not used) */
			case NGTCP2_ERR_WRITE_MORE:
				kr_log_error(DOQ, "should not happen: %s (%d)\n",
						ngtcp2_strerror(nwrite), nwrite);
				kr_require(false);
			default:
				kr_log_error(DOQ, "unknown error in writev_stream: %s (%d)\n",
						ngtcp2_strerror(nwrite), nwrite);
				kr_require(false);
		}

	} else if (*sent >= 0) { /** FIXME */ }

	if (nwrite == 0) {
		return nwrite;
	}

	if (len) {
		/* FIXME this is horrible */
		if (wire_buf_trim(ctx->payload.wire_buf, len) != kr_ok()) {
			kr_log_error(DOQ, "Wrire buf failed to trim: %s (%d)\n",
					ngtcp2_strerror(nwrite), nwrite);
			return -1;
		}
	}

	if (wire_buf_consume(ctx->payload.wire_buf, nwrite) != kr_ok()) {
		kr_log_error(DOQ, "Wire_buf failed to consume: %s (%d)\n",
				ngtcp2_strerror(nwrite), nwrite);
		return nwrite;
	}

	/* case HS has not finished, we have to switch to wrap direction
	 * without proceeding to the resolve layer */
	if (nwrite || *sent) {
		// written++;
		int wrap_ret = session2_wrap_after(ctx->session,
				PROTOLAYER_TYPE_QUIC,
		// int wrap_ret = session2_wrap(ctx->session,

				ctx->payload,
				ctx->comm,
				// NULL,/*req*/
				ctx->finished_cb,
				ctx->finished_cb_baton);


		return 1;
	} else {
		kr_require(nwrite || *sent);
	}

	return 0;
}

// maybe rename kr_quic_respond?
int kr_quic_send(kr_quic_table_t *quic_table /* FIXME maybe unused */,
	kr_quic_conn_t *conn,
	/* kr_quic_reply_t *reply */void *sess_data,
	struct protolayer_iter_ctx *ctx,
	unsigned max_msgs, kr_quic_send_flag_t flags)
{
	pl_quic_sess_data_t *quic = (pl_quic_sess_data_t *)sess_data;

	if (quic_table == NULL || conn == NULL /* || reply == NULL */) {
		return kr_error(EINVAL);
	} else if ((conn->flags & KR_QUIC_CONN_BLOCKED) && !(flags & KR_QUIC_SEND_IGNORE_BLOCKED)) {
		return kr_error(EINVAL);
	// } else if (reply->handle_ret > 0) {
	// 	return send_special(quic_table, reply, conn);
	} else if (conn == NULL) {
		return kr_error(EINVAL);
	} else if (conn->conn == NULL) {
		return kr_ok();
	}

	if (!(conn->flags & KR_QUIC_CONN_HANDSHAKE_DONE)) {
		max_msgs = 1;
	}

	unsigned sent_msgs = 0, stream_msgs = 0, ignore_last = ((flags & KR_QUIC_SEND_IGNORE_LASTBYTE) ? 1 : 0);
	int ret = 1;

	/* KnotDNS stores data to be written into a replay in the unsent_obuf
	 * since this will be called from pl_quic_wrap, and I'll have the
	 * payload in the form of a iovec anyway, I can just change the
	 * conditionals a bit and call send_Stream with the payload iovec */
	for (int64_t si = 0; si < conn->streams_count && sent_msgs < max_msgs; /* NO INCREMENT */) {
		int64_t stream_id = 4 * (conn->first_stream_id + si);

		ngtcp2_ssize sent = 0;
		size_t uf = conn->streams[si].unsent_offset;
		kr_quic_obuf_t *uo = conn->streams[si].unsent_obuf;

		kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF);

		if (uo == NULL) {
			si++;
			// continue;
		}

		// bool fin = (((node_t *)uo->node.next)->next == NULL) && ignore_last == 0;
		// size_t len = 5534u; /* size of the following buffer */
		// uint8_t *data = /* alloc buffer */ NULL;
		// ret = quic_package_payload(quic_table, ctx->payload, sess_data,
		// 		NULL, stream_id, data, len, fin, &sent);

		// ret = send_stream(ctx, conn, stream_id,
		//                   (uint8_t *)uo->buf + uf, uo->len - uf - ignore_last,
		//                   0/* FIXME `fin` probably for client side "request sent" */,
		// 		  &sent);

		ret = send_stream(ctx, conn, stream_id,
				wire_buf_data(ctx->payload.wire_buf),
				wire_buf_data_length(ctx->payload.wire_buf),
				// ctx->req->answer->wire,
				// ctx->req->answer->size,
				0/* FIXME `fin` probably for client side "request sent" */,
				&sent);


		if (ret < 0) {
			return ret;
		}

		sent_msgs++;
		stream_msgs++;
		if (sent > 0 && ignore_last > 0) {
			sent++;
		}

		if (sent > 0) {
			// TODO
			// kr_quic_stream_mark_sent(conn, stream_id, sent);
		}

		if (stream_msgs >= max_msgs / conn->streams_count) {
			stream_msgs = 0;
			si++; // if this stream is sending too much, give chance to other streams
		}
	}

	while (ret == 1) {
		ngtcp2_ssize unused = 0;
		ret = send_stream(ctx, conn, -1, NULL, 0, false, &unused);
	}

	ngtcp2_conn_update_pkt_tx_time(conn->conn, quic_timestamp());
	return ret;
}

static enum protolayer_iter_cb_result pl_quic_wrap(
		void *sess_data, void *iter_data,
		struct protolayer_iter_ctx *ctx)
{
	pl_quic_sess_data_t *quic = sess_data;
	queue_push(quic->wrap_queue, ctx);
	ngtcp2_cid *dcid = ctx->comm_storage.target;

	while (protolayer_queue_has_payload(&quic->wrap_queue)) {
		struct protolayer_iter_ctx *data = queue_head(quic->wrap_queue);
		kr_log_info(DOQ, "queue_len: %zu\n", queue_len(quic->wrap_queue));

		queue_pop(quic->wrap_queue);
		if (!data || !data->comm || !data->comm->target) {
			kr_log_error(DOQ, "missing required transport information in wrap direction\n");
			kr_require(false);
			return protolayer_break(ctx, EINVAL);
		}

		kr_quic_conn_t *conn = kr_quic_table_lookup(dcid, quic->conn_table);
		if (!conn) {
			kr_log_warning(DOQ, "Missing associated connection\n");
			int ret = kr_quic_send(quic->conn_table,
					conn, sess_data, ctx, 1, 0);
			return protolayer_break(ctx, EINVAL /* TODO */);
			// return -1; // TODO
		}

		kr_quic_send(quic->conn_table,
				conn,
				sess_data,
				data,
				QUIC_MAX_SEND_PER_RECV,
				0 /* no flags */);

		kr_log_info(DOQ, "About to continue from quic_wrap: %s\n",
				protolayer_payload_name(data->payload.type));

		return protolayer_continue(data);
		// data->async_mode = true;
		// protolayer_async();
		// return protolayer_continue(data);
		// kr_log_info(DOQ, "protolayer_continue returned %d\n", ret);
		// return protolayer_async();
	}

	/* We had nothing to send TODO error*/
	return protolayer_break(ctx, kr_ok());
	// return protolayer_continue(ctx);
	// return protolayer_break(ctx, PROTOLAYER_RET_NORMAL);
}

static enum protolayer_event_cb_result pl_quic_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	kr_log_warning(DOQ, "IN event_unwrap\n");
	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_quic_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	kr_log_warning(DOQ, "IN event_wrap\n");
	return PROTOLAYER_EVENT_PROPAGATE;
}

static void pl_quic_request_init(struct session2 *session,
                                struct kr_request *req,
                                void *sess_data)
{
	kr_log_warning(DOQ, "IN request init\n");
	req->qsource.comm_flags.quic = true;
	struct pl_quic_sess_data *quic = sess_data;
	quic->req = req;
}

__attribute__((constructor))
static void quic_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_QUIC] = (struct protolayer_globals) {
		.sess_size = sizeof(struct pl_quic_sess_data),
		// .iter_size = sizeof(struct ),
		.wire_buf_overhead = MAX_QUIC_FRAME_SIZE,
		// .iter_init = pl_quic_iter_init,
		// .iter_deinit = pl_quic_iter_deinit
		.sess_init = pl_quic_sess_init,
		.sess_deinit = pl_quic_sess_deinit,
		.unwrap = pl_quic_unwrap,
		.wrap = pl_quic_wrap,
		.event_unwrap = pl_quic_event_unwrap,
		.event_wrap = pl_quic_event_wrap,
		.request_init = pl_quic_request_init,
	};
}
