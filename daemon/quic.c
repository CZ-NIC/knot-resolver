/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <bits/types/struct_iovec.h>
#include <gnutls/x509.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "lib/defines.h"
#include "lib/log.h"
#include "lib/resolve-impl.h"
#include "mempattern.h"
#include "session2.h"
#include "network.h"
#include "lib/resolve.h"
// #include "libknot/quic/quic.h"
#include "libdnssec/random.h"
#include <libknot/wire.h>
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

/* TODO discuss size */
#define OUTBUF_SIZE 131072

static uint64_t cid2hash(const ngtcp2_cid *cid, kr_quic_table_t *table);
kr_quic_conn_t *kr_quic_table_lookup(const ngtcp2_cid *cid, kr_quic_table_t *table);
kr_quic_cid_t **kr_quic_table_lookup2(const ngtcp2_cid *cid, kr_quic_table_t *table);
kr_quic_cid_t **kr_quic_table_insert(kr_quic_conn_t *conn, const ngtcp2_cid *cid,
                                    kr_quic_table_t *table);
static int pl_quic_client_init(struct session2 *session,
			       pl_quic_sess_data_t *quic,
			       tls_client_param_t *param);
int kr_quic_send(kr_quic_table_t *quic_table, struct kr_quic_conn *conn,
		struct protolayer_iter_ctx *ctx, int action,
		ngtcp2_version_cid *decoded_cids,
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
		if (init_random_cid(cid, len), cid->datalen == 0)
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

	/* FIXME magic numbers */
	conn->conn = ngconn;
	conn->quic_table = table;
	conn->stream_inprocess = -1;
	conn->qlog_fd = -1;
	wire_buf_init(&conn->unwrap_buf, 1200);

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

	int ret = kr_quic_stream_recv_data(qconn, stream_id, data, datalen,
			(flags & NGTCP2_STREAM_DATA_FLAG_FIN));

	return ret == KNOT_EOK ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
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

	wire_buf_deinit(&conn->unwrap_buf);
	gnutls_deinit(conn->tls_session);
	ngtcp2_conn_del(conn->conn);
	conn->conn = NULL;

	// free(conn);

	table->usage--;
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 uint8_t *token, size_t cidlen,
                                 void *user_data)
{
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
		 const uint8_t *data, size_t datalen, void *user_data)
{

	return ngtcp2_crypto_recv_crypto_data_cb(conn, encryption_level, offset, data,
		 datalen, user_data);
}

int do_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
		const ngtcp2_crypto_cipher_ctx *hp_ctx, const uint8_t *sample)
{
	if (ngtcp2_crypto_hp_mask(dest, hp, hp_ctx, sample) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	kr_log_debug(DOQ, "hp mask installed %s %d %s %d\n", dest, NGTCP2_HP_MASKLEN, sample, NGTCP2_HP_SAMPLELEN);

	return 0;
}

static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
	kr_log_info(DOQ, "remote endpoint has opened a stream: %ld\n", stream_id);
	return kr_ok();
}

static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
			 uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	struct kr_quic_conn *qconn = (struct kr_quic_conn *)user_data;
	assert(qconn->conn == conn);

	// NOTE possible error is stored in (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)

	bool keep = !ngtcp2_conn_is_server(conn);
	if (!keep) {
		kr_quic_conn_stream_free(qconn, stream_id);
	}
	return kr_ok();
}

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

	// Probablu set bu default, set NULL to disable qlog
	// if (qtable->qlog_dir != NULL) {
		// settings.qlog_write = user_printf;
	// }

	if (qtable->udp_payload_limit != 0) {
		settings.max_tx_udp_payload_size = qtable->udp_payload_limit;
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

	wire_buf_init(&quic->outbuf, OUTBUF_SIZE);

	// TODO set setings?

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

static void kr_conn_heap_reschedule(kr_quic_conn_t *conn, kr_quic_table_t *table)
{
	heap_replace(table->expiry_heap, heap_find(table->expiry_heap, (heap_val_t *)conn), (heap_val_t *)conn);
}

static void kr_quic_conn_mark_used(kr_quic_conn_t *conn, kr_quic_table_t *table)
{
	conn->next_expiry = ngtcp2_conn_get_expiry(conn->conn);
	kr_conn_heap_reschedule(conn, table);
}

bool kr_quic_conn_timeout(kr_quic_conn_t *conn, uint64_t *now)
{
	if (*now == 0)
		*now = quic_timestamp();

	return *now > ngtcp2_conn_get_expiry(conn->conn);
}

// TODO
// static void send_excessive_load(kr_quic_conn_t *conn, struct kr_quic_reply *reply,
// 		kr_quic_table_t *table)
// {
// 	if (reply != NULL) {
// 		reply->handle_ret = KR_QUIC_ERR_EXCESSIVE_LOAD;
// 		(void)kr_quic_send(table, conn, reply, 0, 0);
// 	}
// }
//
// void kr_quic_table_sweep(kr_quic_table_t *table, struct kr_quic_reply *sweep_reply,
// 		struct kr_sweep_stats *stats)
// {
// 	uint64_t now = 0;
// 	if (table == NULL || stats == NULL) {
// 		return;
// 	}
//
// 	while (!EMPTY_HEAP(table->expiry_heap)) {
// 		kr_quic_conn_t *c = *(kr_quic_conn_t **)HHEAD(table->expiry_heap);
// 		if ((c->flags & KNOT_QUIC_CONN_BLOCKED)) {
// 			break; // highly inprobable
// 		} else if (table->usage > table->max_conns) {
// 			// kr_sweep_stats_incr(stats, KNOT_SWEEP_CTR_LIMIT_CONN);
// 			send_excessive_load(c, sweep_reply, table);
// 			kr_quic_table_rem(c, table);
// 		} else if (table->obufs_size > table->obufs_max) {
// 			// kr_sweep_stats_incr(stats, KNOT_SWEEP_CTR_LIMIT_OBUF);
// 			send_excessive_load(c, sweep_reply, table);
// 			kr_quic_table_rem(c, table);
// 		} else if (table->ibufs_size > table->ibufs_max) {
// 			// kr_sweep_stats_incr(stats, KNOT_SWEEP_CTR_LIMIT_IBUF);
// 			send_excessive_load(c, sweep_reply, table);
// 			kr_quic_table_rem(c, table);
// 		} else if (quic_conn_timeout(c, &now)) {
// 			int ret = ngtcp2_conn_handle_expiry(c->conn, now);
// 			if (ret != NGTCP2_NO_ERROR) { // usually NGTCP2_ERR_IDLE_CLOSE or NGTCP2_ERR_HANDSHAKE_TIMEOUT
// 				// kr_sweep_stats_incr(stats, KNOT_SWEEP_CTR_TIMEOUT);
// 				kr_quic_table_rem(c, table);
// 			} else {
// 				if (sweep_reply != NULL) {
// 					sweep_reply->handle_ret = KNOT_EOK;
// 					(void)kr_quic_send(table, c, sweep_reply, 0, 0);
// 				}
// 				kr_quic_conn_mark_used(c, table);
// 			}
// 		}
// 		kr_quic_cleanup(&c, 1);
//
// 		if (*(kr_quic_conn_t **)HHEAD(table->expiry_heap) == c) { // HHEAD already handled, NOOP, avoid infinite loop
// 			break;
// 		}
// 	}
// }

void kr_quic_table_free(kr_quic_table_t *table)
{
	if (table != NULL) {
		while (!EMPTY_HEAP(table->expiry_heap)) {
			kr_quic_conn_t *c = *(kr_quic_conn_t **)HHEAD(table->expiry_heap);
			kr_quic_table_rem(c, table);
			kr_quic_cleanup(&c, 1);
			// free(c);
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
	kr_quic_table_free(quic->conn_table);
	wire_buf_deinit(&quic->outbuf);

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

	kr_require(*out_conn == NULL);

	ngtcp2_pkt_hd header = { 0 };
	ret = ngtcp2_accept(&header,
			payload,
			payload_len);
	if (ret != 0) {
		ret = -QUIC_SEND_STATELESS_RESET;
		goto finish;
	}

	// TODO This never happens (kr_quic_require_retry just returns false)
	// if (header.tokenlen == 0
	// 		&& kr_quic_require_retry(table) /* TBD */) {
	// 	ret = -QUIC_SEND_RETRY;
	// 	goto finish;
	// }

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
		ret = kr_error(-1);
		goto finish;
	}

	*out_conn = kr_quic_table_add(NULL, dcid, table);
	if (*out_conn == NULL) {
		kr_log_error(DOQ, "Failed to create new connection\n");
		ret = kr_error(ENOMEM);
		goto finish;
	}

	ret = conn_new_handler(&(*out_conn)->conn, &path,
			&header.scid, dcid, &header.dcid,
			decoded_cids.version, now, idle_timeout,
			*out_conn, true, header.tokenlen > 0);

	if (ret >= 0) {
		ret = tls_init_conn_session(*out_conn, true);
	} else {
		kr_quic_table_rem(*out_conn, table);
		// free(*out_conn);
		kr_log_error(DOQ, "Failed to create new server connection\n");
		goto finish;
	}

	return kr_ok();

finish:
	// WARNING: This looks like it is here for thread return values,
	// therefore useless for us
	// reply->handle_ret = ret;
	return ret;
}

static int handle_packet(struct pl_quic_sess_data *quic,
		struct protolayer_iter_ctx *ctx, const uint8_t *pkt,
		size_t pktlen, struct quic_target *target,
		ngtcp2_version_cid *dec_cids, struct kr_quic_conn **out_conn,
		int *action)
{
	*action = 0;
	kr_quic_conn_t *qconn = NULL;

	// Initial comm processing
	// ngtcp2_version_cid decoded_cids = { 0 };
	// FIXME: duplicate read, reread in quic_init_server_conn (accept)
	int ret = ngtcp2_pkt_decode_version_cid(dec_cids, pkt,
			pktlen, SERVER_DEFAULT_SCIDLEN);

	/* If Version Negotiation is required, this function
	 * returns NGTCP2_ERR_VERSION_NEGOTIATION.
	 * Unlike the other error cases, all fields of dest are assigned
	 * see https://nghttp2.org/ngtcp2/ngtcp2_pkt_decode_version_cid.html */
	if (ret != NGTCP2_NO_ERROR && ret != NGTCP2_ERR_VERSION_NEGOTIATION) {
		kr_log_warning(DOQ, "Could not decode pkt header: (%d) %s \n",
				ret, ngtcp2_strerror(ret));
		return kr_ok();
	}
	uint32_t supported_quic[1] = { NGTCP2_PROTO_VER_V1 };
	ngtcp2_cid_init(&target->dcid, dec_cids->dcid, dec_cids->dcidlen);
	ngtcp2_cid_init(&target->scid, dec_cids->scid, dec_cids->scidlen);
	if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
		*action = -QUIC_SEND_VERSION_NEGOTIATION;
		return kr_ok();
		// goto finish
	}

	qconn = kr_quic_table_lookup(&target->dcid, quic->conn_table);
	if (!qconn) {
		/* TODO react accordingly to errcodes from accept.
		 * not all errors are terminal nor are all quiet,
		 * see which case warrants the payload to be discarded
		 * (we have to avoid looping over one bad pkt indefinitelly) */
		if ((ret = quic_init_server_conn(quic->conn_table, ctx,
				 UINT64_MAX - 1, &target->scid, &target->dcid,
				 *dec_cids, pkt, pktlen, &qconn)) != kr_ok()) {
			return ret;
		}

		/* Should not happen, if it did we certainly cannot
		 * continue in the communication
		 * Perhaps kr_require is too strong, this situation
		 * shouldn't corelate with kresd run.
		 * TODO: switch to condition and failed resolution */
		kr_require(qconn);
		// continue;
	}

	uint64_t now = quic_timestamp();
	const ngtcp2_path *path = ngtcp2_conn_get_path(qconn->conn);
	ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };

	// while (ngtcp2_conn_read_pkt(qconn->conn, path, &pi, pkt, pktlen, now) == 0);
	ret = ngtcp2_conn_read_pkt(qconn->conn, path, &pi, pkt, pktlen, now);

	*out_conn = qconn;
	/* FIXME: inacurate error handling */
	if (ret == NGTCP2_ERR_DRAINING) { // doq received CONNECTION_CLOSE from the counterpart
		kr_quic_table_rem(qconn, quic->conn_table);
		wire_buf_reset(ctx->payload.wire_buf);
		*action = KR_QUIC_HANDLE_RET_CLOSE;
		free(*out_conn);
		return kr_ok();

	} else if (ngtcp2_err_is_fatal(ret)) { // connection doomed
		kr_log_error(DOQ, "fatal error in ngtcp2_conn_read_pkt: %s (%d)", ngtcp2_strerror(ret), ret);
		// if (ret == NGTCP2_ERR_CALLBACK_FAILURE) {
			// ret = kr_error(KNOT_EBADCERT);
		// } else {
		// 	ret = kr_error();
		// }
		kr_quic_table_rem(qconn, quic->conn_table);
		return ret;

	} else if (ret == NGTCP2_ERR_RETRY) {
		kr_log_info(DOQ, "server will perform address validation via Retry packet\n");
		*action = QUIC_SEND_RETRY;
		wire_buf_reset(ctx->payload.wire_buf);
		return kr_ok();

	} else if (ret != NGTCP2_NO_ERROR) { // non-fatal error, discard packet
		kr_log_error(DOQ, "discarding recieved pkt: %s (%d)", ngtcp2_strerror(ret), ret);
		ret = KNOT_EOK;
		return ret;
	}

	ngtcp2_conn_handle_expiry(qconn->conn, now);

	/* given the 0 return value the pkt has been processed */
	wire_buf_reset(ctx->payload.wire_buf);
	return kr_ok();
}

static int get_query(struct protolayer_iter_ctx *ctx,
		struct kr_quic_conn *qconn, struct quic_target *target)
{
	kr_require(wire_buf_data_length(&qconn->unwrap_buf) == 0);

	int64_t stream_id;
	struct kr_quic_stream *stream;
	stream = kr_quic_stream_get_process(qconn, &stream_id);

	/* no stream has finished payload (should not happen) */
	kr_require(stream);

	size_t to_write = wire_buf_data_length(&stream->pers_inbuf);
	ctx->payload = protolayer_payload_wire_buf(&stream->pers_inbuf,
			false);

	target->stream_id = stream_id;
	ctx->comm->target = target;

	if (to_write > wire_buf_free_space_length(&qconn->unwrap_buf)) {
		kr_log_error(DOQ, "unwrap buf is not big enough\n");
		return kr_error(ENOMEM);
	}

	memcpy(wire_buf_free_space(&qconn->unwrap_buf),
		wire_buf_data(&stream->pers_inbuf), to_write);
	wire_buf_consume(&qconn->unwrap_buf, to_write);
	wire_buf_trim(&stream->pers_inbuf, to_write);
	if (wire_buf_data_length(&stream->pers_inbuf) == 0) {
		wire_buf_deinit(&stream->pers_inbuf);
		memset(&stream->pers_inbuf, 0, sizeof(struct wire_buf));
	}

	return to_write;
}

static int collect_queries(struct protolayer_iter_ctx *ctx,
		struct kr_quic_conn *qconn, struct quic_target *target)
{
	kr_require(wire_buf_data_length(&qconn->unwrap_buf) == 0);
	size_t free_space = wire_buf_free_space_length(&qconn->unwrap_buf);
	uint16_t queries_agregated = 0;

	int64_t stream_id;
	struct kr_quic_stream *stream;
	while (qconn != NULL
		&& (stream = kr_quic_stream_get_process(qconn,
				&stream_id)) != NULL) {

		size_t to_write = wire_buf_data_length(&stream->pers_inbuf);
		ctx->payload = protolayer_payload_wire_buf(&stream->pers_inbuf,
				false);

		target->stream_id = stream_id;
		ctx->comm->target = target;

		kr_assert(to_write > 0);
		if (to_write > free_space) {
			kr_log_error(DOQ, "unwrap buf is not big enough\n");
			return kr_error(ENOMEM);
		}

		memcpy(wire_buf_free_space(&qconn->unwrap_buf),
			wire_buf_data(&stream->pers_inbuf), to_write);
		wire_buf_consume(&qconn->unwrap_buf, to_write);
		wire_buf_trim(&stream->pers_inbuf, to_write);
		if (wire_buf_data_length(&stream->pers_inbuf) == 0) {
			wire_buf_deinit(&stream->pers_inbuf);
			memset(&stream->pers_inbuf, 0, sizeof(struct wire_buf));
		}

		free_space -= to_write;
		++queries_agregated;
	}

	return queries_agregated;
}

static enum protolayer_iter_cb_result pl_quic_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret = kr_ok();
	kr_quic_conn_t *qconn = NULL;
	struct pl_quic_sess_data *quic = sess_data;

	queue_push(quic->unwrap_queue, ctx);

	/* TODO Verify this doesn't leak */
	struct quic_target *target = malloc(sizeof(struct quic_target));
	kr_require(target);

	while (protolayer_queue_has_payload(&quic->unwrap_queue)) {
		kr_assert(ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF);
		ngtcp2_version_cid dec_cids;
		int action;

		ret = handle_packet(quic,
				ctx,
				wire_buf_data(ctx->payload.wire_buf),
				wire_buf_data_length(ctx->payload.wire_buf),
				target, &dec_cids, &qconn, &action);
		/* not all fails should be quiet, some require a response from
		 * our side (kr_quic_send with given action) TODO! */
		if (ret != kr_ok()) {
			goto fail;
		}
		if (action == KR_QUIC_HANDLE_RET_CLOSE) {
			ret = kr_ok();
			goto fail;
		}

		if (qconn->stream_inprocess == -1) {
			kr_quic_send(quic->conn_table, qconn, ctx, action,
					&dec_cids, QUIC_MAX_SEND_PER_RECV, 0);
			ret = kr_ok();
			goto fail;
		}

		if (kr_fails_assert(queue_len(quic->unwrap_queue) == 1)) {
			ret = kr_error(EINVAL);
			goto fail;
		}

		/* WARNING: this has been moved */
		// struct protolayer_iter_ctx *ctx_head = queue_head(quic->unwrap_queue);
		// if (!kr_fails_assert(ctx == ctx_head)) {
		// 	protolayer_break(ctx, kr_error(EINVAL));
		// 	ctx = ctx_head;
		// }
	}

	struct protolayer_iter_ctx *ctx_head = queue_head(quic->unwrap_queue);
	if (!kr_fails_assert(ctx == ctx_head))
		queue_pop(quic->unwrap_queue);

	while (qconn->streams_pending) {
		if ((ret = get_query(ctx, qconn, target)) <= 0)
			goto fail;

		ctx->payload = protolayer_payload_wire_buf(&qconn->unwrap_buf,
				false);

		if (qconn->streams_pending == 0) {
			return protolayer_continue(ctx);
		}

		/* FIXME should we ignore the result? */
		session2_unwrap_after(ctx->session,
				PROTOLAYER_TYPE_QUIC,
				ctx->payload,
				ctx->comm,
				ctx->finished_cb,
				ctx->finished_cb_baton);
	}

	// if ((ret = collect_queries(ctx, qconn, target)) > 0) {
	// 	ctx->payload = protolayer_payload_wire_buf(&qconn->unwrap_buf,
	// 			false);
	// 	return protolayer_continue(ctx);
	// }

	free(target);
	return protolayer_break(ctx, ret);

fail:
	ctx_head = queue_head(quic->unwrap_queue);
	if (!kr_fails_assert(ctx == ctx_head))
		queue_pop(quic->unwrap_queue);

	free(target);
	return protolayer_break(ctx, ret);
}

/* TODO perhaps also move to quic_stream */
static int send_stream(struct protolayer_iter_ctx *ctx,
		// struct protolayer_payload *outwb,
		kr_quic_conn_t *qconn, int64_t stream_id,
		uint8_t *data, size_t len, bool fin, ngtcp2_ssize *sent)
{
	/* require empty wire_buf TODO maybe remove*/
	kr_require(wire_buf_data_length(ctx->payload.wire_buf) == 0);

	assert(stream_id >= 0 || (data == NULL && len == 0));

	while (stream_id >= 0 && !kr_quic_stream_exists(qconn, stream_id)) {
		int64_t opened = 0;
		kr_log_info(DOQ, "Openning bidirectional stream no: %zu\n",
				stream_id);

		int ret = ngtcp2_conn_open_bidi_stream(qconn->conn,
				&opened, NULL);
		if (ret != kr_ok()) {
			kr_log_warning(DOQ, "remote endpoint isn't ready for streams: %s (%d)\n",
					ngtcp2_strerror(ret), ret);
			return ret;
		}
		kr_require((bool)(opened == stream_id) == kr_quic_stream_exists(qconn, stream_id));
	}

	uint32_t fl = ((stream_id >= 0 && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN
					       : NGTCP2_WRITE_STREAM_FLAG_NONE);

	ngtcp2_vec vec = { .base = data, .len = len };
	ngtcp2_pkt_info pi = { 0 };

	const ngtcp2_path *path = ngtcp2_conn_get_path(qconn->conn);

	ngtcp2_conn_info info = { 0 };
	ngtcp2_conn_get_conn_info(qconn->conn, &info);
	int nwrite = ngtcp2_conn_writev_stream(qconn->conn, path, &pi,
			wire_buf_free_space(ctx->payload.wire_buf),
			wire_buf_free_space_length(ctx->payload.wire_buf),
			sent, fl, stream_id, &vec,
			(stream_id >= 0 ? 1 : 0), quic_timestamp());

	/* TODO:
	 * This packet may contain frames other than STREAM frame. The
	 * packet might not contain STREAM frame if other frames
	 * occupy the packet. In that case, *pdatalen would
	 * be -1 if pdatalen is not NULL. */
	// TODO: abstract error printing, likely shared across many ngtcp2_ calls
	if (nwrite < 0) {
		kr_log_error(DOQ, "writev_stream to %zu failed %s (%d)\n",
				stream_id, ngtcp2_strerror(nwrite), nwrite);
		if (len)
			return nwrite;

		goto exit;
	} else if (*sent >= 0) {
		/* TODO this data has to be kept untill acked */
		vec.len -= *sent;
	}

	if (wire_buf_consume(ctx->payload.wire_buf, nwrite) != kr_ok()) {
		kr_log_error(DOQ, "Wire_buf failed to consume: %s (%d)\n",
				ngtcp2_strerror(nwrite), nwrite);
		goto exit;
	}

	/* called from wrap, proceed to the next layer */
	if (len) {
		return protolayer_continue(ctx);
	}

	/* called from unwrap, respond with QUIC communication data */
	if (nwrite || *sent)  {
		int wrap_ret = session2_wrap_after(ctx->session,
				PROTOLAYER_TYPE_QUIC, ctx->payload, ctx->comm,
				ctx->finished_cb, ctx->finished_cb_baton);

		if (wrap_ret < 0) {
			nwrite = wrap_ret;
		}

	} else {
		// TODO?
	}

exit:
	// wire_buf_deinit(wb);
	// mm_free(&ctx->pool, wb);

	return len != 0 ? protolayer_break(ctx, nwrite) : nwrite;
}

/* Function for sending speciall packets, requires
 * a message (which special data are we to send: CONN_CLOSE, RESET, ...)
 * and a buffer to store the pkt in, for now ctx->payloay.wb
 * For now only kr_quic_send ever call send_special, though this might proove
 * to cause issues in situation where the connection has NOT been established
 * and we still would like to send data (i.e. we do not have decoded cids)
 * The only time we need to send_special without having at least the cids
 * is then the decode_v_cid fails with NGTCP2_ERR_VERSION_NEGOTIATION */
static int send_special(struct protolayer_iter_ctx *ctx,
		kr_quic_table_t *quic_table, int action,
		ngtcp2_version_cid *decoded_cids,
		struct kr_quic_conn *conn)
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
			rnd, decoded_cids->scid, decoded_cids->scidlen,
			decoded_cids->dcid, decoded_cids->dcidlen, supported_quic,
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
		init_random_cid(&new_dcid, 0);

		ret = ngtcp2_crypto_generate_retry_token(
			retry_token, (const uint8_t *)quic_table->hash_secret,
			sizeof(quic_table->hash_secret), decoded_cids->version,
			(const struct sockaddr *)remote.addr, remote.addrlen,
			&new_dcid, &target->dcid, now
		);

		if (ret >= 0) {
			ret = ngtcp2_crypto_write_retry(
				wire_buf_free_space(ctx->payload.wire_buf),
				wire_buf_free_space_length(ctx->payload.wire_buf),
				decoded_cids->version, &target->scid,
				&new_dcid, &target->dcid,
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
		if (wire_buf_consume(ctx->payload.wire_buf, ret) == kr_ok()) {
			int wrap_ret = session2_wrap_after(ctx->session,
					PROTOLAYER_TYPE_QUIC, ctx->payload, ctx->comm,
					ctx->finished_cb, ctx->finished_cb_baton);
			if (wrap_ret < 0) {
				ret = wrap_ret;
			}

		} else {
			kr_log_error(DOQ, "Wire_buf failed to consume: %s (%d)\n",
					ngtcp2_strerror(ret), ret);
			// goto exit;
		}
	}

	return ret;
}

int kr_quic_send(kr_quic_table_t *quic_table /* FIXME maybe unused */,
		struct kr_quic_conn *conn,
		// void *sess_data,
		struct protolayer_iter_ctx *ctx,
		int action,
		ngtcp2_version_cid *decoded_cids,
		unsigned max_msgs,
		kr_quic_send_flag_t flags)
{
	if (quic_table == NULL || conn == NULL /* || reply == NULL */) {
		return kr_error(EINVAL);
	} else if ((conn->flags & KR_QUIC_CONN_BLOCKED) && !(flags & KR_QUIC_SEND_IGNORE_BLOCKED)) {
		return kr_error(EINVAL);
	} else if (action != 0) {
		return send_special(ctx, quic_table, action, decoded_cids, conn);
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

	for (int64_t si = 0; si < conn->streams_count && sent_msgs < max_msgs; /* NO INCREMENT */) {
		int64_t stream_id = 4 * (conn->first_stream_id + si);

		ngtcp2_ssize sent = 0;
		size_t uf = conn->streams[si].unsent_offset;
		kr_quic_obuf_t *uo = conn->streams[si].unsent_obuf;
		if (uo == NULL) {
			si++;
			continue;
		}

		bool fin = (((node_t *)uo->node.next)->next == NULL) && ignore_last == 0;

		kr_log_info(DOQ, "About to SEND_STREAM fin: %d stream_id: %zu fsi: %zu streams_count: %d\n",
			   fin, stream_id, conn->first_stream_id, conn->streams_count);

		ret = send_stream(ctx, conn, stream_id, uo->buf + uf,
				  uo->len - uf - ignore_last, fin, &sent);

		/* FIXME: just an attempted hotfix
		 * ok this actually worked, but it shadows an underlying issue
		 * and leaks more than a decapitated elephant */
		if (ret == NGTCP2_ERR_STREAM_SHUT_WR) {
			// kr_quic_stream_mark_sent(conn, stream_id, sent);
			si++;
			continue;
		}

		if (ret < 0 || ret == PROTOLAYER_ITER_CB_RESULT_MAGIC) {
			return ret;
		}

		sent_msgs++;
		stream_msgs++;
		if (sent > 0 && ignore_last > 0) {
			sent++;
		}
		if (sent > 0) {
			kr_quic_stream_mark_sent(conn, stream_id, sent);
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

	// Might not be the correct place to call this
	ngtcp2_conn_update_pkt_tx_time(conn->conn, quic_timestamp());
	return sent_msgs;
}

/* For now we assume any iovec payload we get
 * will just be a single (the second iovec, first one holds size)
 * giant buffer. FIXME if proper iovec support ever comes. */
static enum protolayer_iter_cb_result pl_quic_wrap(
		void *sess_data, void *iter_data,
		struct protolayer_iter_ctx *ctx)
{
	int ret;
	pl_quic_sess_data_t *quic = sess_data;
	queue_push(quic->wrap_queue, ctx);
	struct quic_target *target = ctx->comm_storage.target;
	ngtcp2_cid *dcid = &target->dcid;
	uint64_t stream_id = target->stream_id;

	kr_log_info(DOQ, "Quic wrap prototype: %s\n",
			protolayer_payload_name(ctx->payload.type));

	while (protolayer_queue_has_payload(&quic->wrap_queue)) {
		struct protolayer_iter_ctx *data = queue_head(quic->wrap_queue);

		queue_pop(quic->wrap_queue);
		if (!data || !data->comm || !data->comm->target) {
			kr_log_error(DOQ, "missing required transport information in wrap direction\n");
			kr_require(false);
			return protolayer_break(ctx, kr_error(EINVAL));
		}

		kr_quic_conn_t *conn = kr_quic_table_lookup(dcid, quic->conn_table);
		if (!conn) {
			kr_log_warning(DOQ, "Missing associated connection\n");
			/* There is nothing we can do */
			return protolayer_break(ctx, EINVAL /* TODO */);
		}

		// TODO remove
		knot_pkt_t *ans = kr_request_ensure_answer(ctx->req);
		kr_require(ans != NULL);

		kr_require(data->payload.type == PROTOLAYER_PAYLOAD_IOVEC);
		kr_quic_stream_add_data(conn, stream_id,
				&data->payload);

		struct wire_buf *wb = mm_alloc(&ctx->pool, sizeof(*wb));
		char *buf = mm_alloc(&ctx->pool, 1200 /* FIXME this makes no sence */);
		kr_require(buf);
		*wb = (struct wire_buf){
			.buf = buf,
			.size = 1200 /* FIXME this makes no sence */
		};

		data->payload = protolayer_payload_wire_buf(wb, false);
		ret = kr_quic_send(quic->conn_table,
				conn,
				data,
				0,
				NULL,
				QUIC_MAX_SEND_PER_RECV,
				0 /* no flags */);
		if (ret <= 0)
			break;

		// if (ret == PROTOLAYER_ITER_CB_RESULT_MAGIC) {
		// 	free(ctx->comm_storage.target);
		// }
	}

	// FIXME: certainly not here, this leaks as is
	// free(ctx->comm_storage.target);
	// free(ctx->comm_storage.target);
	return ret;

	// return protolayer_continue(ctx);
	// return protolayer_break(ctx, kr_ok());
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
	// struct pl_quic_sess_data *quic = sess_data;
	// quic->req = req;

	// req->qsource.stream_id = session->comm_storage.target;
}

__attribute__((constructor))
static void quic_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_QUIC] = (struct protolayer_globals) {
		.sess_size = sizeof(struct pl_quic_sess_data),
		// .iter_size = sizeof(struct ),
		.wire_buf_overhead = MAX_QUIC_FRAME_SIZE,
		// .iter_init = pl_quic_iter_init,
		// .iter_deinit = pl_quic_iter_deinit,
		.sess_init = pl_quic_sess_init,
		.sess_deinit = pl_quic_sess_deinit,
		.unwrap = pl_quic_unwrap,
		.wrap = pl_quic_wrap,
		.event_unwrap = pl_quic_event_unwrap,
		.event_wrap = pl_quic_event_wrap,
		.request_init = pl_quic_request_init,
	};
}
