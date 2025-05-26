/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "quic.h"
#include <gnutls/x509.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "lib/log.h"
#include "session2.h"
#include "network.h"
#include "lib/resolve.h"
// #include "libknot/quic/quic.h"
#include "libdnssec/random.h"
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

#include <worker.h>


static uint64_t cid2hash(const ngtcp2_cid *cid, kr_quic_table_t *table);
kr_quic_conn_t *kr_quic_table_lookup(const ngtcp2_cid *cid, kr_quic_table_t *table);
kr_quic_cid_t **kr_quic_table_lookup2(const ngtcp2_cid *cid, kr_quic_table_t *table);
kr_quic_cid_t **kr_quic_table_insert(kr_quic_conn_t *conn, const ngtcp2_cid *cid,
                                    kr_quic_table_t *table);
kr_quic_stream_t *kr_quic_conn_get_stream(kr_quic_conn_t *conn,
					  int64_t stream_id, bool create);
static int pl_quic_client_init(struct session2 *session,
			       pl_quic_sess_data_t *quic,
			       tls_client_param_t *param);

uint64_t quic_timestamp(void);

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

// int kr_quic_stream_recv_data(kr_quic_conn_t *conn, int64_t stream_id,
//                                const uint8_t *data, size_t len, bool fin)
// {
// 	if (len == 0 || conn == NULL || data == NULL) {
// 		return KNOT_EINVAL;
// 	}
//
// 	kr_quic_stream_t *stream = kr_quic_conn_get_stream(conn, stream_id, true);
// 	if (stream == NULL) {
// 		return KNOT_ENOENT;
// 	}
//
// 	struct iovec in = { (void *)data, len };
// 	ssize_t prev_ibufs_size = conn->ibufs_size;
// 	int ret = kr_tcp_inbufs_upd(&stream->inbuf, in, true,
// 	                              &stream->inbufs, &conn->ibufs_size);
// 	conn->quic_table->ibufs_size += (ssize_t)conn->ibufs_size - prev_ibufs_size;
// 	if (ret != KNOT_EOK) {
// 		return ret;
// 	}
//
// 	if (fin && stream->inbufs == NULL) {
// 		return KNOT_ESEMCHECK;
// 	}
//
// 	if (stream->inbufs != NULL) {
// 		stream_inprocess(conn, stream);
// 	}
// 	return KNOT_EOK;
// }


static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                            int64_t stream_id, uint64_t offset,
                            const uint8_t *data, size_t datalen,
                            void *user_data, void *stream_user_data)
{
	(void)(stream_user_data); // always NULL
	(void)(offset); // QUIC shall ensure that data arrive in-order

	kr_quic_conn_t *ctx = (kr_quic_conn_t *)user_data;
	assert(ctx->conn == conn);

	return 0;
	// int ret = kr_quic_stream_recv_data(ctx, stream_id, data, datalen,
	//                                      (flags & NGTCP2_STREAM_DATA_FLAG_FIN));
	//
	// // FIXME: remove knot macros vvv
	// return ret == KNOT_EOK ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}


kr_quic_stream_t *kr_quic_conn_get_stream(kr_quic_conn_t *conn,
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
		kr_quic_stream_t *new_streams;

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
			new_streams = realloc(conn->streams, new_streams_count * sizeof(*new_streams));
			if (new_streams == NULL) {
				return NULL;
			}
		}

		for (kr_quic_stream_t *si = new_streams;
		     si < new_streams + conn->streams_count; si++) {
			if (si->obufs_size == 0) {
				init_list(&si->outbufs);
			} else {
				fix_list(&si->outbufs);
			}
		}

		for (kr_quic_stream_t *si = new_streams + conn->streams_count;
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

void kr_quic_stream_ack_data(kr_quic_conn_t *conn, int64_t stream_id,
                               size_t end_acked, bool keep_stream)
{
	kr_quic_stream_t *s = kr_quic_conn_get_stream(conn, stream_id, false);
	if (s == NULL) {
		return;
	}

	list_t *obs = &s->outbufs;

	kr_quic_obuf_t *first;
	while (!EMPTY_LIST(*obs) && end_acked >= (first = HEAD(*obs))->len + s->first_offset) {
		rem_node((node_t *)first);
		s->obufs_size -= first->len;
		conn->obufs_size -= first->len;
		conn->quic_table->obufs_size -= first->len;
		s->first_offset += first->len;
		free(first);
		if (s->unsent_obuf == first) {
			s->unsent_obuf = EMPTY_LIST(*obs) ? NULL : HEAD(*obs);
			s->unsent_offset = 0;
		}
	}

	if (EMPTY_LIST(*obs) && !keep_stream) {
		// stream_outprocess(conn, s);
		memset(s, 0, sizeof(*s));
		init_list(&s->outbufs);
		while (s = &conn->streams[0], s->inbuf.iov_len == 0 && s->inbufs == NULL && s->obufs_size == 0) {
			assert(conn->streams_count > 0);
			conn->streams_count--;

			if (conn->streams_count == 0) {
				free(conn->streams);
				conn->streams = 0;
				conn->first_stream_id = 0;
				break;
			} else {
				conn->first_stream_id++;
				conn->stream_inprocess--;
				memmove(s, s + 1, sizeof(*s) * conn->streams_count);
				// possible realloc to shrink allocated space, but probably useless
				for (kr_quic_stream_t *si = s;  si < s + conn->streams_count; si++) {
					if (si->obufs_size == 0) {
						init_list(&si->outbufs);
					} else {
						fix_list(&si->outbufs);
					}
				}
			}
		}
	}
}

void kr_quic_conn_stream_free(kr_quic_conn_t *conn, int64_t stream_id)
{
	kr_quic_stream_t *s = kr_quic_conn_get_stream(conn, stream_id, false);
	if (s != NULL && s->inbuf.iov_len > 0) {
		free(s->inbuf.iov_base);
		conn->ibufs_size -= buffer_alloc_size(s->inbuf.iov_len);
		conn->quic_table->ibufs_size -= buffer_alloc_size(s->inbuf.iov_len);
		memset(&s->inbuf, 0, sizeof(s->inbuf));
	}

	while (s != NULL && s->inbufs != NULL) {
		void *tofree = s->inbufs;
		s->inbufs = s->inbufs->next;
		free(tofree);
	}

	kr_quic_stream_ack_data(conn, stream_id, SIZE_MAX, false);
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
	kr_quic_conn_t *ctx = (kr_quic_conn_t *)user_data;
	assert(ctx->conn == conn);

	if (!init_unique_cid(cid, cidlen, ctx->quic_table))
		return NGTCP2_ERR_CALLBACK_FAILURE;

	kr_quic_cid_t **addto = kr_quic_table_insert(ctx, cid, ctx->quic_table);
	(void)addto;

	if (token != NULL &&
	    ngtcp2_crypto_generate_stateless_reset_token(
	            token, (uint8_t *)ctx->quic_table->hash_secret,
	            sizeof(ctx->quic_table->hash_secret), cid) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int handshake_confirmed_cb(ngtcp2_conn *conn, pl_quic_sess_data_t *ctx)
{
	(void)conn;
	kr_log_info(DOQ, "Handshake confirmed\n");
	ctx->state = CONNECTED;
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
		// return kr_tls_pin_check(ctx->tls_session, ctx->quic_table->creds)
		//        == kr_EOK ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
		return NGTCP2_ERR_CALLBACK_FAILURE;
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

static int recv_tx_key_conf_cb(struct ngtcp2_conn *c, enum ngtcp2_encryption_level el, void* _undef)
{
	kr_log_info(DOQ, "TX KEY HAS BEEN INSTALLED!\n");
	/*
	 * Here we can now begin trasmiting non-confidential data
	 * all sensitive data SHOULD be transfered after the handshake
	 * completes (after it really gets authenticated)
	 */
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

static int conn_new_server(ngtcp2_conn **pconn, const ngtcp2_path *path,
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
		.handshake_completed = handshake_confirmed_cb, // handshake_completed_cb - OPTIONAL
		// NULL, // recv_version_negotiation not needed on server, nor kxdpgun - OPTIONAL
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		// .recv_stream_data = kr_recv_stream_data_cb // recv_stream_data, TODO? - OPTIONAL
		// NULL, // acked_stream_data_offset_cb, TODO - OPTIONAL
		// NULL, // stream_opened - OPTIONAL
		// NULL, // stream_closed, TODO - OPTIONAL
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
		// NULL, // handshake_confirmed - OPTIONAL
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
	// settings.no_pmtud = true;

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);

	/** This informs peer that active migration might not be available.
	 * Peer might still attempt to migrate. see RFC 9000/5.2.3 */
	params.disable_active_migration = true;

	/** There is no use for unidirectional streams for us */
	params.initial_max_streams_uni = 0;
	params.initial_max_streams_bidi = 1024;
	params.initial_max_stream_data_bidi_local = NGTCP2_MAX_VARINT;
	params.initial_max_stream_data_bidi_remote = 102400;
	params.initial_max_data = NGTCP2_MAX_VARINT;

	params.max_idle_timeout = idle_timeout_ns;
	params.stateless_reset_token_present = 1;
	params.active_connection_id_limit = 7;
	if (odcid != NULL) {
		params.original_dcid = *odcid;
		params.original_dcid_present = true;
	} else {
		kr_log_error(DOQ, "odcid is required for server initialization\n");
		/** TODO rather return */
		kr_require(false);
	}

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
		// 		&callbacks, &settings, &params, NULL, qconn);
		return ngtcp2_conn_server_new(pconn, scid, dcid, path, version, &callbacks,
		                              &settings, &params, NULL, qconn);
	} else {
		// NOTE: check scid and dcid if not working
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

		// const char *alpn = quic ? "\x03""doq" : "\x03""dot";
		// const gnutls_datum_t alpn_datum = { (void *)&alpn[1], alpn[0] };
		// gnutls_alpn_set_protocols(*session, &alpn_datum, 1, GNUTLS_ALPN_MANDATORY);
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

	return ret;// == GNUTLS_E_SUCCESS ? KNOT_EOK : KNOT_ERROR;
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

		quic->conn_count = 0;
	}

	return 0;

	// if (session->outgoing)
	// 	return pl_quic_client_init(session, quic, param);
	// else
	// 	return pl_quic_server_init(session, quic, param);
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
	heap_deinit(quic->conn_table->expiry_heap);
	kr_quic_table_free(data);
}

static int pl_quic_client_init(struct session2 *session,
			       pl_quic_sess_data_t *quic,
			       tls_client_param_t *param)
{
	kr_log_warning(DOQ, "In client init!\n");

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

				kr_log_error(DOQ, "Result of crypro_verift_regular_token: %d %s\n",
						ret, ngtcp2_strerror(ret));
			}

			if (ret != 0)
				goto finish;

		} else {
			// ngtcp2_cid_init(&odcid, dcid->data, dcid->datalen);
			// kr_log_info(DOQ, "\nCoppied CIDs: %s  =  %s\n", odcid.data, dcid->data);
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
			kr_log_error(DOQ, "Failed to create new conn\n");
			ret = kr_error(ENOMEM);
			goto finish;
		}

		kr_require(kr_quic_table_lookup(dcid, table));

		ret = conn_new_server(&(*out_conn)->conn, &path,
				&header.scid, dcid, &header.dcid,
				decoded_cids.version, now, idle_timeout,
				*out_conn, true, header.tokenlen > 0);

		// ret = conn_new_server(&(*out_conn)->conn, &path, scid, dcid, &odcid,
		// 		decoded_cids.version, now, idle_timeout,
		// 		*out_conn, true, header.tokenlen > 0);

		kr_log_info(DOQ, "Result of conn_new_server: %d\n", ret);

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
	}

	// Knot-resolver currently doesn't support RFC 3168
	ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT };

	ret = ngtcp2_conn_read_pkt((*out_conn)->conn,
			&path, &pi, payload, payload_len, now);
	if (ret == NGTCP2_ERR_DRAINING) { // doq received CONNECTION_CLOSE from the counterpart
		kr_quic_table_rem(*out_conn, table);
		ret = KNOT_EOK;
		goto finish;

	} else if (ngtcp2_err_is_fatal(ret)) { // connection doomed
		if (ret == NGTCP2_ERR_CALLBACK_FAILURE) {
			ret = KNOT_EBADCERTKEY;
		} else {
			ret = KNOT_ECONN;
		}

		kr_quic_table_rem(*out_conn, table);
		goto finish;

	} else if (ret != NGTCP2_NO_ERROR) { // non-fatal error, discard packet
		ret = KNOT_EOK;
		goto finish;
	}

	kr_quic_conn_mark_used(*out_conn, table);

	ret = kr_ok();

finish:
	// WARNING: This looks like it is here for thread return values,
	// therefore useless for us
	// reply->handle_ret = ret;
	return ret;
}

static enum protolayer_iter_cb_result pl_quic_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret;
	struct pl_quic_sess_data *quic = sess_data;

	queue_push(quic->unwrap_queue, ctx);

	kr_quic_conn_t *conn = NULL;

	while (protolayer_queue_has_payload(&quic->unwrap_queue)) {
		struct protolayer_iter_ctx *pkt_ctx = queue_head(quic->unwrap_queue);

		queue_pop(quic->unwrap_queue);

		const uint8_t *pkt;
		size_t pktlen;
		kr_log_info(DOQ, "received pkt in the folowing type: %s\n",
				protolayer_payload_name(ctx->payload.type));
		if (pkt_ctx->payload.type == PROTOLAYER_PAYLOAD_BUFFER) {
			pkt = pkt_ctx->payload.buffer.buf;
			pktlen = pkt_ctx->payload.buffer.len;
		} else if (pkt_ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF) {
			pkt = wire_buf_data(pkt_ctx->payload.wire_buf);
			pktlen = wire_buf_data_length(pkt_ctx->payload.wire_buf);
			if ((ret = wire_buf_trim(pkt_ctx->payload.wire_buf, pktlen)) != 0) {
				kr_log_error(DOQ, "wirebuf failed to trim: %s (%d)\n",
						kr_strerror(ret), ret);
				return kr_error(ret);
			}
		} else {
			protolayer_continue(pkt_ctx);
			continue;
		}

		// Initial comm processing
		ngtcp2_version_cid decoded_cids = { 0 };
		ngtcp2_cid scid = { 0 }, dcid = { 0 } /*, odcid = { 0 } */;

		// FIXME: duplicate read, reread in quic_init_server_conn (accept)
		ret = ngtcp2_pkt_decode_version_cid(&decoded_cids, pkt,
				pktlen, SERVER_DEFAULT_SCIDLEN);

		uint32_t supported_quic[1] = { NGTCP2_PROTO_VER_V1 };
		if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
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
			kr_log_warning(DOQ, "Exit init srv conn 3\n");
			return PROTOLAYER_ITER_CB_RESULT_MAGIC;
			// goto finish;
		} else if (ret != NGTCP2_NO_ERROR) {
			kr_log_warning(DOQ, "Exit init srv conn 4: (%d) %s \n",
					ret, ngtcp2_strerror(ret));
			return PROTOLAYER_ITER_CB_RESULT_MAGIC;
			// goto finish;
		}

		ngtcp2_cid_init(&dcid, decoded_cids.dcid, decoded_cids.dcidlen);
		ngtcp2_cid_init(&scid, decoded_cids.scid, decoded_cids.scidlen);

		conn = kr_quic_table_lookup(&dcid, quic->conn_table);

		if (!conn) {
			int rv = quic_init_server_conn(quic->conn_table, pkt_ctx,
					 UINT64_MAX - 1, &scid, &dcid, decoded_cids,
					 pkt, pktlen, &conn);

			kr_log_info(DOQ, "quic_init_server_conn returned: %d\n", ret);
			if (rv != kr_ok()) {
				protolayer_continue(pkt_ctx);
				return protolayer_break(ctx, rv);
			}

			/* Should not happen, if it did we certainly cannot
			 * continue in the communication
			 * Perhaps kr_require is too strong, this situation
			 * shouldn't corelate with kresd run.
			 * TODO: switch to condition and failed resolution*/
			kr_require(conn);
			// kr_require(conn->conn);
			// continue;

		} else {
			uint64_t now = quic_timestamp();
			kr_require(conn->conn);
			const ngtcp2_path *path = ngtcp2_conn_get_path(conn->conn);
			ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };
			ret = ngtcp2_conn_read_pkt(conn->conn,
					&path, &pi, pkt_ctx, pktlen, now);
			if (ret == NGTCP2_ERR_DRAINING) { // doq received CONNECTION_CLOSE from the counterpart
				kr_quic_table_rem(conn, quic->conn_table);
				ret = KNOT_EOK;
				return ret;

			} else if (ngtcp2_err_is_fatal(ret)) { // connection doomed
				kr_log_error(DOQ, "fatal error in ngtcp2_conn_read_pkt: %s (%d)", ngtcp2_strerror(ret), ret);
				if (ret == NGTCP2_ERR_CALLBACK_FAILURE) {
					ret = KNOT_EBADCERTKEY;
				} else {
					ret = KNOT_ECONN;
				}

				kr_quic_table_rem(conn, quic->conn_table);
				return ret;

			} else if (ret != NGTCP2_NO_ERROR) { // non-fatal error, discard packet
				kr_log_error(DOQ, "discarding recieved pkt: %s (%d)", ngtcp2_strerror(ret), ret);
				ret = KNOT_EOK;
				return ret;
			}
		}

		if (ctx->comm->target != NULL) {
			kr_log_info(DOQ, "rewriting iter_ctx->comm->target of value: %p\n",
					ctx->comm->target);
		}

		ctx->comm->target = &dcid;
		queue_push(quic->wrap_queue, ctx);

		if (!ngtcp2_conn_get_handshake_completed(conn->conn)) {
			uint64_t now = quic_timestamp();
			kr_require(conn->conn);
			const ngtcp2_path *path = ngtcp2_conn_get_path(conn->conn);
			ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };

			ret = ngtcp2_conn_write_pkt(conn->conn, path, &pi,
					wire_buf_free_space(pkt_ctx->payload.wire_buf),
					wire_buf_free_space_length(pkt_ctx->payload.wire_buf),
					now);
			if (ret <= 0) {
				kr_log_error(DOQ, "Failed to write %s (%d)\n", ngtcp2_strerror(ret), ret);
				// TODO: retry?
				protolayer_break(ctx, ret);
			}

			if ((ret = wire_buf_consume(pkt_ctx->payload.wire_buf, ret)) != 0) {
				kr_log_error(DOQ, "wirebuf failed to consume: %s (%d)\n",
						kr_strerror(ret), ret);
				return kr_error(ret);
			}


			queue_push(quic->wrap_queue, pkt_ctx);

			quic->h.session->outgoing = !quic->h.session->outgoing;
			ret = session2_wrap(quic->h.session,
					pkt_ctx->payload,
					pkt_ctx->comm,
					pkt_ctx->finished_cb,
					pkt_ctx->finished_cb_baton);

			kr_log_info(DOQ, "Result of session2_wrap: %s\n",
					ret >= 0 ? "succeeded" : "failed");

			// return protolayer_async();

			ret = ngtcp2_conn_read_pkt(conn->conn,
					&path, &pi, pkt_ctx, pktlen, now);

			ngtcp2_conn_handle_expiry(conn->conn, now);
			if (ret == NGTCP2_ERR_DRAINING) { // doq received CONNECTION_CLOSE from the counterpart
				kr_quic_table_rem(conn, quic->conn_table);
				ret = KNOT_EOK;
				return ret;

			} else if (ngtcp2_err_is_fatal(ret)) { // connection doomed
				kr_log_error(DOQ, "fatal error in ngtcp2_conn_read_pkt: %s (%d)", ngtcp2_strerror(ret), ret);
				if (ret == NGTCP2_ERR_CALLBACK_FAILURE) {
					ret = KNOT_EBADCERTKEY;
				} else {
					ret = KNOT_ECONN;
				}

				kr_quic_table_rem(conn, quic->conn_table);
				return ret;

			} else if (ret != NGTCP2_NO_ERROR) { // non-fatal error, discard packet
				kr_log_error(DOQ, "discarding recieved pkt: %s (%d)", ngtcp2_strerror(ret), ret);
				ret = KNOT_EOK;
				return ret;
			}
		}
	}

	kr_log_info(DOQ, "handshake completed :%d\n", ngtcp2_conn_get_handshake_completed(conn->conn));

	return protolayer_continue(ctx);

	if (conn && !ngtcp2_conn_get_handshake_completed(conn->conn))
		return protolayer_break(ctx, 0);

	kr_log_info(DOQ, "returning protolayer_finished, hopefully quic_wrap gets called\n");
	protolayer_break(ctx, 0);
	// protolayer_continue(ctx);
}

static bool stream_exists(kr_quic_conn_t *conn, int64_t stream_id)
{
	// Taken from Knot, TODO fix if we use stream_user_data
	// TRICK, we never use stream_user_data
	return (ngtcp2_conn_set_stream_user_data(conn->conn, stream_id, NULL) == NGTCP2_NO_ERROR);
}

// static int send_stream(kr_quic_table_t *quic_table, struct protolayer_payload *pl,
//                        kr_quic_conn_t *relay, int64_t stream_id,
//                        uint8_t *data, size_t len, bool fin, ngtcp2_ssize *sent)
// {
// 	(void)quic_table;
// 	assert(stream_id >= 0 || (data == NULL && len == 0));
//
// 	while (stream_id >= 0 && !stream_exists(relay, stream_id)) {
// 		int64_t opened = 0;
// 		int ret = ngtcp2_conn_open_bidi_stream(relay->conn, &opened, NULL);
// 		if (ret != kr_ok()) {
// 			return ret;
// 		}
// 		assert((bool)(opened == stream_id) == stream_exists(relay, stream_id));
// 	}
//
// 	int ret = pl->alloc_reply(pl);
// 	if (ret != KNOT_EOK) {
// 		return ret;
// 	}
//
// 	uint32_t fl = ((stream_id >= 0 && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN :
// 	                                         NGTCP2_WRITE_STREAM_FLAG_NONE);
// 	ngtcp2_vec vec = { .base = data, .len = len };
// 	ngtcp2_pkt_info pi = { 0 };
//
// 	struct sockaddr_storage path_loc = { 0 }, path_rem = { 0 };
// 	ngtcp2_path path = { .local  = { .addr = (struct sockaddr *)&path_loc, .addrlen = sizeof(path_loc) },
// 	                     .remote = { .addr = (struct sockaddr *)&path_rem, .addrlen = sizeof(path_rem) },
// 	                     .user_data = NULL };
// 	bool find_path = (rpl->ip_rem == NULL);
// 	assert(find_path == (bool)(rpl->ip_loc == NULL));
//
// 	ret = ngtcp2_conn_writev_stream(relay->conn, find_path ? &path : NULL, &pi,
// 	                                rpl->out_payload->iov_base, rpl->out_payload->iov_len,
// 	                                sent, fl, stream_id, &vec,
// 	                                (stream_id >= 0 ? 1 : 0), quic_timestamp());
// 	if (ret <= 0) {
// 		rpl->free_reply(rpl);
// 		return ret;
// 	}
//
// 	if (*sent < 0) {
// 		*sent = 0;
// 	}
//
// 	rpl->out_payload->iov_len = ret;
// 	rpl->ecn = pi.ecn;
// 	if (find_path) {
// 		rpl->ip_loc = &path_loc;
// 		rpl->ip_rem = &path_rem;
// 	}
// 	ret = rpl->send_reply(rpl);
// 	if (find_path) {
// 		rpl->ip_loc = NULL;
// 		rpl->ip_rem = NULL;
// 	}
// 	if (ret == KNOT_EOK) {
// 		return 1;
// 	}
// 	return ret;
// }

static int quic_package_payload(kr_quic_table_t *qt,
		struct protolayer_payload pl, void *sess_data,
		kr_quic_conn_t *relay /* ?? */,
		int64_t stream_id, uint8_t *data /* ?? */, size_t len,
		bool fin, ngtcp2_ssize *sent)
{
	// sanity check
	if (!data || !sent || !sess_data) {
		kr_log_error(DOQ, "Missing information in quic_package_payload\n");
		return kr_error(EINVAL);
	}

	pl_quic_sess_data_t *sd = sess_data; // to fill path with data

	uint32_t fl = ((stream_id >= 0 && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN :
	                                         NGTCP2_WRITE_STREAM_FLAG_NONE);

	ngtcp2_vec vec = { .base = pl.buffer.buf, .len = pl.buffer.len};
	// ngtcp2_vec vec; TODO reseach how wirebuf works
	// switch (pl.type) {
	// 	case PROTOLAYER_PAYLOAD_IOVEC:
	// 		vec.base = pl.iovec.iov;
	// 		vec.len = pl.iovec.cnt;
	// 	default:
	// 		vec.base = pl.buffer.buf;
	// 		vec.len = pl.buffer.len;

	ngtcp2_pkt_info pi = { 0 };

	struct sockaddr_storage path_loc = { 0 }, path_rem = { 0 };
	ngtcp2_path path = { .local  = { .addr = (struct sockaddr *)&path_loc, .addrlen = sizeof(path_loc) },
			.remote = { .addr = (struct sockaddr *)&path_rem, .addrlen = sizeof(path_rem) },
			.user_data = NULL };
	// TODO check these dst_addr. Consult knot values, I might be
	// using incorrect fields
	bool find_path = (sd->h.session->comm_storage.dst_addr == NULL);
	assert(find_path == (bool)(sd->h.session->comm_storage.src_addr == NULL));

	assert(len >= NGTCP2_MAX_UDP_PAYLOAD_SIZE);
	// TODO deal with buffer size inc

	ngtcp2_ssize ret = ngtcp2_conn_writev_datagram(
			relay->conn, find_path ? &path : NULL, &pi,
			data, len,
			// rpl.out_payload->iov_base, rpl.out_payload->iov_len,
			sent, fl, stream_id, &vec,
			(stream_id >= 0 ? 1 : 0), quic_timestamp());

	// incorectly handles empty writes as well
	if (ret == 0)
		kr_log_error(DOQ, "ngtcp2_conn_writev_datagram returned 0, see ngtcp2 documentation\n");

	if (ret < 0)
		kr_log_error(DOQ, "Failed to create pkt in WRAP direction (%zu) %s\n",
				ret, ngtcp2_strerror(ret)) ;

	if (*sent < 0)
		*sent = 0;

	pl.buffer.len = ret;
	if (find_path) {
		//					idk if this will work
		sd->h.session->comm_storage.src_addr = (struct sockaddr *)&path_loc;
		sd->h.session->comm_storage.dst_addr = (struct sockaddr *)&path_rem;
	}

	// TODO "If any other negative error is returned,
	// call ngtcp2_conn_write_connection_close() to get terminal
	// packet, and sending it makes QUIC connection enter the closing state."
	// (https://nghttp2.org/ngtcp2/ngtcp2_conn_writev_datagram.html#c.ngtcp2_conn_writev_datagram)
	// if (ret != {array of specified})"
	// 	ngtcp2_conn_write_connection_close();

	return kr_ok();
}

void kr_quic_stream_mark_sent(kr_quic_conn_t *conn, int64_t stream_id,
                                size_t amount_sent)
{
	kr_quic_stream_t *s = kr_quic_conn_get_stream(conn, stream_id, false);
	if (s == NULL) {
		return;
	}

	s->unsent_offset += amount_sent;
	assert(s->unsent_offset <= s->unsent_obuf->len);
	if (s->unsent_offset == s->unsent_obuf->len) {
		s->unsent_offset = 0;
		s->unsent_obuf = (kr_quic_obuf_t *)s->unsent_obuf->node.next;
		if (s->unsent_obuf->node.next == NULL) { // already behind the tail of list
			s->unsent_obuf = NULL;
		}
	}
}

int kr_quic_send(kr_quic_table_t *quic_table, kr_quic_conn_t *conn,
                   /* kr_quic_reply_t *reply */void *sess_data,
		   struct protolayer_payload pl,
		   unsigned max_msgs, kr_quic_send_flag_t flags)
{
	// pl_quic_sess_data_t *data = (pl_quic_sess_data_t *)sess_data;

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
		size_t len = 5534u; /* size of the following buffer */
		uint8_t *data = /* alloc buffer */ NULL;
		ret = quic_package_payload(quic_table, pl, sess_data,
				NULL, stream_id, data, len, fin, &sent);

		// ret = send_stream(quic_table, reply, conn, stream_id,
		//                   uo->buf + uf, uo->len - uf - ignore_last,
		//                   fin, &sent);

		if (ret < 0) {
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

	// while (ret == 1) {
	// 	ngtcp2_ssize unused = 0;
	// 	// ret = send_stream(quic_table, reply, conn, -1, NULL, 0, false, &unused);
	// }

	return ret;
}

static enum protolayer_iter_cb_result pl_quic_wrap(
		void *sess_data, void *iter_data,
		struct protolayer_iter_ctx *ctx)
{
	kr_log_info(DOQ, "In wrap! payload type: %s\n",
			protolayer_payload_name(ctx->payload.type));

	// return protolayer_continue(ctx);
	// input ceremony into session pkt
	// ngtcp2_pkt_hd represents QUIC packet header. //filled by accept
	// ngtcp2_transport_params represents QUIC transport parameters.
	// ngtcp2_settings defines QUIC connection settings.

	pl_quic_sess_data_t *quic = sess_data;
	queue_push(quic->wrap_queue, ctx);
	struct ngtcp2_cid *scid;
	struct protolayer_iter_ctx *data = queue_head(quic->wrap_queue);

	if (!data || !data->comm || !data->comm->target) {
		kr_log_error(DOQ, "missing required information in wrap direction doq\n");
		return -1; // TODO
	}

	struct ngtcp2_cid *dcid = (struct ngtcp2_cid *)data->comm->target;

	// struct protolayer_payload payload = protolayer_payload_as_buffer(&payload); // this is incorrect

	// ctx->comm_addr_storage
	// kr_quic_reply_t *reply = NULL;

	kr_quic_conn_t *conn = kr_quic_table_lookup(dcid, quic->conn_table);
	if (!conn) {
		kr_log_info(DOQ, "No conn found!\n");
		return -1; // TODO
	}

	// example: knot-dns/srt/utils/kxdpgun/main.c/xdp_gun_thread:408
	if (/* no connection present */ 1) {
		// int ret = kr_quic_send(quic->conn_table,
		// 		conn, sess_data, ctx->payload, 1, 0);

		// kr_log_info(DOQ, "Actually sending %s (%d)\n", kr_strerror(ret), ret);
		//
		// if (ret != KNOT_EOK)
		// 	// kr_log_error(DOQ, "knot_quic_send failed (%d)", ret);
		// 	;
	}

	kr_log_info(DOQ, "wrap protolayer_continue hs done: %d\n",
			ngtcp2_conn_get_handshake_completed(conn->conn));
	// return protolayer_break(ctx, PROTOLAYER_ITER_ACTION_BREAK);
	return protolayer_continue(ctx);
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
	pl_quic_sess_data_t *quic = sess_data;
	quic->req = req;
}

__attribute__((constructor))
static void quic_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_QUIC] = (struct protolayer_globals) {
		.sess_size = sizeof(struct pl_quic_sess_data),
		.iter_size = sizeof(struct pl_quic_state),
		.wire_buf_overhead = MAX_QUIC_FRAME_SIZE,
		// .iter_init = TODO?
		// .iter_deinit = TODO?
		.sess_deinit = pl_quic_sess_deinit,
		.sess_init = pl_quic_sess_init,
		.unwrap = pl_quic_unwrap,
		.wrap = pl_quic_wrap,
		.event_unwrap = pl_quic_event_unwrap,
		.event_wrap = pl_quic_event_wrap,
		.request_init = pl_quic_request_init,
	};
}
