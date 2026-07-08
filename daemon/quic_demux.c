/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "network.h"
#include "quic_common.h"
#include "quic_conn.h"
#include "quic_demux.h"
#include "session2.h"
#include "worker.h"
#include "lib/dnssec.h"
#include "session2.h"
#include "worker.h"
#include <stdlib.h>

/* Toggle sending retry for new connections. This is a way to validate the
 * client address, but it adds 1 round trip to the connection establishment
 * potentially hindering performance */
#define BUCKETS_PER_CONNS 8 // Each connecion has several dCIDs, and each CID takes one hash table bucket.

void kr_quic_table_rem(struct pl_quic_conn_sess_data *conn, kr_quic_table_t *table);

static int cmp_expiry_heap_nodes(void *c1, void *c2)
{
	if (((struct pl_quic_conn_sess_data *)c1)->h.heap_value >
			((struct pl_quic_conn_sess_data *)c2)->h.heap_value)
		return 1;

	if (((struct pl_quic_conn_sess_data *)c1)->h.heap_value <
			((struct pl_quic_conn_sess_data *)c2)->h.heap_value)
		return -1;

	return 0;
}

static void conn_heap_reschedule(struct pl_quic_conn_sess_data *conn,
		struct kr_quic_table *table)
{
	heap_replace(table->expiry_heap,
			heap_find(table->expiry_heap,
			(heap_val_t *)conn), (heap_val_t *)conn);
}

void quic_conn_mark_used(struct pl_quic_conn_sess_data *conn,
		kr_quic_table_t *table)
{
	if (table == NULL || conn == NULL || conn->conn == NULL) {
		return;
	}

	conn->h.heap_value = ngtcp2_conn_get_expiry(conn->conn) * quic_not_draining(conn);
	conn_heap_reschedule(conn, table);
}

void kr_quic_table_rem(struct pl_quic_conn_sess_data *conn,
		kr_quic_table_t *table)
{
	if (conn == NULL || table == NULL) {
		return;
	}

	if (conn->conn) {
		size_t num_scid = ngtcp2_conn_get_scid(conn->conn, NULL);
		ngtcp2_cid *scids = calloc(num_scid, sizeof(*scids));
		ngtcp2_conn_get_scid(conn->conn, scids);

		for (size_t i = 0; i < num_scid; i++) {
			kr_quic_cid_t **pcid = kr_quic_table_lookup2(&scids[i], table);
			if (*pcid == NULL) {
				continue;
			}
			kr_quic_table_rem2(pcid, table);
		}

		free(scids);
	} else {
		kr_quic_cid_t **pcid = kr_quic_table_lookup2(&conn->dcid, table);
		if (kr_fails_assert(pcid != NULL && (*pcid) != NULL)) {
			/* Likely impossible without a significantly corrupt
			 * state and/or presence of a programming error */
			kr_log_debug(DOQ, "Failed to remove connection cid from table, counters might not match\n");
		} else {
			kr_quic_table_rem2(pcid, table);
		}
	}

	kr_quic_cid_t **podcid = kr_quic_table_lookup2(&conn->odcid, table);
	if (kr_fails_assert(podcid != NULL && *podcid != NULL)) {
		kr_log_debug(DOQ, "Failed to remove connection cid from table, counters might not match\n");
	} else {
		kr_quic_table_rem2(podcid, table);
	}

	int pos = heap_find(table->expiry_heap, (heap_val_t *)conn);
	if (pos != 0) {
		heap_delete(table->expiry_heap, pos);
		table->usage--;
	}
}

void kr_quic_table_free(kr_quic_table_t *table)
{
	if (!table)
		return;

	kr_require(EMPTY_HEAP(table->expiry_heap));
	kr_assert(table->usage == 0);
	kr_assert(table->pointers == 0);

	gnutls_priority_deinit(table->priority);
	heap_deinit(table->expiry_heap);
	free(table->expiry_heap);
	free(table);
}

static enum protolayer_iter_cb_result pl_quic_demux_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	struct pl_quic_conn_sess_data *qconn = NULL;
	struct pl_quic_demux_sess_data *demux = sess_data;

	bool retry_sent = false;
	ngtcp2_version_cid dec_cids;
	ngtcp2_cid odcid = { 0 };
	ngtcp2_cid dcid = { 0 };
	ngtcp2_cid scid = { 0 };

	kr_require(ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF);
	int ret = ngtcp2_pkt_decode_version_cid(&dec_cids,
			wire_buf_data(ctx->payload.wire_buf),
			wire_buf_data_length(ctx->payload.wire_buf),
			SERVER_DEFAULT_SCIDLEN);

	if (ret == NGTCP2_ERR_INVALID_ARGUMENT) {
		kr_log_warning(DOQ, "Could not decode pkt header: (%d) %s\n",
				ret, ngtcp2_strerror(ret));
		return protolayer_break(ctx, kr_error(EINVAL));
	} else if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
		send_special(&dec_cids, demux->conn_table, ctx,
				QUIC_SEND_VERSION_NEGOTIATION, NULL,
				demux->h.session, NULL);
		return protolayer_break(ctx, kr_ok());
	}

	uint64_t now = quic_timestamp();
	ngtcp2_cid_init(&dcid, dec_cids.dcid, dec_cids.dcidlen);
	ngtcp2_cid_init(&scid, dec_cids.scid, dec_cids.scidlen);

	qconn = kr_quic_table_lookup(&dcid, demux->conn_table);
	if (!qconn) {
		if (demux->conn_table->usage >= demux->conn_table->max_conns) {
			return protolayer_break(ctx, kr_ok());
		}

		ngtcp2_pkt_hd header = { 0 };
		ret = ngtcp2_accept(&header,
			wire_buf_data(ctx->payload.wire_buf),
			wire_buf_data_length(ctx->payload.wire_buf));
		if (ret != NGTCP2_NO_ERROR) {
			kr_log_debug(DOQ, "error accepting new conn: %s (%d)\n",
					ngtcp2_strerror(ret), ret);

			/* either the packet is not acceptable as the first
			 * packet of a new connection, or the function failed
			 * to parse the packet header */
			return protolayer_break(ctx, kr_ok());
		}

		if (header.tokenlen == 0 && the_network->quic_params
				&& the_network->quic_params->require_retry) {
			if (send_special(&dec_cids, demux->conn_table, ctx,
					QUIC_SEND_RETRY, NULL,
					demux->h.session, NULL) != kr_ok()) {

				kr_log_debug(DOQ, "Failed to send retry packet\n");
			}

			return protolayer_break(ctx, kr_ok());
		}

		if (header.tokenlen > 0) {
			if (header.token[0] == NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2) {
				retry_sent = true;
				ret = ngtcp2_crypto_verify_retry_token2(
					&odcid, header.token, header.tokenlen,
					(const uint8_t *)demux->conn_table->hash_secret,
					sizeof(demux->conn_table->hash_secret), header.version,
					ctx->comm->src_addr,
					kr_sockaddr_len(ctx->comm->src_addr),
					&dcid, QUIC_CONN_IDLE_TIMEOUT,
					now);
			} else {
				ret = ngtcp2_crypto_verify_regular_token(
					header.token, header.tokenlen,
					(const uint8_t *)demux->conn_table->hash_secret,
					sizeof(demux->conn_table->hash_secret),
					ctx->comm_storage.src_addr,
					kr_sockaddr_len(ctx->comm->src_addr),
					QUIC_REGULAR_TOKEN_TIMEOUT, now);
			}
			if (ret != 0) {
				kr_log_debug(DOQ, "Failed to verify retry or regular token: %s (%d)\n",
						ngtcp2_strerror(ret), ret);
				return protolayer_break(ctx, kr_ok());
			}

		} else {
			memcpy(&odcid, &dcid, sizeof(odcid));

			/* TODO remove 'likely' once outgoing DoQ is supported */
			if (likely(!demux->h.session->outgoing)) {
				if (init_unique_cid(&dcid, 0, demux->conn_table) != 0) {
					kr_log_debug(DOQ, "Failed to initialize unique cid (servers choice)\n");
					return protolayer_break(ctx, kr_ok());
				}
			}
		}

		struct kr_quic_conn_param params = {
			.retry_sent = retry_sent,
			.table = demux->conn_table,
			.dcid = dcid,
			.scid = scid,
			.odcid = odcid,
			.dec_cids = &dec_cids,
			.comm_storage = ctx->comm,
		};

		struct protolayer_data_param data_param = {
			.protocol = PROTOLAYER_TYPE_QUIC_CONN,
			.param = &params
		};

		struct session2 *new_conn_sess =
			session2_new_child(demux->h.session,
					KR_PROTO_DOQ_CONN,
					&data_param,
					1,
					false);

		if (!new_conn_sess) {
			return protolayer_break(ctx, kr_error(ENOMEM));
		}

		struct pl_quic_conn_sess_data *conn_sess_data =
			protolayer_sess_data_get_proto(new_conn_sess,
					PROTOLAYER_TYPE_QUIC_CONN);
		kr_quic_table_add(conn_sess_data, &dcid, demux->conn_table);
		kr_quic_table_insert(conn_sess_data, &odcid, demux->conn_table);
		qconn = conn_sess_data;

		/* We need the handling of the first packet of the connection
		 * to execute right away. Skip defer to make sure connection
		 * state contains correct flags when we check below. */
		ret = session2_unwrap_after(qconn->h.session,
				PROTOLAYER_TYPE_DEFER,
				ctx->payload,
				ctx->comm,
				ctx->finished_cb,
				ctx->finished_cb_baton);
		/* The connection failed to initialize. Either a general
		 * failure or a retry pkt was sent, both cases mean we
		 * can discard the current conn state (close the session) */
		if (qconn->state >= QUIC_STATE_DRAINING) {
			session2_force_close(new_conn_sess);
			return protolayer_break(ctx, kr_ok());
		}
	} else {
		ret = session2_unwrap(qconn->h.session,
				ctx->payload,
				ctx->comm,
				ctx->finished_cb,
				ctx->finished_cb_baton);
	}

	/* The received message caused the conn to enter closing state,
	 * terminate session here since the protolayer_iter_ctx needs
	 * the session, otherwise mark used and sweep. */
	if ((qconn->state & QUIC_STATE_DRAINING)
		|| (qconn->state & QUIC_STATE_CLOSING)) {
		// pass
	} else {
		quic_conn_mark_used(qconn, demux->conn_table);
	}
	return protolayer_break(ctx, kr_ok());
}

kr_quic_table_t *kr_quic_table_new(size_t max_conns, size_t udp_payload,
		struct tls_credentials *creds)
{
	int ret;
	size_t table_size = max_conns * BUCKETS_PER_CONNS;

	kr_quic_table_t *new_table = calloc(1, sizeof(*new_table) + (table_size * sizeof(new_table->conns[0])));
	if (new_table == NULL) {
		kr_log_error(DOQ, "Calloc in kr_quic_table_new_failed\n");
		return NULL;
	}


	new_table->size = table_size;
	new_table->usage = 0;
	new_table->pointers = 0;
	new_table->max_conns = max_conns;
	new_table->udp_payload_limit = udp_payload;

	// NOTE: Taken from tls-proxy.c/96, we might need to use this
	// to enforce the use of tls1.3 (tls1.3 compat mode might be problematic)
	//
	// static const char * const tlsv13_priorities =
	// 	"NORMAL:" /* GnuTLS defaults */
	// 	"-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2:+VERS-TLS1.3:" /* TLS 1.3 only */
	// 	"-VERS-SSL3.0:-ARCFOUR-128:-COMP-ALL:+COMP-NULL";

	ret = gnutls_priority_init2(&new_table->priority, NULL, NULL, 0);
	if (ret != GNUTLS_E_SUCCESS)
		goto fail;

	new_table->expiry_heap = malloc(sizeof(struct heap));
	if (new_table->expiry_heap == NULL ||
			!heap_init(new_table->expiry_heap, cmp_expiry_heap_nodes, 0))
		goto fail;

	new_table->creds = creds;

	new_table->hash_secret[0] = dnssec_random_uint64_t();
	new_table->hash_secret[1] = dnssec_random_uint64_t();
	new_table->hash_secret[2] = dnssec_random_uint64_t();
	new_table->hash_secret[3] = dnssec_random_uint64_t();

	return new_table;

fail:
	if (new_table->creds) {
		if (new_table->creds->credentials) {
			gnutls_certificate_free_credentials(
					new_table->creds->credentials);
		}
	}
	if (new_table->priority) {
		gnutls_priority_deinit(new_table->priority);
	}
	if (new_table->expiry_heap) {
		free(new_table->expiry_heap);
	}

	free(new_table);
	return NULL;
}

static int pl_quic_demux_sess_init(struct session2 *session, void *sess_data, void *param)
{
	struct pl_quic_demux_sess_data *quic = sess_data;
	session->secure = true;

	if (!the_network->tls_credentials) {
		the_network->tls_credentials = tls_get_ephemeral_credentials();
		if (!the_network->tls_credentials) {
			kr_log_error(TLS, "X.509 credentials are missing, and ephemeral credentials failed; no TLS\n");
			return kr_error(EINVAL);
		}

		kr_log_info(TLS, "Using ephemeral TLS credentials\n");
	}

	struct tls_credentials *creds = the_network->tls_credentials;

	/* kresd process was run without a manager and no quic configuration
	 * which would set defaults was provided -> init and set defaults */
	if (!the_network->quic_params) {
		int ret = 0;
		if ((ret = quic_configuration_set()) != kr_ok()) {
			kr_log_error(DOQ, "Failed to allocate quic defaults\n");
			return ret;
		}
	}

	if (!quic->conn_table) {
		kr_require(the_network->quic_params);
		quic->conn_table = kr_quic_table_new(
				the_network->quic_params->max_conns,
				NGTCP2_MAX_UDP_PAYLOAD_SIZE, creds);
		if (!quic->conn_table) {
			kr_log_error(DOQ, "Failed to create QUIC connection table\n");
			return kr_error(ENOMEM);
		}
	}

	return kr_ok();
}

static int pl_quic_demux_sess_deinit(struct session2 *session, void *data)
{
	if (session->outgoing && the_worker->doq_out_session == session) {
		the_worker->doq_out_session = NULL;
	}

	struct pl_quic_demux_sess_data *quic = data;
	kr_quic_table_free(quic->conn_table);
	if (session->outgoing) {
		the_worker->doq_out_session = NULL;
	}
	return kr_ok();
}

static enum protolayer_event_cb_result pl_quic_demux_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	struct pl_quic_demux_sess_data *demux = sess_data;
	if (event == PROTOLAYER_EVENT_CLOSE || event == PROTOLAYER_EVENT_FORCE_CLOSE) {
		while (!EMPTY_HEAP(demux->conn_table->expiry_heap)) {
			struct pl_quic_conn_sess_data *c =
				*(struct pl_quic_conn_sess_data **)HHEAD(
						demux->conn_table->expiry_heap);
			ngtcp2_ccerr_set_application_error(&c->ccerr,
					DOQ_NO_ERROR, NULL, 0);
			session2_event(c->h.session, event, NULL);
		}
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_quic_demux_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if (event == PROTOLAYER_EVENT_FORCE_CLOSE
			|| event == PROTOLAYER_EVENT_CLOSE
			|| event == PROTOLAYER_EVENT_GENERAL_TIMEOUT
			|| event == PROTOLAYER_EVENT_CONNECT_TIMEOUT) {
		/* Terminate subsession */
		if (baton && *baton) {
			struct pl_quic_conn_sess_data *conn = *baton;
			kr_quic_table_rem(conn, conn->table_ref);
			uv_close((uv_handle_t *)&conn->h.session->timer,
					on_session2_timer_close);
			return PROTOLAYER_EVENT_CONSUME;
		}
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}


__attribute__((constructor))
static void quic_demux_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_QUIC_DEMUX] = (struct protolayer_globals) {
		.sess_size = sizeof(struct pl_quic_demux_sess_data),
		.wire_buf_overhead = MAX_QUIC_FRAME_SIZE,
		.sess_init = pl_quic_demux_sess_init,
		.sess_deinit = pl_quic_demux_sess_deinit,
		.unwrap = pl_quic_demux_unwrap,
		.event_unwrap = pl_quic_demux_event_unwrap,
		.event_wrap = pl_quic_demux_event_wrap,
	};
}
