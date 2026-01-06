/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "network.h"
#include "quic_common.h"
#include "quic_conn.h"
#include "quic_demux.h"
#include "libdnssec/random.h"
#include <stdlib.h>

/* Toggle sending retry for new connections. This is a way to validate the
 * client address, but it adds 1 round trip to the connection establishment
 * potentially hindering performance */
#define BUCKETS_PER_CONNS 8 // Each connecion has several dCIDs, and each CID takes one hash table bucket.

void kr_quic_table_rem(struct pl_quic_conn_sess_data *conn, kr_quic_table_t *table);

static int cmp_expiry_heap_nodes(void *c1, void *c2)
{
	if (((struct pl_quic_conn_sess_data *)c1)->h.heap_value <
			((struct pl_quic_conn_sess_data *)c2)->h.heap_value)
		return -1;

	if (((struct pl_quic_conn_sess_data *)c1)->h.heap_value >
			((struct pl_quic_conn_sess_data *)c2)->h.heap_value)
		return 1;

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

	conn->h.heap_value = ngtcp2_conn_get_expiry(conn->conn) * QUIC_CAN_SEND(conn);
	conn_heap_reschedule(conn, table);
}

kr_quic_cid_t **kr_quic_table_insert(struct pl_quic_conn_sess_data *conn,
		const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	kr_quic_cid_t *cidobj = malloc(sizeof(*cidobj));
	if (cidobj == NULL)
		return NULL;

	memcpy(cidobj->cid_placeholder, cid, sizeof(*cid));
	cidobj->conn_sess = conn;

	kr_quic_cid_t **addto = table->conns + (hash % table->size);
	cidobj->next = *addto;
	*addto = cidobj;
	table->pointers++;
	conn->cid_pointers++;

	return addto;
}

int kr_quic_table_add(struct pl_quic_conn_sess_data *conn_sess,
		const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	if (!conn_sess || !cid || !table) {
		return kr_error(EINVAL);
	}

	conn_sess->h.heap_value = UINT64_MAX;
	if (!heap_insert(table->expiry_heap, (heap_val_t *)conn_sess)) {
		return kr_error(ENOMEM);
	}

	kr_quic_cid_t **addto = kr_quic_table_insert(conn_sess, cid, table);
	if (addto == NULL) {
		heap_delete(table->expiry_heap, heap_find(table->expiry_heap, (heap_val_t *)conn_sess));
		return kr_error(ENOMEM);
	}

	table->usage++;
	return kr_ok();
}

int kr_quic_table_rem2(kr_quic_cid_t **pcid, kr_quic_table_t *table)
{
	kr_quic_cid_t *cid = *pcid;
	*pcid = cid->next;
	free(cid);
	table->pointers--;

	return kr_ok();
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
			conn->cid_pointers--;
		}

		free(scids);
	}
	
	int pos = heap_find(table->expiry_heap, (heap_val_t *)conn);
	/* Since deferred iteration context increases the session ref_count
	 * it is possible that the session will exist after being removed
	 * from the expiry heap. In such case no cid is found and the
	 * the heap_find function returns 0, which is not a valid value
	 * because the heap index starts at 1. */
	if (pos != 0) {
		heap_delete(table->expiry_heap, pos);
		table->usage--;
	}
}

void kr_quic_table_free(kr_quic_table_t *table)
{
	if (!table)
		return;

	while (!EMPTY_HEAP(table->expiry_heap)) {
		struct pl_quic_conn_sess_data *c =
			*(struct pl_quic_conn_sess_data **)HHEAD(table->expiry_heap);

		kr_quic_table_rem(c, table);
	}

	kr_assert(table->usage == 0);
	kr_assert(table->pointers == 0);

	gnutls_priority_deinit(table->priority);
	heap_deinit(table->expiry_heap);
	free(table->expiry_heap);
	free(table);
}

void kr_quic_table_sweep(struct kr_quic_table *table,
		struct protolayer_iter_ctx *ctx)
{
	uint64_t now = 0;
	while (!EMPTY_HEAP(table->expiry_heap)) {
		struct pl_quic_conn_sess_data *c =
			*(struct pl_quic_conn_sess_data **)
			HHEAD(table->expiry_heap);

		if ((c->state & QUIC_STATE_BLOCKED)) {
			break;
		/* when we reach the limit of open conns we lookup the most idle
		 * one but only close it if it received at least one query.
		 * This is to prevent closing brand new connections which has
		 * crippling effects on the number of answered queries when
		 * conn limits are reached. */
		} else if (table->usage >= table->max_conns &&
				// c->streams_count <= 0 &&
				c->finished_streams > 0) {
			quic_doq_error_t doq_error = DOQ_EXCESSIVE_LOAD;
			send_special(&c->dec_cids, c->table_ref, ctx,
					QUIC_SEND_CONN_CLOSE, c, c->h.session,
					&doq_error);
			session2_event(c->h.session->transport.parent,
					PROTOLAYER_EVENT_DISCONNECT,
					c);
		} else if (c->state & QUIC_STATE_DRAINING) {
			session2_event(c->h.session->transport.parent,
					PROTOLAYER_EVENT_DISCONNECT,
					c);
		// } else if (c->state & QUIC_STATE_CLOSING) {
		// 	quic_doq_error_t doq_error = DOQ_NO_ERROR;
		// 	send_special(&c->dec_cids, c->table_ref,
		// 			ctx, QUIC_SEND_CONN_CLOSE,
		// 			c, c->h.session, &doq_error);
		// 	session2_event(c->h.session->transport.parent,
		// 			PROTOLAYER_EVENT_DISCONNECT,
		// 			c);
		} else if (kr_quic_conn_timeout(c, &now)) {
			int ret = ngtcp2_conn_handle_expiry(c->conn, now);
			if (ret != NGTCP2_NO_ERROR) {
				quic_doq_error_t doq_error = DOQ_NO_ERROR;
				/* see https://nghttp2.org/ngtcp2/ngtcp2_conn_handle_expiry.html */
				if (ret != NGTCP2_ERR_IDLE_CLOSE) {
					send_special(&c->dec_cids, c->table_ref,
							ctx, QUIC_SEND_CONN_CLOSE,
							c, c->h.session, &doq_error);
				}
				session2_event(c->h.session->transport.parent,
						PROTOLAYER_EVENT_DISCONNECT, c);
			} else {
				// quic_conn_mark_used(c, table);
			}
		}
		// HHEAD already handled, NOOP, avoid infinite loop
		if (*(struct pl_quic_conn_sess_data **)
				HHEAD(table->expiry_heap) == c) {
			break;
		}
	}
}

static enum protolayer_iter_cb_result pl_quic_demux_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret = kr_ok();
	struct pl_quic_conn_sess_data *qconn = NULL;
	struct pl_quic_demux_sess_data *demux = sess_data;

	/* Currently we only receive WIRE_BUF payload */
	// if (ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF) {
	// 	kr_log_warning(DOQ, "Unexpected payload type in quic-demux\n");
	// 	return protolayer_break(ctx, kr_error(ENOTSUP));
	// }

	bool retry_sent = false;
	ngtcp2_version_cid dec_cids;
	ngtcp2_cid odcid;
	ngtcp2_cid dcid;
	ngtcp2_cid scid;

	ret = ngtcp2_pkt_decode_version_cid(&dec_cids,
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
			kr_quic_table_sweep(demux->conn_table, ctx);
			if (demux->conn_table->usage >= demux->conn_table->max_conns) {
				/* no luck */
				return protolayer_break(ctx, kr_ok());
			}
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
				/* FIXME the generate string might not be correct */
				kr_log_debug(DOQ, "Failed to verify retry or regular token: %s (%d)\n",
						ngtcp2_strerror(ret), ret);
				return protolayer_break(ctx, kr_ok());
			} else {
				kr_log_debug(DOQ, "Retry or regular token successfully verified\n");
			}

		} else {
			memcpy(&odcid, &dcid, sizeof(odcid));

			/* TODO remove 'likely' once outgoing DoQ is supported */
			if (likely(!demux->h.session->outgoing)) {
				if (!init_unique_cid(&dcid, 0, demux->conn_table)) {
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

		struct pl_quic_conn_sess_data *conn_sess_data =
			protolayer_sess_data_get_proto(new_conn_sess,
					PROTOLAYER_TYPE_QUIC_CONN);
		kr_quic_table_add(conn_sess_data, &dcid,
				demux->conn_table);
		qconn = conn_sess_data;
	}

	ret = session2_unwrap(qconn->h.session,
			ctx->payload,
			ctx->comm,
			// NULL,
			ctx->finished_cb,
			ctx->finished_cb_baton);

	quic_conn_mark_used(qconn, demux->conn_table);
	kr_quic_table_sweep(demux->conn_table, ctx);
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
	new_table->max_conns = max_conns;
	new_table->udp_payload_limit = udp_payload;

	// kr_require(new_table->creds);
	// ret = gnutls_certificate_allocate_credentials(&new_table->creds->credentials);
	// if (ret != GNUTLS_E_SUCCESS)
	// 	goto fail;
	//

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
	struct pl_quic_demux_sess_data *quic = data;
	kr_quic_table_free(quic->conn_table);
	return kr_ok();
}

static int remove_connection_id(struct pl_quic_demux_sess_data *demux,
		ngtcp2_cid *cid, void *user_data)
{
	kr_quic_cid_t **pcid = kr_quic_table_lookup2(cid, demux->conn_table);
	if (!pcid || !*pcid) {
		kr_log_error(DOQ, "Table doesn't contain cid that is to be removed\n");
		return kr_error(EINVAL);
	}

	if ((*pcid)->conn_sess->cid_pointers <= 1) {
		kr_log_error(DOQ, "Cannot remove all connection ids, protocol error\n");
		return kr_error(EPROTO);
	}

	return kr_quic_table_rem2(pcid, demux->conn_table);
}

static int update_connection_id_map(struct pl_quic_demux_sess_data *demux,
		struct pl_quic_conn_sess_data *conn)
{
	ngtcp2_cid *cid = &conn->dcid;
	if (!init_unique_cid(cid, cid->datalen, demux->conn_table)) {
		kr_log_error(DOQ, "Failed to create init new cid\n");
		return kr_error(EINVAL);
	}

	if (kr_quic_table_insert(conn, cid, demux->conn_table) == NULL) {
		kr_log_error(DOQ, "Failed to add new cid to conn map\n");
		return kr_error(EINVAL);
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
			kr_quic_table_rem(c, demux->conn_table);
			session2_close(c->h.session);
		}

		session2_dec_refs(session);
		return PROTOLAYER_EVENT_CONSUME;
	}

	if (*baton == NULL) {
		return PROTOLAYER_EVENT_PROPAGATE;
	}

	struct pl_quic_conn_sess_data *conn = *baton;

	/* received NEW_CONNECTION_ID, update mapping to conn_sess_data */
	if (event == PROTOLAYER_EVENT_CONNECT_UPDATE) {
		if (update_connection_id_map(demux, conn) != kr_ok()) {
			event = PROTOLAYER_EVENT_DISCONNECT;
			/* fallthrough */
		}
	}

	if (event == PROTOLAYER_EVENT_CONNECT_RETIRE) {
		if (remove_connection_id(demux, &conn->dcid, conn) != kr_ok()) {
			event = PROTOLAYER_EVENT_DISCONNECT;
			/* fallthrough */
		}
	}

	if (event == PROTOLAYER_EVENT_DISCONNECT ||
			event == PROTOLAYER_EVENT_CONNECT_TIMEOUT) {
		kr_quic_table_rem(conn, demux->conn_table);
		session2_close(conn->h.session);
		return PROTOLAYER_EVENT_CONSUME;
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
	};
}
