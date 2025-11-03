/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/defines.h"
#include "network.h"
#include "quic_common.h"

#include "libdnssec/random.h"
#include "contrib/openbsd/siphash.h"
#include "quic_conn.h"
#include "session2.h"
#include "worker.h"
#include <ngtcp2/ngtcp2.h>
#include <sys/cdefs.h>
#include "quic_demux.h"

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

struct pl_quic_conn_sess_data *kr_quic_table_lookup(const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	kr_quic_cid_t **pcid = kr_quic_table_lookup2(cid, table);
	return *pcid == NULL ? NULL : (*pcid)->conn_sess;
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

static void send_excessive_load(struct pl_quic_conn_sess_data *conn,
		struct protolayer_iter_ctx *ctx, kr_quic_table_t *table)
{
	(void)send_special(conn, ctx, DOQ_EXCESSIVE_LOAD);
}

/* unused for now, compare performance with per conn uv_timer_t spawns */
void kr_quic_table_sweep(struct kr_quic_table *table,
		struct protolayer_iter_ctx *ctx)
{
	uint64_t now = 0;
	size_t removed = 0;

	while (!EMPTY_HEAP(table->expiry_heap)) {
		struct pl_quic_conn_sess_data *c =
			*(struct pl_quic_conn_sess_data **)
			HHEAD(table->expiry_heap);

		if ((c->state & QUIC_STATE_BLOCKED)) {
			break;
		} else if (table->usage > table->max_conns) {
			send_excessive_load(c, ctx, table);
			kr_quic_table_rem(c, table);
			session2_event(c->h.session,
					PROTOLAYER_EVENT_DISCONNECT,
					NULL);
			++removed;
		} else if (c->state >= QUIC_STATE_CLOSING) {
			send_special(c, ctx, QUIC_SEND_CONN_CLOSE);
			kr_quic_table_rem(c, table);
			session2_event(c->h.session,
					PROTOLAYER_EVENT_DISCONNECT,
					NULL);
			++removed;


		} else if (kr_quic_conn_timeout(c, &now)) {
			int ret = ngtcp2_conn_handle_expiry(c->conn, now);
			if (ret != NGTCP2_NO_ERROR) {
				if (ret != NGTCP2_ERR_IDLE_CLOSE) {
					send_special(c, ctx, QUIC_SEND_CONN_CLOSE);
				}
				kr_quic_table_rem(c, table);
				session2_event(c->h.session,
						PROTOLAYER_EVENT_DISCONNECT,
						NULL);
				++removed;
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

	if (removed > 0) {
		kr_log_debug(DOQ, "Closing %zu idle quic connections\n", removed);
	}
}

static bool init_unique_cid(ngtcp2_cid *cid, size_t len, kr_quic_table_t *table)
{
	do {
		if (init_random_cid(cid, len), cid->datalen == 0)
			return false;

	} while (kr_quic_table_lookup(cid, table) != NULL);

	return true;
}

static enum protolayer_iter_cb_result pl_quic_demux_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret = kr_ok();
	struct pl_quic_conn_sess_data *qconn = NULL;
	struct pl_quic_demux_sess_data *demux = sess_data;

	if (kr_fails_assert(ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF)) {
		kr_log_warning(DOQ, "Unexpected payload type in quic-conn\n");
		return protolayer_break(ctx, kr_error(ENOTSUP));
	}

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
	}

	uint64_t now = quic_timestamp();

	ngtcp2_cid_init(&dcid, dec_cids.dcid, dec_cids.dcidlen);
	ngtcp2_cid_init(&scid, dec_cids.scid, dec_cids.scidlen);

	if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
		wire_buf_reset(ctx->payload.wire_buf);
		send_version_negotiation(ctx->payload.wire_buf,
				dec_cids, dcid, scid);
		if (ret >= 0) {
			session2_wrap(demux->h.session, ctx->payload, ctx->comm,
					ctx->req, ctx->finished_cb,
					ctx->finished_cb_baton);
		}

		return protolayer_break(ctx, kr_ok());
	}

	qconn = kr_quic_table_lookup(&dcid, demux->conn_table);
	if (!qconn) {
		/* Clear idle connections */
		// kr_quic_table_sweep(demux->conn_table, ctx);

		if (demux->conn_table->usage >= demux->conn_table->max_conns) {
			kr_log_warning(DOQ,
				"Refusing to open new connection, reached limit of active conns\n");
			/* we might want to inform the client
			 * that limits have been reached */
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

		if (header.tokenlen == 0 /*&& quic_require_retry(table)*/) {
			kr_log_error(DOQ, "received empty header.token\n");
			// ret = -QUIC_SEND_RETRY;
			// goto finish;
		}

		if (header.tokenlen > 0) {
			if (header.token[0] == NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY) {
				ret = ngtcp2_crypto_verify_retry_token(
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
				return protolayer_break(ctx, kr_ok());
			}
		} else {
			memcpy(&odcid, &dcid, sizeof(odcid));
		}

		if (!demux->h.session->outgoing) {
			if (!init_unique_cid(&dcid, 0, demux->conn_table)) {
				kr_log_error(DOQ, "Failed to initialize unique cid (servers choice)\n");
				return protolayer_break(ctx, kr_ok());
			}
		}

		struct kr_quic_conn_param params = {
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

		new_conn_sess->comm_storage = demux->h.session->comm_storage;

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
			ctx->finished_cb,
			ctx->finished_cb_baton);

	quic_conn_mark_used(qconn, demux->conn_table);
	// kr_quic_table_sweep(demux->conn_table, ctx);

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
	kr_require(creds->credentials != NULL);

	if (!quic->conn_table) {
		quic->conn_table = kr_quic_table_new(QUIC_MAX_OPEN_CONNS,
				NGTCP2_MAX_UDP_PAYLOAD_SIZE, creds);

		if (!quic->conn_table) {
			kr_log_error(DOQ, "Failed to create QUIC connection table\n");
			return kr_error(ENOMEM);
		}

		kr_require(quic->conn_table);
	}

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
		}

		conn->cid_pointers--;
		table->usage--;
		free(scids);
	}

	int pos = heap_find(table->expiry_heap, (heap_val_t *)conn);
	heap_delete(table->expiry_heap, pos);
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

	/* received NEW_CONNECTION_ID, update mapping to conn_sess_data */
	if (event == PROTOLAYER_EVENT_CONNECT_UPDATE) {
		kr_require(*baton);
		struct pl_quic_conn_sess_data *conn = *baton;
		if (update_connection_id_map(demux, conn) != kr_ok()) {
			event = PROTOLAYER_EVENT_DISCONNECT;
			/* fallthrough */
		}
	}

	if (event == PROTOLAYER_EVENT_CONNECT_RETIRE) {
		kr_require(*baton);
		struct pl_quic_conn_sess_data *conn = *baton;
		if (remove_connection_id(demux, &conn->dcid, conn) != kr_ok()) {
			event = PROTOLAYER_EVENT_DISCONNECT;
			/* fallthrough */
		}
	}

	if (event == PROTOLAYER_EVENT_CLOSE || event == PROTOLAYER_EVENT_FORCE_CLOSE) {
		while (!EMPTY_HEAP(demux->conn_table->expiry_heap)) {
			struct pl_quic_conn_sess_data *c =
				*(struct pl_quic_conn_sess_data **)HHEAD(
						demux->conn_table->expiry_heap);
			kr_quic_table_rem(c, demux->conn_table);
			session2_event(c->h.session,
					PROTOLAYER_EVENT_DISCONNECT, NULL);
		}

		session2_dec_refs(session);
		return PROTOLAYER_EVENT_CONSUME;
	}

	if (event == PROTOLAYER_EVENT_DISCONNECT ||
			event == PROTOLAYER_EVENT_CONNECT_TIMEOUT) {
		if (*baton == NULL)
			return PROTOLAYER_EVENT_CONSUME;

		struct pl_quic_conn_sess_data *conn = *baton;
		kr_quic_table_rem(conn, demux->conn_table);
		session2_event(conn->h.session, PROTOLAYER_EVENT_DISCONNECT, NULL);
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
