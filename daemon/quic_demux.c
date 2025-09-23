#include "quic_demux.h"
#include "quic_conn.h"
#include "lib/proto.h"
// #include "quic.h"
#include "session2.h"
#include <ctype.h>
#include <fenv.h>
#include <ngtcp2/ngtcp2.h>
#include <string.h>

static int cmp_expiry_heap_nodes(void *c1, void *c2)
{
	if (((struct pl_quic_conn_sess_data *)c1)->h.next_expiry < ((struct pl_quic_conn_sess_data *)c2)->h.next_expiry)
		return -1;

	if (((struct pl_quic_conn_sess_data *)c1)->h.next_expiry > ((struct pl_quic_conn_sess_data *)c2)->h.next_expiry)
		return 1;

	return 0;
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

// struct session2 *kr_quic_table_lookup(const ngtcp2_cid *cid, kr_quic_table_t *table)
struct pl_quic_conn_sess_data *kr_quic_table_lookup(const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	kr_quic_cid_t **pcid = kr_quic_table_lookup2(cid, table);
	assert(pcid != NULL);
	return *pcid == NULL ? NULL : (*pcid)->conn_sess;
}

kr_quic_cid_t **kr_quic_table_insert(struct pl_quic_conn_sess_data *conn_sess,
		const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	kr_quic_cid_t *cidobj = malloc(sizeof(*cidobj));
	if (cidobj == NULL)
		return NULL;

	static_assert(sizeof(*cid) <= sizeof(cidobj->cid_placeholder),
			"insufficient placeholder for CID struct");
	memcpy(cidobj->cid_placeholder, cid, sizeof(*cid));
	cidobj->conn_sess = conn_sess;

	kr_quic_cid_t **addto = table->conns + (hash % table->size);
	cidobj->next = *addto;
	*addto = cidobj;
	table->pointers++;

	return addto;
}

//TODO
// struct pl_quic_demux_sess_data *kr_quic_table_add(ngtcp1_conn *ngconn, const ngtcp2_cid *cid,
//                                  kr_quic_table_t *table)
int kr_quic_table_add(struct pl_quic_conn_sess_data *conn_sess,
		const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	if (!conn_sess || !cid || !table) {
		return kr_error(EINVAL);
	}

	// struct pl_quic_demux_sess_data *conn = calloc(1, sizeof(*conn));
	// if (conn == NULL)
	// 	return NULL;

	// FIXME might be redundant
	conn_sess->conn_table = table;

	/* FIXME magic numbers */
	// conn->conn = ngconn;
	// conn->quic_table = table;
	// conn->stream_inprocess = -1;
	// conn->qlog_fd = -1;
	// wire_buf_init(&conn->unwrap_buf, 1200);

	conn_sess->h.next_expiry = UINT64_MAX;
	if (!heap_insert(table->expiry_heap, (heap_val_t *)conn_sess)) {
		return -1;
	}

	kr_quic_cid_t **addto = kr_quic_table_insert(conn_sess, cid, table);
	if (addto == NULL) {
		heap_delete(table->expiry_heap, heap_find(table->expiry_heap, (heap_val_t *)conn_sess));
		return -2;
	}

	conn_sess->creds = table->creds;
	conn_sess->priority = table->priority;
	conn_sess->hash_secret[0] = table->hash_secret[0];
	conn_sess->hash_secret[1] = table->hash_secret[1];
	conn_sess->hash_secret[2] = table->hash_secret[2];
	conn_sess->hash_secret[3] = table->hash_secret[3];

	table->usage++;
	return kr_ok();
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

	} while (kr_quic_table_lookup(cid, table) != NULL);
	return true;
}

static enum protolayer_iter_cb_result pl_quic_demux_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret = kr_ok();
	// struct session2 *qconn = NULL;
	struct pl_quic_conn_sess_data *qconn = NULL;
	struct pl_quic_demux_sess_data *quic_demux = sess_data;

	// queue_push(quic_demux->unwrap_queue, ctx);

	/* TODO Verify this doesn't leak */
	// struct quic_target *target = malloc(sizeof(struct quic_target));
	// kr_require(target);

	// while (protolayer_queue_has_payload(&quic_demux->unwrap_queue)) {
		// struct protolayer_iter_ctx *data = queue_head(quic_demux->unwrap_queue);
		// queue_pop(quic_demux->unwrap_queue);
		struct protolayer_iter_ctx *data = ctx;

		kr_require(data->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF);

		ngtcp2_version_cid dec_cids;
		ngtcp2_cid odcid;
		ngtcp2_cid dcid;
		ngtcp2_cid scid;

		ret = ngtcp2_pkt_decode_version_cid(&dec_cids,
				wire_buf_data(data->payload.wire_buf),
				wire_buf_data_length(data->payload.wire_buf),
				SERVER_DEFAULT_SCIDLEN);

		if (ret != NGTCP2_NO_ERROR && ret != NGTCP2_ERR_VERSION_NEGOTIATION) {
			kr_log_warning(DOQ, "Could not decode pkt header: (%d) %s \n",
					ret, ngtcp2_strerror(ret));
			return kr_ok();
		}

		uint32_t supported_quic_demux[1] = { NGTCP2_PROTO_VER_V1 };
		ngtcp2_cid_init(&dcid, dec_cids.dcid, dec_cids.dcidlen);
		ngtcp2_cid_init(&scid, dec_cids.scid, dec_cids.scidlen);

		kr_log_info(DOQ, "in demux_unwrap queue loop\n");

		// TODO:
		// if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
		// 	*action = -QUIC_SEND_VERSION_NEGOTIATION;
		// 	return kr_ok();
		// 	// goto finish
		// }

		qconn = kr_quic_table_lookup(&dcid, quic_demux->conn_table);
		if (!qconn) {
			ngtcp2_pkt_hd header = { 0 };
			if (ngtcp2_accept(&header,
				wire_buf_data(data->payload.wire_buf),
				wire_buf_data_length(data->payload.wire_buf))
					!= NGTCP2_NO_ERROR) {
				// TODO stateless reset 
				return protolayer_break(data, -1/*FIXME*/);
			}
			kr_require(header.type == NGTCP2_PKT_INITIAL);
			if (header.tokenlen == 0 /*&& quic_require_retry(table)*/) {
				kr_log_error(DOQ, "received empty header.token\n");
				// ret = -QUIC_SEND_RETRY;
				// goto finish;
			}

			/* if (header.tokenlen > 0) {
				if (header.token[0] == NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY) {
					ret = ngtcp2_crypto_verify_retry_token(
						&odcid, header.token, header.tokenlen,
						(const uint8_t *)table->hash_secret,
						sizeof(table->hash_secret), header.version,
						(const struct sockaddr *)reply->ip_rem,
						addr_len((struct sockaddr_in6 *)reply->ip_rem),
						&dcid, idle_timeout, now // NOTE setting retry token validity to idle_timeout for simplicity
					);
				} else {
					ret = ngtcp2_crypto_verify_regular_token(
						header.token, header.tokenlen,
						(const uint8_t *)table->hash_secret,
						sizeof(table->hash_secret),
						(const struct sockaddr *)reply->ip_rem,
						addr_len((struct sockaddr_in6 *)reply->ip_rem),
						QUIC_REGULAR_TOKEN_TIMEOUT, now
					);
				}
				if (ret != 0) {
					ret = KNOT_EOK;
					goto finish;
				}
			} else*/ {
				memcpy(&odcid, &dcid, sizeof(odcid));
			}

			/* we are the server side so choose our dcid */
			if (!quic_demux->h.session->outgoing) {
				if (!init_unique_cid(&dcid, 0, quic_demux->conn_table)) {
					kr_log_error(DOQ, "Failed to initialize unique cid (servers choice)\n");
					ret = kr_error(-1);
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
				session2_new_child(quic_demux->h.session,
						KR_PROTO_DOQ_CONN,
						&data_param,
						1 /* FIXME */,
						false);

			struct pl_quic_conn_sess_data *conn_sess_data =
				protolayer_sess_data_get_proto(new_conn_sess,
						PROTOLAYER_TYPE_QUIC_CONN);
			kr_quic_table_add(conn_sess_data, &dcid,
					quic_demux->conn_table);

			qconn = conn_sess_data;

			// TODO This never happens (kr_quic_require_retry just returns false)
			// if (header.tokenlen == 0
			// 		&& kr_quic_require_retry(table) /* TBD */) {
			// 	ret = -QUIC_SEND_RETRY;
			// 	goto finish;
			// }

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
			// 	if (ret != 0) {
			// 		// goto finish;
			// 	}

			// TODO store tokenlen to know if the pkt is retry
			// (tokenlen > 0)
		}

		ret = session2_unwrap(qconn->h.session,
				data->payload,
				data->comm,
				data->finished_cb,
				data->finished_cb_baton);
	return protolayer_break(ctx, kr_ok());

}

static enum protolayer_iter_cb_result pl_quic_demux_wrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	return protolayer_continue(ctx);
}

kr_quic_table_t *kr_quic_table_new(size_t max_conns, size_t max_ibufs,
		size_t max_obufs, size_t udp_payload,
		struct tls_credentials *creds)
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

static int pl_quic_demux_sess_init(struct session2 *session, void *sess_data, void *param)
{
	struct pl_quic_demux_sess_data *quic = sess_data;
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

	// wire_buf_init(&quic->outbuf, OUTBUF_SIZE);

	// TODO set setings?

	return 0;
}

void kr_quic_table_rem2(kr_quic_cid_t **pcid, kr_quic_table_t *table)
{
	kr_quic_cid_t *cid = *pcid;
	*pcid = cid->next;
	free(cid);
	table->pointers--;
}


void kr_quic_table_rem(struct pl_quic_conn_sess_data *conn,
		kr_quic_table_t *table)
{
	if (conn == NULL || conn->conn == NULL || table == NULL) {
		return;
	}

	assert(conn->streams_count <= 0);
	assert(conn->obufs_size == 0);

	size_t num_scid = ngtcp2_conn_get_scid(conn->conn, NULL);
	ngtcp2_cid *scids = calloc(num_scid, sizeof(*scids));
	ngtcp2_conn_get_scid(conn->conn, scids);

	for (size_t i = 0; i < num_scid; i++) {
		kr_quic_cid_t **pcid = kr_quic_table_lookup2(&scids[i], table);
		assert(pcid != NULL);
		if (*pcid == NULL) {
			continue;
		}
		assert((*pcid)->conn == conn);
		kr_quic_table_rem2(pcid, table);
	}

	int pos = heap_find(table->expiry_heap, (heap_val_t *)conn);
	heap_delete(table->expiry_heap, pos);

	free(scids);

	table->usage--;
}

// void kr_quic_table_rem(struct pl_quic_conn_sess_data *conn,
// 		kr_quic_table_t *table)
// {
// 	if (conn == NULL || table == NULL)
// 		return;
//
// 	// session2_event(conn->h.session, PROTOLAYER_EVENT_DISCONNECT, NULL);
// 	// session2_event(conn->h.session, PROTOLAYER_EVENT_CLOSE/*maybe FORCE?*/, NULL);
//
// 	// for (ssize_t i = conn->streams_count - 1; i >= 0; i--)
// 	// 	kr_quic_conn_stream_free(conn, (i + conn->first_stream_id) * 4);
//
// 	// assert(conn->streams_count <= 0);
// 	// assert(conn->obufs_size == 0);
//
//
// 	// TODO: in the conn layer
// 	// size_t num_scid = ngtcp2_conn_get_scid(conn->conn, NULL);
// 	// ngtcp2_cid *scids = calloc(num_scid, sizeof(*scids));
// 	// ngtcp2_conn_get_scid(conn->conn, scids);
// 	//
// 	// for (size_t i = 0; i < num_scid && scids; i++) {
// 	// 	kr_quic_cid_t **pcid = kr_quic_table_lookup2(&scids[i], table);
// 	// 	assert(pcid != NULL);
// 	// 	if (*pcid == NULL)
// 	// 		continue;
// 	//
// 	// 	assert((*pcid)->conn == conn);
// 	// 	kr_quic_table_rem2(pcid, table);
//
//
// 	int pos = heap_find(table->expiry_heap, (heap_val_t *)conn);
// 	heap_delete(table->expiry_heap, pos);
//
// 	// wire_buf_deinit(&conn->unwrap_buf);
// 	// gnutls_deinit(conn->tls_session);
// 	// ngtcp2_conn_del(conn->conn);
// 	// conn->conn = NULL;
//
// 	// free(conn);
//
// 	--table->usage;
// }

void kr_quic_table_free(kr_quic_table_t *table)
{
	if (table != NULL) {
		while (!EMPTY_HEAP(table->expiry_heap)) {
			struct pl_quic_conn_sess_data *c =
				*(struct pl_quic_conn_sess_data **)HHEAD(table->expiry_heap);

			kr_quic_table_rem(c, table);
			// kr_quic_cleanup(&c, 1);
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

static int pl_quic_demux_sess_deinit(struct session2 *session, void *data)
{
	struct pl_quic_demux_sess_data *quic = data;
	queue_deinit(quic->unwrap_queue);
	queue_deinit(quic->wrap_queue);
	// currently just loops forever
	kr_quic_table_free(quic->conn_table);
	wire_buf_deinit(&quic->outbuf);

	return kr_ok();
}

static enum protolayer_event_cb_result pl_quic_demux_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	struct pl_quic_demux_sess_data *demux = sess_data;
	kr_log_info(DOQ, "entered QUIC DEMUX E: %d UNWRAP conncount: %d\n",
			event, demux->conn_count);

	if (event == PROTOLAYER_EVENT_CONNECT_UPDATE) {
	}
	if (event == PROTOLAYER_EVENT_CLOSE || event == PROTOLAYER_EVENT_FORCE_CLOSE) {
		pl_quic_demux_sess_deinit(session, sess_data);
	}
	if (event == PROTOLAYER_EVENT_DISCONNECT) {
		/* we have to have the connection we are disconnecting */
		kr_require(baton);
		struct pl_quic_conn_sess_data *conn = *baton;
		kr_quic_table_rem(conn, demux->conn_table);
		session2_event(conn->h.session,
				PROTOLAYER_EVENT_DISCONNECT, NULL);
		return PROTOLAYER_EVENT_CONSUME;
	}

	return PROTOLAYER_EVENT_CONSUME;
}

static enum protolayer_event_cb_result pl_quic_demux_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	struct pl_quic_demux_sess_data *demux = sess_data;
	kr_log_info(DOQ, "entered QUIC DEMUX E WRAP conncount: %d\n",
			demux->conn_count);

	if (event == PROTOLAYER_EVENT_CONNECT_UPDATE) {
	}
	if (event == PROTOLAYER_EVENT_CLOSE || event == PROTOLAYER_EVENT_FORCE_CLOSE) {
		pl_quic_demux_sess_deinit(session, sess_data);
	}
	if (event == PROTOLAYER_EVENT_DISCONNECT) {

	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

__attribute__((constructor))
static void quic_demux_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_QUIC_DEMUX] = (struct protolayer_globals) {
		.sess_size = sizeof(struct pl_quic_demux_sess_data),
		// .iter_size = sizeof(struct ),
		.wire_buf_overhead = MAX_QUIC_FRAME_SIZE,
		// .iter_init = pl_quic_iter_init,
		// .iter_deinit = pl_quic_iter_deinit,
		.sess_init = pl_quic_demux_sess_init,
		.sess_deinit = pl_quic_demux_sess_deinit,
		.unwrap = pl_quic_demux_unwrap,
		.wrap = pl_quic_demux_wrap,
		.event_unwrap = pl_quic_demux_event_unwrap,
		.event_wrap = pl_quic_demux_event_wrap,
		// .request_init = pl_quic_demux_request_init,
	};
}
