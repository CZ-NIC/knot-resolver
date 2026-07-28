/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <ngtcp2/ngtcp2.h>
#include <uv.h>
#include "contrib/openbsd/siphash.h"
#include "lib/dnssec.h"

#include "quic_common.h"
#include "lib/proto.h"
#include "quic_conn.h"
#include "session2.h"
#include "network.h"

void inline quic_set_draining(struct pl_quic_conn_sess_data *conn)
{
	conn->state |= QUIC_STATE_DRAINING;
}

void inline quic_set_closing(struct pl_quic_conn_sess_data *conn)
{
	conn->state |= QUIC_STATE_CLOSING;
}

void inline quic_set_hs_completed(struct pl_quic_conn_sess_data *conn)
{
	conn->state |= QUIC_STATE_HANDSHAKE_DONE;
}

bool inline quic_not_draining(struct pl_quic_conn_sess_data *conn)
{
	return conn->state < QUIC_STATE_DRAINING;
}

bool inline quic_can_send(struct pl_quic_conn_sess_data *conn)
{
	return conn->state >= QUIC_STATE_HANDSHAKE_DONE
		&& conn->state < QUIC_STATE_DRAINING;
}

int quic_configuration_set(void)
{
	if (kr_fails_assert(the_network)) {
		return kr_error(EINVAL);
	}

	if (the_network->quic_params) {
		return kr_ok();
	}

	struct net_quic_params *quic_params = calloc(1, sizeof(*quic_params));
	if (quic_params == NULL) {
		return kr_error(ENOMEM);
	}

	the_network->quic_params = quic_params;
	/* Default values */
	the_network->quic_params->require_retry = false;
	the_network->quic_params->max_streams = 16;
	the_network->quic_params->max_conns = 1024;
	return kr_ok();
}

int quic_configuration_free(struct net_quic_params *quic_params)
{
	if (quic_params) {
		free(quic_params);
	}
	return kr_ok();
}

uint64_t quic_timestamp(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;

	return ((uint64_t)ts.tv_sec * NGTCP2_SECONDS) + (uint64_t)ts.tv_nsec;
}

// void quic_hs_timeout(uv_timer_t *timer)
// {
// 	struct session2 *s = timer->data;
// 	session2_timer_stop(s);
//
// 	struct session2 *root = session2_get_root(s);
// 	struct pl_quic_conn_sess_data *conn =
// 		protolayer_sess_data_get_proto(s, PROTOLAYER_TYPE_QUIC_CONN);
// 	session2_event(root, PROTOLAYER_EVENT_CONNECT_TIMEOUT, conn);
// }
//
// static void quic_idle_timeout(uv_timer_t *timer)
// {
// 	struct session2 *s = timer->data;
// 	struct pl_quic_conn_sess_data *conn =
// 		protolayer_sess_data_get_proto(s, PROTOLAYER_TYPE_QUIC_CONN);
// 	struct session2 *demux = session2_get_root(s);
// 	uint64_t now = quic_timestamp();
// 	int ret = ngtcp2_conn_handle_expiry(conn->conn, now);
// 	if (ret == NGTCP2_ERR_IDLE_CLOSE) {
// 		/* idle equal max_idle_timeout, don't send CONNECTION_CLOSE */
// 		quic_set_draining(conn);
// 		session2_event(demux, PROTOLAYER_EVENT_GENERAL_TIMEOUT, conn);
// 	} else if (ret < 0) {
// 		quic_set_closing(conn);
// 		session2_event(demux, PROTOLAYER_EVENT_GENERAL_TIMEOUT, conn);
// 	} else {
// 		/* ngtcp2_conn_writev_stream should be scheduled
// 		 * see https://nghttp2.org/ngtcp2/ngtcp2_conn_handle_expiry.html#c.ngtcp2_conn_handle_expiry */
// 	}
// }
//
// int quic_set_timeout(struct session2 *s, uint64_t ms, uv_timer_cb timeout_cb)
// {
// 	uv_timer_stop(&s->timer);
// 	return uv_timer_start(&s->timer, timeout_cb, ms, ms);
// }
//
// int quic_set_hs_timeout(struct session2 *s, uint64_t ms)
// {
// 	return quic_set_timeout(s, ms, quic_hs_timeout);
// }
//
// int quic_set_idle_timeout(struct session2 *s, uint64_t ms)
// {
// 	return quic_set_timeout(s, ms, quic_idle_timeout);
// }
//
// void quic_reset_expiry(struct pl_quic_conn_sess_data *conn)
// {
// 	kr_require(conn);
// 	struct session2 *s = conn->h.session;
// 	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn->conn);
//
// 	/* In case timeout is set to 0 and the peer agrees => no timeout */
// 	if (expiry == UINT64_MAX) {
// 		uv_timer_stop(&s->timer);
// 		/* In QUICv1 the max_idle_timeout cat NOT be
// 		 * changed after initial negotiation. */
// 		return;
// 	}
//
// 	/* only fails if UV_HANDLE_CLOSING or the handle->cb == NULL */
// 	if (uv_timer_again(&s->timer) != 0) {
// 		session2_event(s, PROTOLAYER_EVENT_FORCE_CLOSE, conn);
// 	}
// }

inline uint64_t quic_ns_to_ms_ceil(uint64_t ns)
{
	return (ns + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS;
}

inline uint64_t quic_get_closing_timeout(uint64_t pto_ns)
{
	/* see: https://nghttp2.org/ngtcp2/programmers-guide.html#the-closing-and-draining-state */
	return 3 * quic_ns_to_ms_ceil(pto_ns);
}

void quic_hs_timeout(uv_timer_t *timer)
{
	struct session2 *s = timer->data;
	session2_timer_stop(s);

	struct pl_quic_conn_sess_data *conn =
		protolayer_sess_data_get_proto(s, PROTOLAYER_TYPE_QUIC_CONN);
	session2_event(conn->h.session, PROTOLAYER_EVENT_CONNECT_TIMEOUT, NULL);
}

void quic_handle_timeout(uv_timer_t *timer)
{
	struct session2 *s = timer->data;
	struct pl_quic_conn_sess_data *conn =
		protolayer_sess_data_get_proto(s, PROTOLAYER_TYPE_QUIC_CONN);

	if (conn->state & QUIC_STATE_CLOSING) {
		session2_close(conn->h.session);
		return;
	} else if (conn->state & QUIC_STATE_DRAINING) {
		session2_force_close(conn->h.session);
		return;
	}

	uint64_t now = quic_timestamp();
	int ret = ngtcp2_conn_handle_expiry(conn->conn, now);
	if (ret != 0) {
		kr_log_debug(DOQ, "Result of ngtcp2_conn_handle_expiry: %s (%d)\n",
				ngtcp2_strerror(ret), ret);
	}
	if (ret == NGTCP2_ERR_IDLE_CLOSE) {
		session2_force_close(s);
	} else if (ret == NGTCP2_ERR_HANDSHAKE_TIMEOUT) {
		session2_event(s, PROTOLAYER_EVENT_CONNECT_TIMEOUT, NULL);
	} else if (ret < 0) {
		QUIC_SET_CLOSING(conn);
		session2_close(s);
	} else {
		quic_flush_streams(conn);
		/* let the connection itself send whatever data it needs to */
		session2_wrap(s, protolayer_payload_wire_buf(&s->wire_buf, true),
				&conn->comm_storage, NULL, NULL, NULL);
	}
}

int quic_set_timeout(struct session2 *s, uint64_t ms, uv_timer_cb timeout_cb)
{
	uv_timer_stop(&s->timer);
	return uv_timer_start(&s->timer, timeout_cb, ms, 0);
}

int quic_set_hs_timeout(struct session2 *s, uint64_t ms)
{
	return quic_set_timeout(s, ms, quic_hs_timeout);
}

int quic_set_idle_timeout(struct session2 *s, uint64_t ms)
{
	return quic_set_timeout(s, ms, quic_handle_timeout);
}

void quic_reset_expiry(struct pl_quic_conn_sess_data *conn)
{
	kr_require(conn);
	struct session2 *s = conn->h.session;
	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn->conn);

	uv_timer_stop(&s->timer);
	if (expiry == UINT64_MAX) {
		uv_timer_start(&s->timer, quic_handle_timeout,
				QUIC_MAX_IDLE_TIMEOUT, 0);
		return;
	}
	uint64_t now = quic_timestamp();
	if (expiry > now) {
		uv_timer_start(&s->timer, quic_handle_timeout,
				quic_ns_to_ms_ceil(expiry - now), 0);
	} else {
		uv_timer_start(&s->timer, quic_handle_timeout, 0, 0);
	}
}

int init_random_cid(ngtcp2_cid *cid, size_t len)
{
	if (len == 0)
		len = SERVER_DEFAULT_SCIDLEN;

	uint8_t buf[NGTCP2_MAX_CIDLEN];
	if (len > sizeof(buf)) {
		len = sizeof(buf);
	}

	int ret;
	if ((ret = dnssec_random_buffer(buf, len)) == 0) {
		ngtcp2_cid_init(cid, buf, len);
	}

	return ret;
}

uint64_t cid2hash(const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	SIPHASH_CTX ctx;
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)(table->hash_secret));
	SipHash24_Update(&ctx, cid->data, MIN(cid->datalen, 8));
	uint64_t ret = SipHash24_End(&ctx);

	return ret;
}

kr_quic_cid_t **kr_quic_table_lookup2(const ngtcp2_cid *cid,
		kr_quic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	kr_quic_cid_t **res = table->conns + (hash % table->size);
	while (*res != NULL && !ngtcp2_cid_eq(cid,
				(const ngtcp2_cid *)(*res)->cid_placeholder)) {
		res = &(*res)->next;
	}

	return res;
}

struct pl_quic_conn_sess_data *kr_quic_table_lookup(const ngtcp2_cid *cid,
		kr_quic_table_t *table)
{
	kr_quic_cid_t **pcid = kr_quic_table_lookup2(cid, table);
	return *pcid == NULL ? NULL : (*pcid)->conn_sess;
}

kr_quic_cid_t **kr_quic_table_insert(struct pl_quic_conn_sess_data *conn,
		const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	if (kr_fails_assert(conn && cid && table)) {
		return NULL;
	}

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
	if (kr_fails_assert(conn_sess && cid && table)) {
		return kr_error(EINVAL);
	}

	conn_sess->h.heap_value = UINT64_MAX;
	if (!heap_insert(table->expiry_heap, (heap_val_t *)conn_sess)) {
		return kr_error(ENOMEM);
	}

	kr_quic_cid_t **addto = kr_quic_table_insert(conn_sess, cid, table);
	if (addto == NULL) {
		heap_delete(table->expiry_heap, heap_find(table->expiry_heap,
					(heap_val_t *)conn_sess));
		return kr_error(ENOMEM);
	}

	table->usage++;
	return kr_ok();
}

int kr_quic_table_rem2(kr_quic_cid_t **pcid, kr_quic_table_t *table)
{
	kr_quic_cid_t *cid = *pcid;
	*pcid = cid->next;
	cid->conn_sess->cid_pointers--;
	free(cid);
	table->pointers--;

	return kr_ok();
}

int set_tls_error(struct pl_quic_conn_sess_data *conn,
		quic_doq_error_t *error_code,
		const uint8_t *msg, size_t msglen)
{
	if (kr_fails_assert(conn && msglen < 128))
		return kr_error(EINVAL);

	/* Not redundant! ngtcp2 doesn't memcpy the message.
	 * msgs on the stack could therefore cause stack use after return
	 * once ngtcp2_conn_writev_stream is called. */
	if (msg && msglen > 0) {
		memcpy(&conn->err_msg_buffer, msg, msglen);
	}

	*error_code = 0x100 | ngtcp2_conn_get_tls_alert(conn->conn);

	ngtcp2_ccerr_set_tls_alert(&conn->ccerr,
			ngtcp2_conn_get_tls_alert(conn->conn),
			conn->err_msg_buffer, msglen);

	return kr_ok();
}

int set_application_error(struct pl_quic_conn_sess_data *conn,
		quic_doq_error_t error_code, const uint8_t *msg, size_t msglen)
{
	if (kr_fails_assert(conn && msglen < 128))
		return kr_error(EINVAL);

	/* Not redundant! ngtcp2 doesn't memcpy the message.
	 * msgs on the stack could therefore cause stack use after return
	 * once ngtcp2_conn_writev_stream is called. */
	if (msg && msglen > 0) {
		memcpy(&conn->err_msg_buffer, msg, msglen);
	}

	ngtcp2_ccerr_set_application_error(&conn->ccerr, error_code,
			conn->err_msg_buffer, msglen);

	return kr_ok();
}

int init_unique_cid(ngtcp2_cid *cid, size_t len, kr_quic_table_t *table)
{
	do {
		if (init_random_cid(cid, len) != 0)
			return -1;

	} while (kr_quic_table_lookup(cid, table) != NULL);

	return 0;
}

int write_retry_packet(struct wire_buf *dest, kr_quic_table_t *table,
		ngtcp2_version_cid *dec_cids,
		const struct sockaddr *src_addr)
{
	ngtcp2_cid odcid;
	ngtcp2_cid oscid;
	ngtcp2_cid retry_scid;

	ngtcp2_cid_init(&odcid, dec_cids->dcid, dec_cids->dcidlen);
	ngtcp2_cid_init(&oscid, dec_cids->scid, dec_cids->scidlen);
	init_random_cid(&retry_scid, 0);
	if (init_unique_cid(&retry_scid, 0, table) != 0) {
		kr_log_debug(DOQ, "Failed to initialize unique cid for Retry packet\n");
		return -1;
	}

	uint8_t retry_token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2];
	uint64_t now = quic_timestamp();

	if (kr_fails_assert(src_addr->sa_family != AF_UNIX))
		return -1;  // too long addr; silence analyzers
	int ret = ngtcp2_crypto_generate_retry_token2(
		retry_token, (const uint8_t *)table->hash_secret,
		sizeof(table->hash_secret), dec_cids->version,
		src_addr, kr_sockaddr_len(src_addr),
		&retry_scid, &odcid, now);

	if (ret < 0) {
		kr_log_debug(DOQ, "Failed to generate retry token\n");
		return ret;
	}

	ret = ngtcp2_crypto_write_retry(
		wire_buf_free_space(dest),
		wire_buf_free_space_length(dest),
		dec_cids->version, &oscid,
		&retry_scid, &odcid,
		retry_token, ret
	);

	return ret;
}
