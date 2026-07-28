/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <contrib/ucw/heap.h>
#include <contrib/ucw/lists.h>

#include "quic_common.h"
#include "daemon/tls.h"

/** QUIC parameters. */
typedef struct {
	/*! Use QUIC indicator. */
	bool enable;
} quic_params_t;

typedef enum {
	QUIC_STATE_HANDSHAKE_DONE = (1 << 0),
	QUIC_STATE_SESSION_TAKEN  = (1 << 1),
	QUIC_STATE_BLOCKED        = (1 << 2),
	QUIC_STATE_AUTHORIZED     = (1 << 3),
	QUIC_STATE_EPROTO         = (1 << 4),
	QUIC_STATE_CLOSING        = (1 << 5),
	/* Following states prevent connections from writing (retry packet
	 * is an exception, it doesn't require ngtcp2_conn struct). */
	QUIC_STATE_DRAINING       = (1 << 6),
	QUIC_STATE_HS_ABORT       = (1 << 7),
} quic_conn_state_t;

/* Quic connection state set functions */
#define QUIC_SET_DRAINING(conn) \
	(conn)->state |= QUIC_STATE_DRAINING;
#define QUIC_SET_CLOSING(conn) \
	(conn)->state |= QUIC_STATE_CLOSING;
#define QUIC_SET_HS_COMPLETED(conn) \
	(conn)->state |= QUIC_STATE_HANDSHAKE_DONE;
#define QUIC_SET_HS_ABORT(conn) \
	(conn)->state |= QUIC_STATE_HS_ABORT;
#define QUIC_CAN_SEND(conn) \
	((conn)->state < QUIC_STATE_DRAINING)

typedef struct {
	struct ngtcp2_conn *(*get_conn)(ngtcp2_crypto_conn_ref *conn_ref);
	struct pl_quic_conn_sess_data *user_data;
} nc_conn_ref_placeholder_t;

struct kr_quic_stream_list {
	list_t *streams;
	struct session2 *stream_session;
};

struct stream_item {
	node_t n;
	struct session2 *stream_session;
};

struct pl_quic_conn_sess_data {
	struct protolayer_data h;
	nc_conn_ref_placeholder_t conn_ref;
	struct ngtcp2_conn *conn;
	struct kr_quic_conn *next;
	/* queue for streams that received full queries and are ready
	 * to proceed in the unwrap direction */
	queue_t(struct pl_quic_stream_sess_data *) pending_unwrap;
	bool is_server;
	bool retry_sent;
	/* defer can keep the session alive even if the connection timed out or
	 * terminated. To avoid decreasing the refcount more than once in
	 * quic_conn:pl_quic_event_unwrap this boolean value is used. */
	bool disconnected;
	enum protolayer_event_type term_event;
	ngtcp2_cid dcid;
	ngtcp2_cid scid;
	ngtcp2_cid odcid;
	ngtcp2_version_cid dec_cids;
	bool token_present;
	uint8_t secret[32];
	ngtcp2_path *path;
	struct comm_info comm_storage;
	struct comm_addr_storage comm_addr_storage;

	/* last application error
	 * the msg is limited to MAX_REASONLEN bytes */
	ngtcp2_ccerr ccerr;
	uint8_t err_msg_buffer[MAX_REASONLEN];

	/* TLS data */
	gnutls_session_t tls_session;
	struct gnutls_priority_st *priority;
	union {
		struct tls_credentials *server_credentials;
		tls_client_param_t *client_params; /* for TBD client side */
	};

	// crypto callbacks
	ngtcp2_crypto_conn_ref crypto_ref;

	list_t streams;
	// number of allocated streams structures
	int16_t streams_count;
	/* only used by client side */
	int64_t next_stream_id;
	uint64_t finished_streams;
	quic_conn_state_t state;
	size_t cid_pointers;

	kr_quic_table_t *table_ref;
};

/* Iterates over the connections streams attempting to send out
 * any data that failed to get sent previously. Also flushes
 * any messages the connection itself might want to send. */
int quic_flush_streams(struct pl_quic_conn_sess_data *conn);

/* This function handles responses to special states from handle_packet(...),
 * often followed by CONNECTION CLOSE. This function doesn't overwrite the
 * buffer in the provided ctx and takes care of submitting the message
 * to the wrap dirrection cascade.
 * Currently sends special payload to the
 * following QUIC_SEND requests:
 *
 * QUIC_SEND_VERSION_NEGOTIOATION
 *   Response to a client using an unsupported QUIC version.
 *
 * QUIC_SEND_RETRY
 *   sets the conn->state to QUIC_SET_HS_ABORT. Retry packets are sent
 *   for address validation and are a response to the INITIAL packet.
 *   Once the retry packet is sent the connection state is to be destroyed and
 *   the client is expected to send a new INITIAL containing the address
 *   validation token (as a response to the retry packet).
 *
 * QUIC_SEND_CONN_CLOSE
 *   in case the ccerr for this connection is DOQ_NO_ERROR this function will
 *   replace the ccerr with the DoQ error code passed to this function as
 *   the doq_error parameter. If the current ccerr is not DOQ_NO_ERROR the ccerr
 *   will not be changed to ensure more specific error code remains.
 *
 * Returns 0 on success,
 * EINVAL if the requested state was missing some argument,
 * ENOMEM if the function fails to allocate memory for the payload,
 * or other negative error code from some ngtcp2 library function. */
int send_special(ngtcp2_version_cid *dec_cids,
		kr_quic_table_t *table,
		struct protolayer_iter_ctx *ctx, int action,
		struct pl_quic_conn_sess_data *conn,
		struct session2 *session, quic_doq_error_t *doq_error);
struct session2 *setup_quic_stream(struct pl_quic_conn_sess_data *conn);
