/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include "daemon/tls.h"
#include "session2.h"
#include <contrib/ucw/heap.h>
#include <contrib/ucw/lists.h>

/** QUIC parameters. */
typedef struct {
	/*! Use QUIC indicator. */
	bool enable;
} quic_params_t;


#define KR_QUIC_HANDLE_RET_CLOSE	2000
#define KR_QUIC_ERR_EXCESSIVE_LOAD	0x4
#define QUIC_MAX_OPEN_CONNS 1024

typedef enum {
	KR_QUIC_SEND_IGNORE_LASTBYTE = (1 << 0),
	KR_QUIC_SEND_IGNORE_BLOCKED  = (1 << 1),
} kr_quic_send_flag_t;

struct pl_quic_conn_sess_data;

int kr_quic_send(struct pl_quic_conn_sess_data *conn,
		struct protolayer_iter_ctx *ctx,
		int action,
		unsigned max_msgs,
		kr_quic_send_flag_t flags);

typedef struct kr_quic_cid {
	uint8_t cid_placeholder[32];
	struct pl_quic_conn_sess_data *conn_sess;
	struct kr_quic_cid *next;
} kr_quic_cid_t;

typedef enum {
	QUIC_STATE_HANDSHAKE_DONE = (1 << 0),
	QUIC_STATE_SESSION_TAKEN  = (1 << 1),
	QUIC_STATE_BLOCKED        = (1 << 2),
	QUIC_STATE_AUTHORIZED     = (1 << 3),
	QUIC_STATE_EPROTO         = (1 << 4),
	QUIC_STATE_CLOSING        = (1 << 5),
	QUIC_STATE_DRAINING       = (1 << 6),
} quic_conn_state_t;

/* Quic connection state set functions */
#define QUIC_SET_DRAINING(conn) \
	(conn)->state |= QUIC_STATE_DRAINING;
#define QUIC_SET_CLOSING(conn) \
	(conn)->state |= QUIC_STATE_CLOSING;
#define QUIC_SET_HS_COMPLETED(conn) \
	(conn)->state |= QUIC_STATE_HANDSHAKE_DONE;
#define QUIC_CAN_SEND(conn) \
	((conn)->state < QUIC_STATE_DRAINING)

typedef struct {
	void *get_conn;
	void *user_data;
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
	ngtcp2_cid dcid;
	ngtcp2_cid scid;
	ngtcp2_cid odcid;
	ngtcp2_version_cid dec_cids;
	uint8_t secret[32];
	struct comm_info comm_storage;
	struct comm_addr_storage comm_addr_storage;

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
	uint64_t finished_streams;
	quic_conn_state_t state;
	size_t cid_pointers;
};

int send_special(struct pl_quic_conn_sess_data *conn,
		struct protolayer_iter_ctx *ctx, int action);
