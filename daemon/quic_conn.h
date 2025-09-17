/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <bits/types/struct_iovec.h>
#include <stdbool.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
// #include "daemon/tls.h"

#include <gnutls/x509.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
// #include "lib/generic/queue.h"
#include "lib/log.h"
#include "quic_demux.h"
#include "quic_stream.h"
#include "session2.h"
#include "network.h"
#include "lib/resolve.h"
// #include "libknot/quic/quic.h"
#include "libdnssec/random.h"
#include <stdint.h>
#include <contrib/ucw/heap.h>
#include <contrib/ucw/lists.h>
#include "contrib/openbsd/siphash.h"
#include "lib/utils.h"
#include "libdnssec/error.h"

#include <stddef.h>
#include <netinet/in.h>

#include <worker.h>

/** RFC 9250 4.3.  DoQ Error Codes */
typedef enum {
	/*! No error.  This is used when the connection or stream needs to be
	    closed, but there is no error to signal. */
	DOQ_NO_ERROR = 0x0,
	/*! The DoQ implementation encountered an internal error and is
	    incapable of pursuing the transaction or the connection. */
	DOQ_INTERNAL_ERROR = 0x1,
	/*! The DoQ implementation encountered a protocol error and is forcibly
	    aborting the connection. */
	DOQ_PROTOCOL_ERROR = 0x2,
	/*! A DoQ client uses this to signal that it wants to cancel an
	    outstanding transaction. */
	DOQ_REQUEST_CANCELLED = 0x3,
	/*! A DoQ implementation uses this to signal when closing a connection
	    due to excessive load. */
	DOQ_EXCESSIVE_LOAD = 0x4,
	/*!  A DoQ implementation uses this in the absence of a more specific
	     error code. */
	DOQ_UNSPECIFIED_ERROR = 0x5,
	/*! Alternative error code used for tests. */
	DOQ_ERROR_RESERVED = 0xd098ea5e
} quic_doq_error_t;


/** QUIC parameters. */
typedef struct {
	/*! Use QUIC indicator. */
	bool enable;
} quic_params_t;

#define SERVER_DEFAULT_SCIDLEN 18
#define ENABLE_QUIC

#define KR_QUIC_HANDLE_RET_CLOSE	2000
#define KR_QUIC_ERR_EXCESSIVE_LOAD	0x4

// Macros from knot quic impl
#define SERVER_DEFAULT_SCIDLEN 18
#define QUIC_REGULAR_TOKEN_TIMEOUT (24 * 3600 * 1000000000LLU)
#define QUIC_SEND_VERSION_NEGOTIATION    NGTCP2_ERR_VERSION_NEGOTIATION
#define QUIC_SEND_RETRY                  NGTCP2_ERR_RETRY
#define QUIC_SEND_STATELESS_RESET        (-NGTCP2_STATELESS_RESET_TOKENLEN)
#define QUIC_SEND_CONN_CLOSE             (-KR_QUIC_HANDLE_RET_CLOSE)
#define QUIC_SEND_EXCESSIVE_LOAD         (-KR_QUIC_ERR_EXCESSIVE_LOAD)
// this limits the number of un-finished streams per conn
// i.e. if response has been recvd with FIN, it doesn't count
#define MAX_STREAMS_PER_CONN 10

#define MAX_QUIC_FRAME_SIZE 65536

#define QUIC_MAX_SEND_PER_RECV	4

typedef enum {
	KR_QUIC_SEND_IGNORE_LASTBYTE = (1 << 0),
	KR_QUIC_SEND_IGNORE_BLOCKED  = (1 << 1),
} kr_quic_send_flag_t;

struct pl_quic_conn_sess_data;

int kr_quic_send(struct pl_quic_conn_sess_data *conn,
		// void *sess_data,
		struct protolayer_iter_ctx *ctx,
		int action,
		// ngtcp2_version_cid *decoded_cids,
		unsigned max_msgs,
		kr_quic_send_flag_t flags);

typedef struct kr_quic_obuf {
	// struct kr_quic_ucw_list *node;
	struct node node;
	size_t len;
	// struct wire_buf buf;?
	uint8_t buf[];
} kr_quic_obuf_t;

typedef struct kr_quic_cid {
	uint8_t cid_placeholder[32];
	struct pl_quic_conn_sess_data *conn_sess;
	// struct session2 *conn_sess;
	struct kr_quic_cid *next;
} kr_quic_cid_t;

typedef enum {
	KR_QUIC_CONN_HANDSHAKE_DONE = (1 << 0),
	KR_QUIC_CONN_SESSION_TAKEN  = (1 << 1),
	KR_QUIC_CONN_BLOCKED        = (1 << 2),
	KR_QUIC_CONN_AUTHORIZED     = (1 << 3),
} kr_quic_conn_flag_t;

/* parameters that will be passed to pl_quic_conn_sess_init */
struct kr_quic_conn_param {
	ngtcp2_cid dcid;
	ngtcp2_cid scid;
	ngtcp2_cid odcid;
	ngtcp2_version_cid dec_cids;
	struct comm_info comm_storage;
};

typedef struct {
	void *get_conn;
	void *user_data;
} nc_conn_ref_placeholder_t;

struct pl_quic_conn_sess_data {
	struct protolayer_data h;

	/* I do not like this */
	// uint64_t next_expiry;
	// nc_conn_ref_placeholder_t conn_ref;

	nc_conn_ref_placeholder_t conn_ref;

	// // conn_table next conn link
	struct ngtcp2_conn *conn;
	struct kr_quic_conn *next;

	// FIXME might be redundant
	struct kr_quic_table *conn_table;

	// quic_params_t params;
	ngtcp2_settings settings;

	protolayer_iter_ctx_queue_t unwrap_queue;
	protolayer_iter_ctx_queue_t wrap_queue;
	// protolayer_iter_ctx_queue_t resend_queue;
	// struct wire_buf outbuf;

	ngtcp2_cid dcid;
	ngtcp2_cid scid;
	ngtcp2_cid odcid;
	ngtcp2_version_cid dec_cids;

	struct comm_info comm_storage;
	struct comm_addr_storage comm_addr_storage;

	gnutls_session_t tls_session;

	// crypto callbacks
	ngtcp2_crypto_conn_ref crypto_ref;

	// QUIC stream abstraction
	// TODO sentinel for streams?
	struct pl_quic_stream_sess_data *streams;
	// struct kr_quic_stream *streams;
	// number of allocated streams structures
	int16_t streams_count;
	// index of first stream that has complete incomming data to be processed (aka inbuf_fin)
	int16_t stream_inprocess;
	// stream_id/4 of first allocated stream
	int64_t first_stream_id;
	// count of streams with finished queries pending a resolution
	uint16_t streams_pending;

	ngtcp2_ccerr last_error;
	kr_quic_conn_flag_t flags;
	int qlog_fd;

	uint64_t hash_secret[4];
	struct tls_credentials *creds;
	struct gnutls_priority_st *priority;

	// TODO: consider removing
	size_t ibufs_size;
	size_t obufs_size;

	struct wire_buf unwrap_buf;

	struct kr_request *req;
	// quic_state_t state;
};

uint64_t quic_timestamp(void);

struct pl_quic_stream_sess_data *kr_quic_stream_get_process(
		struct pl_quic_conn_sess_data *conn, int64_t *stream_id);

int kr_quic_stream_recv_data(struct pl_quic_conn_sess_data *conn,
		int64_t stream_id, const uint8_t *data, size_t len, bool fin);
