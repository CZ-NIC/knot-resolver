/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/x509.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "quic_conn.h"

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
	/*! Alternative error code, can be used for tests. */
	DOQ_ERROR_RESERVED = 0xd098ea5e
} quic_doq_error_t;

// Macros from knot quic impl
#define SERVER_DEFAULT_SCIDLEN 18
#define QUIC_REGULAR_TOKEN_TIMEOUT 	 (24LLU * 3600LLU * 1000000000LLU)
#define QUIC_SEND_VERSION_NEGOTIATION    NGTCP2_ERR_VERSION_NEGOTIATION
#define QUIC_SEND_RETRY                  NGTCP2_ERR_RETRY
#define QUIC_SEND_STATELESS_RESET        (-NGTCP2_STATELESS_RESET_TOKENLEN)
#define QUIC_SEND_CONN_CLOSE             (-KR_QUIC_HANDLE_RET_CLOSE)
#define QUIC_SEND_EXCESSIVE_LOAD         (-KR_QUIC_ERR_EXCESSIVE_LOAD)
#define BUCKETS_PER_CONNS 8

#define MAX_STREAMS_BIDI 1024
#define MAX_STREAMS_ACTIVE 16

#define MAX_QUIC_PKT_SIZE 65536
#define MAX_QUIC_FRAME_SIZE 65536
#define QUIC_MAX_SEND_PER_RECV	4

#define QUIC_CONN_IDLE_TIMEOUT (3 * NGTCP2_SECONDS)
#define QUIC_HS_IDLE_TIMEOUT   (3 * NGTCP2_SECONDS)

/* HACK adjust pointer of conn->streams head so it points to
 * struct pl_quic_stream_sess_data, this is hacky */
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

/* quic subsession init parameters */
struct kr_quic_conn_param {
	ngtcp2_cid dcid;
	ngtcp2_cid scid;
	ngtcp2_cid odcid;
	ngtcp2_version_cid *dec_cids;
	struct comm_info *comm_storage;
};
struct kr_quic_stream_param {
	int64_t stream_id;
	ngtcp2_conn *conn;
	struct comm_info comm_storage;
};

uint64_t quic_timestamp(void);
bool kr_quic_conn_timeout(struct pl_quic_conn_sess_data *conn, uint64_t *now);
void init_random_cid(ngtcp2_cid *cid, size_t len);
ssize_t send_version_negotiation(struct wire_buf *dest, ngtcp2_version_cid dec_cids,
		ngtcp2_cid dcid, ngtcp2_cid scid);
