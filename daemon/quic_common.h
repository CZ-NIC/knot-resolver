/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "kresconfig.h"

#if !ENABLE_QUIC
#else

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/x509.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <ucw/lists.h>

#include "session2.h"
#include "network.h"

/* option to turn of ngtcp2 log which is by default enabled for log_level = debug */
#define DEBUG_NGTCP2 false

/** RFC 9250 4.3 DoQ Error Codes for use as application protocol error codes */
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
	// DOQ_ERROR_RESERVED = 0xd098ea5e
} quic_doq_error_t;

// Macros from knot quic impl
#define SERVER_DEFAULT_SCIDLEN 18
#define QUIC_REGULAR_TOKEN_TIMEOUT       (24LLU * 3600LLU * 1000000000LLU)
#define QUIC_SEND_VERSION_NEGOTIATION    NGTCP2_ERR_VERSION_NEGOTIATION
#define QUIC_SEND_RETRY                  NGTCP2_ERR_RETRY
#define QUIC_SEND_STATELESS_RESET        (-NGTCP2_STATELESS_RESET_TOKENLEN)
#define QUIC_SEND_CONN_CLOSE             (-2000)
/* Returning this value from handle_packet has to be accompanied
 * by timer startup (if not already running). Otherwise the connection
 * might linger in the table until the DoQ endpoint terminates.
 * see NGTCP2_ERR_DROP_CONN switch case in handle_packet */
#define QUIC_SEND_NONE                   (-2001)

/* maximum message length for messages used in ccerr */
#define MAX_REASONLEN 128
#define BUCKETS_PER_CONNS 8
#define DOQ_MAX_MESSAGE_SIZE 65535
#define DOQ_MAX_STREAM_DATA (DOQ_MAX_MESSAGE_SIZE + sizeof(uint16_t))
#define QUIC_MAX_SEND_PER_RECV	4
/* A connection can reach a state where the internal ngtcp2 state machine is
 * not waiting for any event. In such a case the ngtcp2_conn_get_expiry
 * returns UINT64_MAX => meaning no timer event. If the peer abruptly
 * stops communicating in such a state the connection remains in the table.
 * We set the timer to the QUIC_MAX_TIMEOUT to assure
 * that every connection will terminate within a reasonable time period.
 * NOTE These constants are in nanoseconds! use quic_ns_to_ms_ceil(...)
 * when using them in libuv function calls.*/
#define QUIC_MAX_IDLE_TIMEOUT (15 * NGTCP2_SECONDS)
#define QUIC_CONN_IDLE_TIMEOUT (5 * NGTCP2_SECONDS)
#define QUIC_HS_IDLE_TIMEOUT   (4 * NGTCP2_SECONDS)


#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

typedef enum {
	KNOT_QUIC_TABLE_CLIENT_ONLY = (1 << 0),
} kr_quic_table_flag_t;

typedef struct kr_quic_cid {
	uint8_t cid_placeholder[32];
	struct pl_quic_conn_sess_data *conn_sess;
	struct kr_quic_cid *next;
} kr_quic_cid_t;

typedef struct kr_quic_table {
	kr_quic_table_flag_t flags;
	/* general "settings" for connections */
	size_t size;
	size_t usage;
	size_t pointers;
	size_t max_conns;
	size_t udp_payload_limit;
	void (*log_cb)(const char *);
	const char *qlog_dir;
	uint64_t hash_secret[4];
	struct tls_credentials *creds;
	struct gnutls_priority_st *priority;
	list_t conn_list;
	struct kr_quic_cid *conns[];
} kr_quic_table_t;

/* quic subsession init parameters */
struct kr_quic_conn_param {
	bool retry_sent;
	kr_quic_table_t *table;
	ngtcp2_cid dcid;
	ngtcp2_cid scid;
	ngtcp2_cid odcid;
	ngtcp2_version_cid *dec_cids;
	bool token_present;
	struct comm_info *comm_storage;
};

struct kr_quic_stream_param {
	int64_t stream_id;
	ngtcp2_conn *conn;
};

void quic_set_draining(struct pl_quic_conn_sess_data *conn);
void quic_set_closing(struct pl_quic_conn_sess_data *conn);
void quic_set_hs_completed(struct pl_quic_conn_sess_data *conn);
/* check that connection is not in DRAINING state */
bool quic_not_draining(struct pl_quic_conn_sess_data *conn);
/* check that handshake has finished and connection is not in DRAINING state */
bool quic_can_send(struct pl_quic_conn_sess_data *conn);
bool kr_quic_conn_timeout(struct pl_quic_conn_sess_data *conn, uint64_t *now);

uint64_t cid2hash(const ngtcp2_cid *cid, kr_quic_table_t *table);

/* ngtcp2 operates with ns whilst libuv uses ms. Simple inline ceil converter. */
uint64_t quic_ns_to_ms_ceil(uint64_t ns);

/* Closing/draining state PTO based timeout recommended by ngtcp2. The returned
 * value is the time in ms that the connection state should be available for.
 * Combine with quic_set_idle_timeout to take care of conn state
 * teardown once the closing/draining state is reached. */
uint64_t quic_get_closing_timeout(uint64_t pto_ns);

/* start uv_timer with timeout equal to ms, this timer is to be used
 * only during the handshake, after that the negotiated max_idle_timeout
 * will be used. Returns 0 or EINVAL */
int quic_set_hs_timeout(struct session2 *s, uint64_t ms);

/* Only used when the connection entered closing/draining state
 * and we have to wait 3 * PTO before freeing the connection (e.g. session). */
int quic_set_idle_timeout(struct session2 *s, uint64_t ms);

/* Call this every time a bunch of writes are executed.
 * The next expiry is retrieved and the connection timer is reset
 * so ngtcp2 library can schedule next event */
void quic_reset_expiry(struct pl_quic_conn_sess_data *conn);

int kr_quic_table_rem2(kr_quic_cid_t **pcid, kr_quic_table_t *table);

/* Function to forcefully terminate the connection because the peer
 * violated protocol specification, see RFC 9250 4.3.3 Protocol Errors. */
int doq_protocol_error(struct session2 *stream, const char *msg);

/* Set the connection ccerr to type TRANSPORT with the error code
 * containing the tls alert. The error code is calculated as
 * 0x100 | <the tls alert>  (see RFC 9001 4.8. TLS Errors). */
int set_tls_error(struct pl_quic_conn_sess_data *conn,
		quic_doq_error_t *error_code,
		const uint8_t *msg, size_t msglen);

/* This function sets the ccerr type to APPLICATION and the error_code to
 * the provided error_code. msg can be NULL, if so set mgslen to 0.
 * see RFC 9250 4.3 DoQ Error Codes */
int set_application_error(struct pl_quic_conn_sess_data *conn,
		quic_doq_error_t error_code, const uint8_t *msg, size_t msglen);

/* Inserts another cid into the table. This cid will point
 * to the connection provided via the conn parameter. Can be called
 * multiple times on the same connection (i.e. use when new cid for an
 * existing connection is required). */
kr_quic_cid_t **kr_quic_table_insert(struct pl_quic_conn_sess_data *conn,
		const ngtcp2_cid *cid, kr_quic_table_t *table);

/* Registeres a new connection in the table and the connection list.
 * Only call once when the connection is created. Calls kr_quic_table_insert
 * to add a reference from cid to the connection. */
int kr_quic_table_add(struct pl_quic_conn_sess_data *conn_sess,
		const ngtcp2_cid *cid, kr_quic_table_t *table);

/* Due to the multi-protolayer-group design of DoQ the session2_get_peer
 * function is not usable for DoQ sessions. This function locates
 * the KR_PROTO_DOQ_CONN session (if applicable) and returns
 * comm_addr stored in the sess_data. Returns NULL if the data is missing
 * or the input session is not valid for this lookup. */
const struct sockaddr *quic_get_peer(struct session2 *s);

int init_unique_cid(ngtcp2_cid *cid, size_t len, kr_quic_table_t *table);

int init_random_cid(ngtcp2_cid *cid, size_t len);

uint64_t quic_timestamp(void);

kr_quic_cid_t **kr_quic_table_lookup2(const ngtcp2_cid *cid,
		kr_quic_table_t *table);

struct pl_quic_conn_sess_data *kr_quic_table_lookup(const ngtcp2_cid *cid,
		kr_quic_table_t *table);

/* Writes a retry packer into the buffer pointer to by dest and sends
 * it into the protolayer cascade in the wrap direction.
 * Since this function can be called from different contexts and sides
 * of the connection dec_cids and conn are exclusive parameters;
 * only one has to be NULL. dec_cids one is used when the function call
 * is a response to an initial packet with no existing connection. */
int write_retry_packet(struct wire_buf *dest, kr_quic_table_t *table,
		const struct sockaddr *src_addr, ngtcp2_version_cid *dec_cids,
		struct pl_quic_conn_sess_data *conn);
#endif
