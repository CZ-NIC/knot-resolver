/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdbool.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
// #include "daemon/tls.h"

#include <gnutls/x509.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "lib/log.h"
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


#define MAX_QUIC_FRAME_SIZE 65536

typedef enum {
	CLOSED,    // Initialized
	CONNECTED, // RTT-0
	VERIFIED,  // RTT-1
} quic_state_t;


/*! \brief QUIC parameters. */
typedef struct {
	/*! Use QUIC indicator. */
	bool enable;
} quic_params_t;

#define SERVER_DEFAULT_SCIDLEN 18
#define ENABLE_QUIC


// Macros from knot quic impl
#define SERVER_DEFAULT_SCIDLEN 18
#define QUIC_REGULAR_TOKEN_TIMEOUT (24 * 3600 * 1000000000LLU)
#define QUIC_SEND_VERSION_NEGOTIATION    NGTCP2_ERR_VERSION_NEGOTIATION
#define QUIC_SEND_RETRY                  NGTCP2_ERR_RETRY
#define QUIC_SEND_STATELESS_RESET        (-NGTCP2_STATELESS_RESET_TOKENLEN)
#define QUIC_SEND_CONN_CLOSE             (-KNOT_QUIC_HANDLE_RET_CLOSE)
#define QUIC_SEND_EXCESSIVE_LOAD         (-KNOT_QUIC_ERR_EXCESSIVE_LOAD)
#define MAX_STREAMS_PER_CONN 10 // this limits the number of un-finished streams per conn (i.e. if response has been recvd with FIN, it doesn't count)

typedef enum {
	KR_QUIC_SEND_IGNORE_LASTBYTE = (1 << 0),
	KR_QUIC_SEND_IGNORE_BLOCKED  = (1 << 1),
} kr_quic_send_flag_t;

struct quic_ctx;
// TODO maybe rename to something more in line with iter_data
struct pl_quic_state {
	struct protolayer_data h;
	struct quic_ctx *quic_ctx;
	/* struct ortt_ NOTE: Or some other data */ ;
};

struct kr_quic_conn;
typedef struct kr_quic_cid {
	uint8_t cid_placeholder[32];
	struct kr_quic_conn *conn;
	struct kr_quic_cid *next;
} kr_quic_cid_t;

typedef enum {
	KNOT_QUIC_TABLE_CLIENT_ONLY = (1 << 0),
} kr_quic_table_flag_t;

typedef struct {
	void *get_conn;
	void *user_data;
} nc_conn_ref_placeholder_t;

typedef struct kr_quic_table {
	kr_quic_table_flag_t flags;
	size_t size;
	size_t usage;
	size_t pointers;
	size_t max_conns;
	size_t ibufs_max;
	size_t obufs_max;
	size_t ibufs_size;
	size_t obufs_size;
	size_t udp_payload_limit;
	void (*log_cb)(const char *);
	const char *qlog_dir;
	uint64_t hash_secret[4];
	struct tls_credentials *creds;
	struct gnutls_priority_st *priority;
	struct heap *expiry_heap;
	kr_quic_cid_t *conns[];
} kr_quic_table_t;

typedef struct kr_quic_obuf {
	/*ucw_*/node_t node;
	size_t len;
	// struct wire_buf buf;?
	char buf[];
} kr_quic_obuf_t;

typedef enum {
	KR_QUIC_CONN_HANDSHAKE_DONE = (1 << 0),
	KR_QUIC_CONN_SESSION_TAKEN  = (1 << 1),
	KR_QUIC_CONN_BLOCKED        = (1 << 2),
	KR_QUIC_CONN_AUTHORIZED     = (1 << 3),
} kr_quic_conn_flag_t;

typedef struct kr_tcp_inbufs_upd_res {
	size_t n_inbufs;
	struct kr_tcp_inbufs_upd_res *next;
	struct iovec inbufs[];
} kr_tcp_inbufs_udp_res_t;

typedef struct kr_quic_stream {
	/** the inbuf for small, singlepacket messages
	 * while the latter is for larger comunications, but still... */
	struct iovec inbuf;
	struct kr_tcp_inbufs_upd_res *inbufs;

	size_t firstib_consumed;
	/*ucw_*/list_t outbufs;
	size_t obufs_size;

	kr_quic_obuf_t *unsent_obuf;
	size_t first_offset;
	size_t unsent_offset;
} kr_quic_stream_t;

typedef struct quic_ctx {
	ngtcp2_crypto_conn_ref conn_ref;

	// // Parameters
	// quic_params_t params;
	//
	// // Context
	// ngtcp2_settings settings;
	// struct {
	// 	int64_t id;
	// 	uint64_t out_ack;
	// 	struct iovec in_buffer;
	// 	struct knot_tcp_inbufs_upd_res *in_parsed;
	// 	size_t in_parsed_it;
	// 	size_t in_parsed_total;
	// } stream;
	// ngtcp2_ccerr last_err;
	// uint8_t secret[32];

	// tls_ctx_t *tls;

	// convenient struct to store Connection ID, its associated path, and stateless reset token.
	ngtcp2_cid_token dcid_token;
	ngtcp2_cid_token scid_token;
	// ngtcp2_cid_token odcid_token; // maybe?
	ngtcp2_conn *conn;
	ngtcp2_pkt_info pi;
	ngtcp2_path path;
	quic_state_t state;
} quic_ctx_t;

typedef struct kr_quic_conn {
	int heap_node_placeholder; // MUST be first field of the struct
	uint64_t next_expiry;

	 // placeholder for internal struct ngtcp2_crypto_conn_ref
	nc_conn_ref_placeholder_t conn_ref;

	// conn_table next conn link
	struct ngtcp2_conn *conn;
	struct kr_quic_conn *next;

	gnutls_session_t tls_session;

	// crypto callbacks
	ngtcp2_crypto_conn_ref crypto_ref;

	 // QUIC stream abstraction
	kr_quic_stream_t *streams;
	 // number of allocated streams structures
	int16_t streams_count;
	 // index of first stream that has complete incomming data to be processed (aka inbuf_fin)
	int16_t stream_inprocess;
	 // stream_id/4 of first allocated stream
	int64_t first_stream_id;

	ngtcp2_ccerr last_error;
	kr_quic_conn_flag_t flags;
	int qlog_fd;

	// TODO: consider removing
	size_t ibufs_size;
	size_t obufs_size;

	// TODO: Definitelly move
	ngtcp2_pkt_info pi;

	// back-pointer
	struct kr_quic_table *quic_table;
} kr_quic_conn_t;

typedef struct pl_quic_sess_data {
	struct protolayer_data h;
	// ngtcp2_conn *conns; This one might be wrong
	// ngtcp2_crypto_conn_ref conn_ref;
	// Parameters
	quic_params_t params;
	ngtcp2_settings settings;

	// Context
	// struct {
	// 	int64_t id;
	// 	uint64_t out_ack;
	// 	struct iovec in_buffer;
	// 	struct knot_tcp_inbufs_upd_res *in_parsed;
	// 	size_t in_parsed_it;
	// 	size_t in_parsed_total;
	// } stream;
	// ngtcp2_ccerr last_err;
	// uint8_t secret[32];

	uint32_t conn_count;
	protolayer_iter_ctx_queue_t unwrap_queue;
	protolayer_iter_ctx_queue_t wrap_queue;

	kr_quic_table_t *conn_table;

	struct kr_request *req;
	quic_state_t state;
	// struct wire_buf wire_buf;
} pl_quic_sess_data_t;
