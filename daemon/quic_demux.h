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
#include "quic_conn.h"

#include <gnutls/x509.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "lib/generic/queue.h"
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

#define SERVER_DEFAULT_SCIDLEN 18

// struct kr_quic_conn;
// typedef struct kr_quic_cid {
// 	uint8_t cid_placeholder[32];
// 	struct session2 *conn_sess;
// 	struct kr_quic_cid *next;
// } kr_quic_cid_t;

typedef enum {
	KNOT_QUIC_TABLE_CLIENT_ONLY = (1 << 0),
} kr_quic_table_flag_t;

// struct kr_quic_conn_exp {
// 	int heap_node_placeholder; // MUST be first field of the struct
// 	uint64_t next_expiry;
// }

typedef struct kr_quic_table {
	kr_quic_table_flag_t flags;
	/* general "settings" for connections */
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


typedef struct pl_quic_demux_sess_data {
	struct protolayer_data h;
	// quic_params_t params;
	ngtcp2_settings settings;

	uint32_t conn_count;
	protolayer_iter_ctx_queue_t unwrap_queue;
	protolayer_iter_ctx_queue_t wrap_queue;
	// protolayer_iter_ctx_queue_t resend_queue;
	struct wire_buf outbuf;

	struct kr_quic_table *conn_table;
	uint64_t first_stream_id;

	struct kr_request *req;
	// quic_state_t state;
} pl_quic_demux_sess_data_t;
