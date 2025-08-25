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

#define MAX_STREAMS_PER_CONN 10
#define MAX_QUIC_FRAME_SIZE 65536

typedef struct kr_quic_obuf {
	// struct kr_quic_ucw_list *node;
	struct node node;
	size_t len;
	// struct wire_buf buf;?
	uint8_t buf[];
} kr_quic_obuf_t;

struct kr_quic_conn;
typedef struct kr_quic_cid {
	uint8_t cid_placeholder[32];
	struct session2 *conn_sess;
	struct kr_quic_cid *next;
} kr_quic_cid_t;

struct kr_quic_stream {
	// struct iovec inbuf;
	struct wire_buf pers_inbuf;
	// struct kr_tcp_inbufs_upd_res *inbufs;

	size_t firstib_consumed;
	/* stores data that has been sent out and awaits acknowledgement and
	 * data that has just been created and is waiting to be sent out */
	/* ucw */struct list outbufs;

	// /* ucw */struct kr_quic_ucw_list outbufs;
	// /*ucw_*/queue_t(struct kr_quic_obuf) outbufs;
	// /*ucw_*/list_t outbufs;

	/* FIXME Properly implement everywhere
	 * kr_quic_stream_ack_data uses this to check the
	 * stream is really finished, without proper handling
	 * no stream will ever be deleted */
	/* size of all outbufs */
	size_t obufs_size;

	/* pointer to somewhere in outbufs */
	struct kr_quic_obuf *unsent_obuf;
	/* offset of the first unacked data in the entire stream
	 * (not just current unsent_obuf) */
	size_t first_offset;
	/* number of sent out bytes in the current unsent_obuf
	 * if we send >= to the unsent_obuf size the list attemps
	 * to advance to the next unsent_obuf and this value is reset to 0 */
	size_t unsent_offset;
};

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
	ngtcp2_version_cid dec_cids;
};

typedef struct {
	void *get_conn;
	void *user_data;
} nc_conn_ref_placeholder_t;

typedef struct pl_quic_conn_sess_data {
	struct protolayer_data h;

	/* I do not like this */
	uint64_t next_expiry;
	// nc_conn_ref_placeholder_t conn_ref;
	//
	// // conn_table next conn link
	struct ngtcp2_conn *conn;
	struct kr_quic_conn *next;


	// quic_params_t params;
	ngtcp2_settings settings;

	protolayer_iter_ctx_queue_t unwrap_queue;
	protolayer_iter_ctx_queue_t wrap_queue;
	// protolayer_iter_ctx_queue_t resend_queue;
	// struct wire_buf outbuf;

	ngtcp2_cid dcid;
	ngtcp2_cid scid;
	ngtcp2_version_cid dec_cids;

	gnutls_session_t tls_session;

	// crypto callbacks
	ngtcp2_crypto_conn_ref crypto_ref;

	// QUIC stream abstraction
	// TODO sentinel for streams?
	struct kr_quic_stream *streams;
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

	// TODO: consider removing
	size_t ibufs_size;
	size_t obufs_size;

	struct wire_buf unwrap_buf;

	struct kr_request *req;
	// quic_state_t state;
} pl_quic_conn_sess_data_t;
