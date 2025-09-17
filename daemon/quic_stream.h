/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "quic_conn.h"
#include "quic_demux.h"
#include "session2.h"
#include <ngtcp2/ngtcp2.h>

#define QUIC_MAX_SEND_PER_RECV	4

// struct pl_quic_stream_sess_data *kr_quic_conn_get_stream(
// 		struct pl_quic_conn_sess_data *conn,
// 		int64_t stream_id, bool create);

// int kr_quic_stream_add_data(struct pl_quic_conn_sess_data *conn,
// 		int64_t stream_id, struct protolayer_payload *pl);

// int kr_quic_stream_recv_data(struct pl_quic_conn_sess_data *conn,
// 		int64_t stream_id, const uint8_t *data, size_t len, bool fin);

// struct pl_quic_stream_sess_data *kr_quic_stream_get_process(
// 		struct pl_quic_conn_sess_data *conn, int64_t *stream_id);

/* parameters that will be passed to pl_quic_conn_sess_init */
struct kr_quic_stream_param {
	int64_t stream_id;
	ngtcp2_conn *conn;
	struct comm_info comm_storage;
};

struct pl_quic_stream_sess_data {
	struct protolayer_data h;

	int64_t stream_id;
	struct ngtcp2_conn *conn;
	// struct iovec inbuf;
	struct wire_buf pers_inbuf;
	// struct kr_tcp_inbufs_upd_res *inbufs;

	struct comm_info comm_storage;

	size_t firstib_consumed;
	/* stores data that has been sent out and awaits acknowledgement and
	 * data that has just been created and is waiting to be sent out */
	/* ucw */struct list outbufs;

	// /* ucw */struct kr_quic_ucw_list outbufs;
	// /*ucw_*/queue_t(struct kr_quic_obuf) outbufs;
	// /*ucw_*/list_t outbufs;

	protolayer_iter_ctx_queue_t unwrap_queue;
	protolayer_iter_ctx_queue_t wrap_queue;

	uint32_t incflags;
	uint64_t sdata_offset;

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

static int send_stream(struct pl_quic_stream_sess_data *stream,
		struct protolayer_iter_ctx *ctx,
		// struct protolayer_payload *outwb,
		uint8_t *data, size_t len, bool fin, ngtcp2_ssize *sent);
