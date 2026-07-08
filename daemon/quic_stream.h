/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <ngtcp2/ngtcp2.h>
#include "contrib/ucw/lists.h"
#include "quic_conn.h"
#include "session2.h"

struct kr_quic_obuf {
	struct node node;
	size_t len;
	uint8_t buf[];
};

/* stated that might overlap for the current state of the stream
 * this enum exists to simplify handling of forcefull stream termination.
 * QUIC streams have quite complex reference_counting, this
 * enum and the pl_quic_stream_sess_data::state should hopefully simplify
 * termination of the session */
typedef enum {
	/* Timer is running, holds one ref */
	QUIC_STREAM_HAS_TIMER      = (1 << 0),
	/* ngtcp2_bidi stream is open on this stream, holds one ref */
	QUIC_STREAM_BIDI_OPEN      = (1 << 1),
	/* sent data is not acked yet, holds one ref */
	QUIC_STREAM_ACK_PENDING    = (1 << 2),
	/* sent query has not been answered yer (client side only) */
	QUIC_STREAM_ANSWER_PENDING = (1 << 4),
} quic_stream_state;

struct pl_quic_stream_sess_data {
	struct protolayer_data h;

	node_t list_node;
	int64_t stream_id;
	struct ngtcp2_conn *conn;
	struct wire_buf pers_inbuf;
	struct wire_buf outbuf;
	struct comm_info comm_storage;
	/* stores both data that has been sent out but hasn't been acked and
	 * data that has just been created and is waiting to be sent out */
	struct list outbufs;
	size_t obufs_size;

	/* Parent connection was closed, but this stream's death was
	 * defered to finish a leading task. */
	bool orphan;
	bool terminated_gracefully;
	uint32_t state;
	struct kr_quic_obuf *unsent_obuf;
	size_t first_offset;
	size_t unsent_offset;
	bool closed;
	bool write_closed;
	uint32_t incflags;
	bool skip_update_time;
	uint64_t sdata_offset;

	struct pl_quic_conn_sess_data *conn_ref;
};

void kr_quic_stream_ack_data(struct pl_quic_stream_sess_data *stream,
		int64_t stream_id, size_t end_acked, bool keep_stream);
uint8_t *kr_quic_stream_add_data(struct pl_quic_stream_sess_data *s,
		   uint8_t *data, size_t len);
