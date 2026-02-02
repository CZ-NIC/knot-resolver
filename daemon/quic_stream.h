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

	struct kr_quic_obuf *unsent_obuf;
	size_t first_offset;
	size_t unsent_offset;

	uint32_t incflags;
	uint64_t sdata_offset;

	struct pl_quic_conn_sess_data *conn_ref;
};

void kr_quic_stream_ack_data(struct pl_quic_stream_sess_data *stream,
		int64_t stream_id, size_t end_acked, bool keep_stream);
