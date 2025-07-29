/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "quic.h"

#define QUIC_MAX_SEND_PER_RECV	4

bool kr_quic_stream_exists(kr_quic_conn_t *conn, int64_t stream_id);

/** We have to buffer all data that has been send but still waits
 * to be acked, move the pointer of "yet to be acked" data */
// void kr_quic_stream_ack_data(struct kr_quic_conn *conn, int64_t stream_id,
//                                size_t end_acked, bool keep_stream);
void kr_quic_stream_mark_sent(struct kr_quic_conn *conn,
		int64_t stream_id, size_t amount_sent);

struct kr_quic_stream *quic_conn_get_stream(struct kr_quic_conn *conn,
		int64_t stream_id, bool create);

int kr_quic_stream_recv_data(kr_quic_conn_t *conn, int64_t stream_id,
		const uint8_t *data, size_t len, bool fin);

/* returns the first stream that has received FIN i.e. has full query ready */
struct kr_quic_stream *kr_quic_stream_get_process(struct kr_quic_conn *conn,
                                                 int64_t *stream_id);

void kr_quic_conn_stream_free(kr_quic_conn_t *conn, int64_t stream_id);

struct kr_quic_stream *kr_quic_conn_get_stream(kr_quic_conn_t *conn,
		int64_t stream_id, bool create);
