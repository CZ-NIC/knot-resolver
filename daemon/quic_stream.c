/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/defines.h"
// #include "lib/generic/queue.h"
#include "contrib/ucw/lists.h"
#include "quic.h"
#include <asm-generic/errno-base.h>
#include <stdint.h>
#include <string.h>
#include "quic_stream.h"
#include "libknot/xdp/tcp_iobuf.h"
#include "session2.h"


typedef queue_t(kr_quic_obuf_t *) q_stream_buf;

static void stream_outprocess(struct kr_quic_conn *conn, struct kr_quic_stream *stream)
{
	if (stream != &conn->streams[conn->stream_inprocess]) {
		return;
	}

	for (int16_t idx = conn->stream_inprocess + 1; idx < conn->streams_count; idx++) {
		stream = &conn->streams[idx];
		// if (stream->pers_inbuf != NULL) {
		// 	conn->stream_inprocess = stream - conn->streams;
		// 	return;
		// }
	}

	conn->stream_inprocess = -1;
	--conn->streams_pending;
}

void kr_quic_stream_ack_data(struct kr_quic_conn *conn, int64_t stream_id,
                               size_t end_acked, bool keep_stream)
{
	struct kr_quic_stream *s = kr_quic_conn_get_stream(conn,
			stream_id, false);
	if (s == NULL) {
		return;
	}

	struct list *obs = &s->outbufs;

	struct kr_quic_obuf *first;

	while (EMPTY_LIST(*obs) != 0 && end_acked >= (first = HEAD(*obs))->len + s->first_offset) {
		rem_node(&first->node);
		assert(HEAD(*obs) != first); // help CLANG analyzer understand
					     // what rem_node did and that
					     // usage of HEAD(*obs) is safe
		s->obufs_size -= first->len;
		conn->obufs_size -= first->len;
		conn->quic_table->obufs_size -= first->len;
		s->first_offset += first->len;
		free(first);
		if (s->unsent_obuf == first) {
			s->unsent_obuf = EMPTY_LIST(*obs) == 0
				? NULL : HEAD(*obs);
			s->unsent_offset = 0;
		}
	}

	if (EMPTY_LIST(*obs) == 0 && !keep_stream) {
		stream_outprocess(conn, s);
		memset(s, 0, sizeof(*s));
		init_list(&s->outbufs);
		while (s = &conn->streams[0],
				wire_buf_data_length(&s->pers_inbuf) == 0 &&
				s->obufs_size == 0) {
			kr_assert(conn->streams_count > 0);
			conn->streams_count--;

			if (conn->streams_count == 0) {
				free(conn->streams);
				conn->streams = 0;
				conn->first_stream_id = 0;
				break;
			} else {
				conn->first_stream_id ++;
				conn->stream_inprocess--;
				memmove(s, s + 1,
					sizeof(*s) * conn->streams_count);
				// possible realloc to shrink allocated space,
				// but probably useless
				for (struct kr_quic_stream *si = s;
						si < s + conn->streams_count;
						si++) {
					if (si->obufs_size == 0) {
						init_list(&si->outbufs);
					} else {
						fix_list(&si->outbufs);
					}
				}
			}
		}
	}
}

void kr_quic_stream_mark_sent(struct kr_quic_conn *conn,
		int64_t stream_id, size_t amount_sent)
{
	struct kr_quic_stream *s = kr_quic_conn_get_stream(conn, stream_id, false);
	if (s == NULL) {
		return;
	}

	s->unsent_offset += amount_sent;
	assert(s->unsent_offset <= s->unsent_obuf->len);
	if (s->unsent_offset == s->unsent_obuf->len) {
		s->unsent_offset = 0;
		s->unsent_obuf = (kr_quic_obuf_t *)s->unsent_obuf->node.next;
		if (s->unsent_obuf->node.next == NULL) { // already behind the tail of list
			s->unsent_obuf = NULL;
		}
	}
}

/* TODO header + desc */
struct kr_quic_stream *kr_quic_stream_get_process(struct kr_quic_conn *conn,
                                                 int64_t *stream_id)
{
	if (conn == NULL || conn->stream_inprocess < 0) {
		return NULL;
	}

	struct kr_quic_stream *stream = &conn->streams[conn->stream_inprocess];
	*stream_id = (conn->first_stream_id + conn->stream_inprocess) * 4;
	stream_outprocess(conn, stream);
	return stream;
}


// inline static void params_update_quic_stream(krd_qdata_params_t *params,
//                                              int64_t stream_id)
// {
// 	params->quic_stream = stream_id;
// 	params->measured_rtt = kr_quic_conn_rtt(params->quic_conn);
// }

void kr_quic_conn_stream_free(kr_quic_conn_t *conn, int64_t stream_id)
{
	// TODO:
	// struct kr_quic_stream *s = kr_quic_conn_get_stream(conn, stream_id, false);
	// if (s != NULL && s->inbuf.iov_len > 0) {
	// 	free(s->inbuf.iov_base);
	// 	conn->ibufs_size -= buffer_alloc_size(s->inbuf.iov_len);
	// 	conn->quic_table->ibufs_size -= buffer_alloc_size(s->inbuf.iov_len);
	// 	memset(&s->inbuf, 0, sizeof(s->inbuf));
	// }
	//
	// while (s != NULL && s->inbufs != NULL) {
	// 	void *tofree = s->inbufs;
	// 	s->inbufs = s->inbufs->next;
	// 	free(tofree);
	// }

	// TODO:
	// kr_quic_stream_ack_data(conn, stream_id, SIZE_MAX, false);
}

bool kr_quic_stream_exists(kr_quic_conn_t *conn, int64_t stream_id)
{
	// Taken from Knot, TODO fix if we use stream_user_data
	// TRICK, we never use stream_user_data
	return (ngtcp2_conn_set_stream_user_data(conn->conn, stream_id, NULL) == NGTCP2_NO_ERROR);
}

#define QBUFSIZE 256u

struct kr_quic_stream *kr_quic_conn_get_stream(kr_quic_conn_t *conn,
		int64_t stream_id, bool create)
{
	if (stream_id % 4 != 0 || conn == NULL) {
		return NULL;
	}
	stream_id /= 4;

	if (conn->first_stream_id > stream_id) {
		return NULL;
	}
	if (conn->streams_count > stream_id - conn->first_stream_id) {
		return &conn->streams[stream_id - conn->first_stream_id];
	}

	if (create) {
		size_t new_streams_count;
		struct kr_quic_stream *new_streams;

		// should we attempt to purge unused streams here?
		// maybe only when we approach the limit
		if (conn->streams_count == 0) {
			new_streams = malloc(sizeof(new_streams[0]));
			if (new_streams == NULL) {
				return NULL;
			}
			new_streams_count = 1;
			conn->first_stream_id = stream_id;
		} else {
			new_streams_count = stream_id + 1 - conn->first_stream_id;
			if (new_streams_count > MAX_STREAMS_PER_CONN) {
				return NULL;
			}
			new_streams = realloc(conn->streams, new_streams_count * sizeof(*new_streams));
			if (new_streams == NULL) {
				return NULL;
			}
		}

		for (struct kr_quic_stream *si = new_streams;
		     si < new_streams + conn->streams_count; si++) {
			if (si->obufs_size == 0) {
				init_list(&si->outbufs);
			} else {
				fix_list(&si->outbufs);
			}
		}

		for (struct kr_quic_stream *si = new_streams + conn->streams_count;
		     si < new_streams + new_streams_count; si++) {
			memset(si, 0, sizeof(*si));
			wire_buf_init(&si->pers_inbuf, /* FIXME */QBUFSIZE);
			init_list(&si->outbufs);
		}

		conn->streams = new_streams;
		conn->streams_count = new_streams_count;

		return &conn->streams[stream_id - conn->first_stream_id];
	}

	return NULL;
}

// TODO: frfee the streams
// while (stream->inbufs != NULL) {
// 	knot_tcp_inbufs_upd_res_t *tofree = stream->inbufs;
// 	stream->inbufs = tofree->next;
// 	free(tofree);
// }

/** buffer resolved payload in the wire format, this buffer
 * is used to create quic stream data. Data in this buffer
 * MUST be kept untill ack frame confirms their retrieval
 * or the stream gets closed. */
int kr_quic_stream_add_data(kr_quic_conn_t *conn, int64_t stream_id,
		uint8_t *data, size_t len)
{
	struct kr_quic_stream *s = kr_quic_conn_get_stream(conn, stream_id, true);
	kr_require(s);

	struct kr_quic_obuf *obuf = malloc(sizeof(*obuf) + len);
	kr_require(obuf);
	// if (!obuf)
	// 	return kr_error(ENOMEM)

	obuf->len = len;
	if (data)
		memcpy(obuf->buf, data, len);

	list_t *list = (list_t *)&s->outbufs;
	if (EMPTY_LIST(*list)) {
		s->unsent_obuf = obuf;
	}
	add_tail((list_t *)&s->outbufs, (node_t *)obuf);
	s->obufs_size += obuf->len;
	conn->obufs_size += obuf->len;
	conn->quic_table->obufs_size += obuf->len;

	return kr_ok();
}

/* store the index of the first stream that has a
 * query ready to be resolved in conn->stream_inprocess */
void stream_inprocess(struct kr_quic_conn *conn, struct kr_quic_stream *stream)
{
	int16_t idx = stream - conn->streams;
	assert(idx >= 0);
	assert(idx < conn->streams_count);
	if (conn->stream_inprocess < 0 || conn->stream_inprocess > idx) {
		conn->stream_inprocess = idx;
	}
}

int update_stream_pers_buffer(const uint8_t *data, size_t len,
		struct kr_quic_stream *stream, int64_t stream_id)
{
	kr_require(len > 0 && data && stream);

	// struct wire_buf wb = stream->pers_inbuf;
	if (wire_buf_free_space_length(&stream->pers_inbuf) < len) {
		kr_log_error(DOQ, "wire buf for stream no. %ld ran out of available space"
				" needed: %zu, available: %zu\n",
				stream_id, len,
				wire_buf_free_space_length(&stream->pers_inbuf));
		return kr_error(ENOMEM);
	}

	memcpy(wire_buf_free_space(&stream->pers_inbuf), data, len);
	/* FIXME reqire for now, though this is hardly the desired check */
	kr_require(wire_buf_consume(&stream->pers_inbuf, len) == kr_ok());

	return kr_ok();
}

/** callback of recv_stream_data,
 * data passed to this cb function is the actuall query.
 * */
int kr_quic_stream_recv_data(struct kr_quic_conn *qconn, int64_t stream_id,
                               const uint8_t *data, size_t len, bool fin)
{
	if (len == 0 || qconn == NULL || data == NULL) {
		return KNOT_EINVAL;
	}

	struct kr_quic_stream *stream = kr_quic_conn_get_stream(qconn, stream_id, true);
	if (stream == NULL) {
		return KNOT_ENOENT;
	}

	qconn->streams_pending++;

	// struct iovec in = { (void *)data, len };
	// ssize_t prev_ibufs_size = qconn->ibufs_size;
	// size_t save_total = qconn->ibufs_size;

	if (update_stream_pers_buffer(data, len, stream, stream_id) != kr_ok()) {
		return -1 /* TODO */;
	}

	// int ret = knot_tcp_inbufs_upd(&stream->inbuf, in, true,
	// 		&stream->inbufs, &qconn->ibufs_size);

	// TODO:
	// int ret = kr_tcp_inbufs_upd(&stream->inbuf, in, true,
	//                               &stream->inbufs, &conn->ibufs_size);
	// int ret = KNOT_EOK;

	// qconn->quic_table->ibufs_size += (ssize_t)qconn->ibufs_size - prev_ibufs_size;
	// if (ret != KNOT_EOK) {
	// 	return ret;
	// }

	// if (fin && stream->inbufs == NULL) {
	// 	return KNOT_ESEMCHECK;
	// }

	if (fin) {
		kr_log_info(DOQ, "wire_buf: %s\n", (char *)wire_buf_data(&stream->pers_inbuf));
		stream_inprocess(qconn, stream);
	}

	return kr_ok();
}

