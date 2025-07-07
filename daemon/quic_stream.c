/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/generic/queue.h"
#include "quic.h"
#include <stdint.h>
#include "quic_stream.h"

typedef queue_t(kr_quic_obuf_t *) q_stream_buf;

static void stream_outprocess(struct kr_quic_conn *conn, struct kr_quic_stream *stream)
{
	if (stream != &conn->streams[conn->stream_inprocess]) {
		return;
	}

	for (int16_t idx = conn->stream_inprocess + 1; idx < conn->streams_count; idx++) {
		stream = &conn->streams[idx];
		if (stream->inbufs != NULL) {
			conn->stream_inprocess = stream - conn->streams;
			return;
		}
	}
	conn->stream_inprocess = -1;
}

void kr_quic_stream_ack_data(struct kr_quic_conn *conn, int64_t stream_id,
                               size_t end_acked, bool keep_stream)
{
	struct kr_quic_stream *s = kr_quic_conn_get_stream(conn, stream_id, false);
	if (s == NULL) {
		return;
	}

	q_stream_buf *obs = (q_stream_buf *)&s->outbufs;

	kr_quic_obuf_t *first;

	while (queue_len(*obs) != 0 && end_acked >= (first = queue_head(*obs))->len + s->first_offset) {
		queue_pop(*obs);
		assert(queue_head(*obs) != first); // help CLANG analyzer understand what rem_node did and that further usage of HEAD(*obs) is safe
		s->obufs_size -= first->len;
		conn->obufs_size -= first->len;
		conn->quic_table->obufs_size -= first->len;
		s->first_offset += first->len;
		free(first);
		if (s->unsent_obuf == first) {
			s->unsent_obuf = queue_len(*obs) == 0 ? NULL : queue_head(*obs);
			s->unsent_offset = 0;
		}
	}

	if (queue_len(*obs) == 0 && !keep_stream) {
		stream_outprocess(conn, s);
		memset(s, 0, sizeof(*s));
		init_list((list_t *)&s->outbufs);
		while (s = &conn->streams[0], s->inbuf.iov_len == 0 && s->inbufs == NULL && s->obufs_size == 0) {
			assert(conn->streams_count > 0);
			conn->streams_count--;

			if (conn->streams_count == 0) {
				free(conn->streams);
				conn->streams = 0;
				conn->first_stream_id = 0;
				break;
			} else {
				conn->first_stream_id ++;
				conn->stream_inprocess--;
				memmove(s, s + 1, sizeof(*s) * conn->streams_count);
				// possible realloc to shrink allocated space, but probably useless
				for (struct kr_quic_stream *si = s;  si < s + conn->streams_count; si++) {
					if (si->obufs_size == 0) {
						queue_init(si->outbufs);
						// init_list((list_t *)&si->outbufs);
					} else {
						// fix_list((list_t *)&si->outbufs);
					}
				}
			}
		}
	}
}

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
				queue_init(si->outbufs);
				// init_list(&si->outbufs);
			} else {
				// fix_list(&si->outbufs);
			}
		}

		for (struct kr_quic_stream *si = new_streams + conn->streams_count;
		     si < new_streams + new_streams_count; si++) {
			memset(si, 0, sizeof(*si));
			queue_init(si->outbufs);
			// init_list(&si->outbufs);
		}

		conn->streams = new_streams;
		conn->streams_count = new_streams_count;

		return &conn->streams[stream_id - conn->first_stream_id];
	}

	return NULL;
}

void kr_quic_stream_mark_sent(kr_quic_conn_t *conn,
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

	struct iovec in = { (void *)data, len };
	ssize_t prev_ibufs_size = qconn->ibufs_size;
	// TODO:
	// int ret = kr_tcp_inbufs_upd(&stream->inbuf, in, true,
	//                               &stream->inbufs, &conn->ibufs_size);
	int ret = KNOT_EOK;

	qconn->quic_table->ibufs_size += (ssize_t)qconn->ibufs_size - prev_ibufs_size;
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (fin && stream->inbufs == NULL) {
		return KNOT_ESEMCHECK;
	}

	if (stream->inbufs != NULL) {
		// TODO:
		// stream_inprocess(conn, stream);
	}
	return KNOT_EOK;
}
