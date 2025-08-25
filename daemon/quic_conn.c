/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdlib.h>
#include <stdio.h>
#include "quic_conn.h"
#include "lib/proto.h"
// #include "quic.h"
#include "session2.h"
#include <ngtcp2/ngtcp2.h>
#include <string.h>

// static int handle_packet(struct pl_quic_conn_sess_data *quic,
// 		struct protolayer_iter_ctx *ctx, const uint8_t *pkt,
// 		size_t pktlen, struct quic_target *target,
// 		ngtcp2_version_cid *dec_cids, struct kr_quic_conn **out_conn,
// 		int *action)
// {
// 	*action = 0;
// 	kr_quic_conn_t *qconn = NULL;
//
// 	// Initial comm processing
// 	// ngtcp2_version_cid decoded_cids = { 0 };
// 	// FIXME: duplicate read, reread in quic_init_server_conn (accept)
// 	int ret = ngtcp2_pkt_decode_version_cid(dec_cids, pkt,
// 			pktlen, SERVER_DEFAULT_SCIDLEN);
//
// 	/* If Version Negotiation is required, this function
// 	 * returns NGTCP2_ERR_VERSION_NEGOTIATION.
// 	 * Unlike the other error cases, all fields of dest are assigned
// 	 * see https://nghttp2.org/ngtcp2/ngtcp2_pkt_decode_version_cid.html */
// 	if (ret != NGTCP2_NO_ERROR && ret != NGTCP2_ERR_VERSION_NEGOTIATION) {
// 		kr_log_warning(DOQ, "Could not decode pkt header: (%d) %s \n",
// 				ret, ngtcp2_strerror(ret));
// 		return kr_ok();
// 	}
// 	uint32_t supported_quic[1] = { NGTCP2_PROTO_VER_V1 };
// 	ngtcp2_cid_init(&target->dcid, dec_cids->dcid, dec_cids->dcidlen);
// 	ngtcp2_cid_init(&target->scid, dec_cids->scid, dec_cids->scidlen);
// 	if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
// 		*action = -QUIC_SEND_VERSION_NEGOTIATION;
// 		return kr_ok();
// 		// goto finish
// 	}
//
// 	qconn = kr_quic_table_lookup(&target->dcid, quic->conn_table);
// 	if (!qconn) {
// 		struct protolayer_data_param data_param = {
// 			.protocol = PROTOLAYER_TYPE_QUIC,
// 			.param = NULL /* TODO! */
// 		};
//
// 		struct session2 *conn_sess = session2_new(SESSION2_TRANSPORT_PARENT,
// 				KR_PROTO_DOQ,
// 				&data_param,
// 				0,
// 				false);
//
// 		/* TODO react accordingly to errcodes from accept.
// 		 * not all errors are terminal nor are all quiet,
// 		 * see which case warrants the payload to be discarded
// 		 * (we have to avoid looping over one bad pkt indefinitelly) */
// 		if ((ret = quic_init_server_conn(quic->conn_table, ctx,
// 				 UINT64_MAX - 1, &target->scid, &target->dcid,
// 				 *dec_cids, pkt, pktlen, &qconn)) != kr_ok()) {
// 			return ret;
// 		}
//
// 		/* Should not happen, if it did we certainly cannot
// 		 * continue in the communication
// 		 * Perhaps kr_require is too strong, this situation
// 		 * shouldn't corelate with kresd run.
// 		 * TODO: switch to condition and failed resolution */
// 		kr_require(qconn);
// 		// continue;
// 	}
//
// 	uint64_t now = quic_timestamp();
// 	const ngtcp2_path *path = ngtcp2_conn_get_path(qconn->conn);
// 	ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };
//
// 	// while (ngtcp2_conn_read_pkt(qconn->conn, path, &pi, pkt, pktlen, now) == 0);
// 	ret = ngtcp2_conn_read_pkt(qconn->conn, path, &pi, pkt, pktlen, now);
//
// 	*out_conn = qconn;
// 	/* FIXME: inacurate error handling */
// 	if (ret == NGTCP2_ERR_DRAINING) { // doq received CONNECTION_CLOSE from the counterpart
// 		kr_quic_table_rem(qconn, quic->conn_table);
// 		wire_buf_reset(ctx->payload.wire_buf);
// 		*action = KR_QUIC_HANDLE_RET_CLOSE;
// 		free(*out_conn);
// 		return kr_ok();
//
// 	} else if (ngtcp2_err_is_fatal(ret)) { // connection doomed
// 		kr_log_error(DOQ, "fatal error in ngtcp2_conn_read_pkt: %s (%d)", ngtcp2_strerror(ret), ret);
// 		// if (ret == NGTCP2_ERR_CALLBACK_FAILURE) {
// 			// ret = kr_error(KNOT_EBADCERT);
// 		// } else {
// 		// 	ret = kr_error();
// 		// }
// 		kr_quic_table_rem(qconn, quic->conn_table);
// 		return ret;
//
// 	} else if (ret == NGTCP2_ERR_RETRY) {
// 		kr_log_info(DOQ, "server will perform address validation via Retry packet\n");
// 		*action = QUIC_SEND_RETRY;
// 		wire_buf_reset(ctx->payload.wire_buf);
// 		return kr_ok();
//
// 	} else if (ret != NGTCP2_NO_ERROR) { // non-fatal error, discard packet
// 		kr_log_error(DOQ, "discarding recieved pkt: %s (%d)", ngtcp2_strerror(ret), ret);
// 		ret = KNOT_EOK;
// 		return ret;
// 	}
//
// 	ngtcp2_conn_handle_expiry(qconn->conn, now);
//
// 	/* given the 0 return value the pkt has been processed */
// 	wire_buf_reset(ctx->payload.wire_buf);
// 	return kr_ok();
// }

static enum protolayer_iter_cb_result pl_quic_conn_unwrap(void *sess_data,
		void *iter_data, struct protolayer_iter_ctx *ctx)
{
	int ret = kr_ok();
	struct session2 *qconn = NULL;
	struct pl_quic_conn_sess_data *quic_conn = sess_data;

	queue_push(quic_conn->unwrap_queue, ctx);
	/* TODO Verify this doesn't leak */
	// struct quic_target *target = malloc(sizeof(struct quic_target));
	// kr_require(target);

	return protolayer_async();

	while (protolayer_queue_has_payload(&quic_conn->unwrap_queue)) {
		struct protolayer_iter_ctx *data = queue_head(quic_conn->unwrap_queue);
		ngtcp2_version_cid dec_cids;

		// ret = ngtcp2_pkt_decode_version_cid(&dec_cids,
		// 		wire_buf_data(data->payload.wire_buf),
		// 		wire_buf_data_length(data->payload.wire_buf),
		// 		SERVER_DEFAULT_SCIDLEN);

		// if (ret != NGTCP2_NO_ERROR && ret != NGTCP2_ERR_VERSION_NEGOTIATION) {
		// 	kr_log_warning(DOQ, "Could not decode pkt header: (%d) %s \n",
		// 			ret, ngtcp2_strerror(ret));
		// 	return kr_ok();
		// }

		uint32_t supported_quic_conn[1] = { NGTCP2_PROTO_VER_V1 };
		// ngtcp2_cid_init(&target->dcid, dec_cids.dcid, dec_cids.dcidlen);
		// ngtcp2_cid_init(&target->scid, dec_cids.scid, dec_cids.scidlen);
		// TODO:
		// if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
		// 	*action = -QUIC_SEND_VERSION_NEGOTIATION;
		// 	return kr_ok();
		// 	// goto finish
		// }

		// qconn = kr_quic_table_lookup(&target->dcid, quic_conn->conn_table);
		// if (!qconn) {
		// 	/* FIXME: alloc on the heap if used beyond this scope */
		// 	struct protolayer_data_param data_param = {
		// 		.protocol = PROTOLAYER_TYPE_QUIC_CONN,
		// 		.param = NULL /* TODO! */
		// 	};
		//
		// 	qconn = session2_new_child(quic_conn->h.session,
		// 			KR_PROTO_DOQ,
		// 			&data_param,
		// 			0 /* FIXME */,
		// 			false);
		// }
		//
		// /* might not be needed or even detrimental */
		// data->session = qconn;
		//
		// ret = session2_unwrap_after(qconn,
		// 		PROTOLAYER_TYPE_QUIC_CONN,
		// 		data->payload,
		// 		data->comm,
		// 		data->finished_cb,
		// 		data->finished_cb_baton);
		//
		// // return protolayer_continue(data);
		}

// 		/* not all fails should be quiet, some require a response from
// 		 * our side (kr_quic_send with given action) TODO! */
// 		if (ret != kr_ok()) {
// 			goto fail;
// 		}
// 		if (action == KR_QUIC_HANDLE_RET_CLOSE) {
// 			ret = kr_ok();
// 			goto fail;
// 		}
//
// 		if (qconn->stream_inprocess == -1) {
// 			kr_quic_send(quic->conn_table, qconn, ctx, action,
// 					&dec_cids, QUIC_MAX_SEND_PER_RECV, 0);
// 			ret = kr_ok();
// 			goto fail;
// 		}
//
// 		if (kr_fails_assert(queue_len(quic->unwrap_queue) == 1)) {
// 			ret = kr_error(EINVAL);
// 			goto fail;
// 		}
//
// 		/* WARNING: this has been moved */
// 		// struct protolayer_iter_ctx *ctx_head = queue_head(quic->unwrap_queue);
// 		// if (!kr_fails_assert(ctx == ctx_head)) {
// 		// 	protolayer_break(ctx, kr_error(EINVAL));
// 		// 	ctx = ctx_head;
// 		// }
// 	}
//
// 	struct protolayer_iter_ctx *ctx_head = queue_head(quic->unwrap_queue);
// 	if (!kr_fails_assert(ctx == ctx_head))
// 		queue_pop(quic->unwrap_queue);
//
// 	while (qconn->streams_pending) {
// 		if ((ret = get_query(ctx, qconn, target)) <= 0)
// 			goto fail;
//
// 		ctx->payload = protolayer_payload_wire_buf(&qconn->unwrap_buf,
// 				false);
//
// 		if (qconn->streams_pending == 0) {
// 			return protolayer_continue(ctx);
// 		}
//
// 		/* FIXME should we ignore the result? */
// 		session2_unwrap_after(ctx->session,
// 				PROTOLAYER_TYPE_QUIC,
// 				ctx->payload,
// 				ctx->comm,
// 				ctx->finished_cb,
// 				ctx->finished_cb_baton);
// 	}
//
// 	// if ((ret = collect_queries(ctx, qconn, target)) > 0) {
// 	// 	ctx->payload = protolayer_payload_wire_buf(&qconn->unwrap_buf,
// 	// 			false);
// 	// 	return protolayer_continue(ctx);
// 	// }
//
// 	free(target);
// 	return protolayer_break(ctx, ret);
//
// fail:
// 	ctx_head = queue_head(quic->unwrap_queue);
// 	if (!kr_fails_assert(ctx == ctx_head))
// 		queue_pop(quic->unwrap_queue);
//
// 	free(target);
// 	return protolayer_break(ctx, ret);
}

/* FIXME */
#define OUTBUF_SIZE 131072

static int pl_quic_conn_sess_init(struct session2 *session, void *sess_data, void *param)
{
	struct pl_quic_conn_sess_data *quic = sess_data;
	// quic->h.session = session;
	session->secure = true;
	queue_init(quic->wrap_queue);
	queue_init(quic->unwrap_queue);

	if (param) {
		struct kr_quic_conn_param *p = param;
		quic->dcid = p->dcid;
		quic->scid = p->scid;
		quic->dec_cids = p->dec_cids;
		/* FIXME THIS will not work */
		session->comm_storage.target = &quic->dcid;
	} else {
		// struct kr_quic_conn_param *p = param;
		// quic->dcid = p->dcid;
		// quic->scid = p->scid;
		// quic->dec_cids = p->dec_cids;
	}

	wire_buf_init(&quic->unwrap_buf, 1024);

	char *test_str = "I've been here\n";
	memcpy(wire_buf_free_space(&quic->unwrap_buf), test_str, strlen(test_str));

	// if (!the_network->tls_credentials) {
	// 	kr_log_info(DOQ, "tls credentials were not present at the start of DoQ iteration\n");
	// 	the_network->tls_credentials = tls_get_ephemeral_credentials();
	// 	if (!the_network->tls_credentials) {
	// 		kr_log_error(TLS, "X.509 credentials are missing, and ephemeral credentials failed; no TLS\n");
	// 		return kr_error(EINVAL);
	// 	}
	//
	// 	kr_log_info(TLS, "Using ephemeral TLS credentials\n");
	// }

	// struct tls_credentials *creds = the_network->tls_credentials;
	// kr_require(creds->credentials != NULL);

	wire_buf_init(&quic->unwrap_buf, OUTBUF_SIZE);

	// TODO set setings?

	return 0;
}

static void stream_outprocess(struct pl_quic_conn_sess_data *conn, struct kr_quic_stream *stream)
{
	if (stream != &conn->streams[conn->stream_inprocess]) {
		return;
	}

	for (int16_t idx = conn->stream_inprocess + 1; idx < conn->streams_count; idx++) {
		stream = &conn->streams[idx];
		if (wire_buf_data_length(&stream->pers_inbuf) != 0) {
			conn->stream_inprocess = stream - conn->streams;
			return;
		}
	}

	conn->stream_inprocess = -1;
	--conn->streams_pending;
}

struct kr_quic_stream *kr_quic_conn_get_stream(struct pl_quic_conn_sess_data *conn,
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
			new_streams = realloc(conn->streams,
					new_streams_count * sizeof(*new_streams));
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
			init_list(&si->outbufs);
		}

		conn->streams = new_streams;
		conn->streams_count = new_streams_count;

		return &conn->streams[stream_id - conn->first_stream_id];
	}

	return NULL;
}

struct kr_quic_stream *kr_quic_stream_get_process(struct pl_quic_conn_sess_data *conn,
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

void kr_quic_stream_ack_data(struct pl_quic_conn_sess_data *conn, int64_t stream_id,
                               size_t end_acked, bool keep_stream)
{
	struct kr_quic_stream *s = kr_quic_conn_get_stream(conn,
			stream_id, false);
	if (s == NULL) {
		return;
	}

	struct list *obs = &s->outbufs;

	struct kr_quic_obuf *first;

	while (!EMPTY_LIST(*obs) && end_acked >= (first = HEAD(*obs))->len + s->first_offset) {
		rem_node(&first->node);
		assert(HEAD(*obs) != first); // help CLANG analyzer understand
					     // what rem_node did and that
					     // usage of HEAD(*obs) is safe
		s->obufs_size -= first->len;
		conn->obufs_size -= first->len;
		// conn->quic_table->obufs_size -= first->len;
		s->first_offset += first->len;
		free(first);
		if (s->unsent_obuf == first) {
			s->unsent_obuf = EMPTY_LIST(*obs) == 0 ? NULL : HEAD(*obs);
			s->unsent_offset = 0;
		}
	}

	if (EMPTY_LIST(*obs) && !keep_stream) {
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
				conn->first_stream_id++;
				conn->stream_inprocess--;
				memmove(s, s + 1, sizeof(*s) * conn->streams_count);
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

void kr_quic_stream_mark_sent(struct pl_quic_conn_sess_data *conn,
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

void kr_quic_conn_stream_free(struct pl_quic_conn_sess_data *conn, int64_t stream_id)
{

	struct kr_quic_stream *s = kr_quic_conn_get_stream(conn, stream_id, false);

	if (s != NULL && s->pers_inbuf.buf) {
		/* should not happen */
		wire_buf_deinit(&s->pers_inbuf);
	}

	if (s != NULL && /* FIXME this condition */ wire_buf_data_length(&s->pers_inbuf) > 0) {
		wire_buf_deinit(&s->pers_inbuf);
		// TODO
		// conn->ibufs_size -= buffer_alloc_size(s->inbuf.iov_len);
		// conn->quic_table->ibufs_size -= buffer_alloc_size(s->inbuf.iov_len);

		// s->pers_inbuf = NULL;
	}

	// knotdns iovec inbufs specific
	// while (s != NULL && s->inbufs != NULL) {
	// 	void *tofree = s->inbufs;
	// 	s->inbufs = s->inbufs->next;
	// 	free(tofree);
	// }

	kr_quic_stream_ack_data(conn, stream_id, SIZE_MAX, false);
}

static int pl_quic_conn_sess_deinit(struct session2 *session, void *data)
{
	// pl_quic_sess_data_t *quic = data;
	// queue_deinit(quic->unwrap_queue);
	// queue_deinit(quic->wrap_queue);
	// kr_quic_table_free(quic->conn_table);
	// wire_buf_deinit(&quic->outbuf);
	//
	// return kr_ok();
}

static enum protolayer_event_cb_result pl_quic_conn_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if (event == PROTOLAYER_EVENT_CLOSE) {
		kr_log_info(DOQ, "IM SUPPOSTED TO CLOSE FROM EVENT UNWRAP\n");
	}

	return PROTOLAYER_EVENT_PROPAGATE;
}

static enum protolayer_event_cb_result pl_quic_conn_event_wrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if (event == PROTOLAYER_EVENT_CLOSE) {
		kr_log_info(DOQ, "IM SUPPOSTED TO CLOSE FROM EVENT WRAP\n");
	}

	return PROTOLAYER_EVENT_CONSUME;
}

__attribute__((constructor))
static void quic_conn_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_QUIC_CONN] = (struct protolayer_globals) {
		.sess_size = sizeof(struct pl_quic_conn_sess_data),
		// .iter_size = sizeof(struct ),
		.wire_buf_overhead = MAX_QUIC_FRAME_SIZE,
		// .iter_init = pl_quic_iter_init,
		// .iter_deinit = pl_quic_iter_deinit,
		.sess_init = pl_quic_conn_sess_init,
		.sess_deinit = pl_quic_conn_sess_deinit,
		.unwrap = pl_quic_conn_unwrap,
		// .wrap = pl_quic_conn_wrap,
		.event_unwrap = pl_quic_conn_event_unwrap,
		.event_wrap = pl_quic_conn_event_wrap,
		// .request_init = pl_quic_request_init,
	};
}
