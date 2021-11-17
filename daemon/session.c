/*  Copyright (C) 2018-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <libknot/packet/pkt.h>

#include "lib/defines.h"
#include "daemon/session.h"
#include "daemon/engine.h"
#include "daemon/tls.h"
#include "daemon/http.h"
#include "daemon/worker.h"
#include "daemon/io.h"
#include "lib/generic/queue.h"

#define TLS_CHUNK_SIZE (16 * 1024)

/* Initial max frame size: https://tools.ietf.org/html/rfc7540#section-6.5.2 */
#define HTTP_MAX_FRAME_SIZE 16384

/* Per-socket (TCP or UDP) persistent structure.
 *
 * In particular note that for UDP clients it's just one session (per socket)
 * shared for all clients.  For TCP/TLS it's also for the connection-specific socket,
 * i.e one session per connection.
 *
 * LATER(optim.): the memory here is used a bit wastefully.
 */
struct session {
	struct session_flags sflags;  /**< miscellaneous flags. */
	union inaddr peer;            /**< address of peer; not for UDP clients (downstream) */
	union inaddr sockname;        /**< our local address; for UDP it may be a wildcard */
	uv_handle_t *handle;          /**< libuv handle for IO operations. */
	uv_timer_t timeout;           /**< libuv handle for timer. */

	struct tls_ctx *tls_ctx;      /**< server side tls-related data. */
	struct tls_client_ctx *tls_client_ctx;  /**< client side tls-related data. */

#if ENABLE_DOH2
	struct http_ctx *http_ctx;  /**< server side http-related data. */
#endif

	trie_t *tasks;                /**< list of tasks associated with given session. */
	queue_t(struct qr_task *) waiting;  /**< list of tasks waiting for sending to upstream. */

	uint8_t *wire_buf;            /**< Buffer for DNS message, except for XDP. */
	ssize_t wire_buf_size;        /**< Buffer size. */
	ssize_t wire_buf_start_idx;   /**< Data start offset in wire_buf. */
	ssize_t wire_buf_end_idx;     /**< Data end offset in wire_buf. */
	uint64_t last_activity;       /**< Time of last IO activity (if any occurs).
				       *   Otherwise session creation time. */
};

static void on_session_close(uv_handle_t *handle)
{
	struct session *session = handle->data;
	kr_require(session->handle == handle);
	io_free(handle);
}

static void on_session_timer_close(uv_handle_t *timer)
{
	struct session *session = timer->data;
	uv_handle_t *handle = session->handle;
	kr_require(handle && handle->data == session);
	kr_require(session->sflags.outgoing || handle->type == UV_TCP);
	if (!uv_is_closing(handle)) {
		uv_close(handle, on_session_close);
	}
}

void session_free(struct session *session)
{
	if (session) {
		session_clear(session);
		free(session);
	}
}

void session_clear(struct session *session)
{
	kr_require(session_is_empty(session));
	if (session->handle && session->handle->type == UV_TCP) {
		free(session->wire_buf);
	}
#if ENABLE_DOH2
	http_free(session->http_ctx);
#endif
	trie_clear(session->tasks);
	trie_free(session->tasks);
	queue_deinit(session->waiting);
	tls_free(session->tls_ctx);
	tls_client_ctx_free(session->tls_client_ctx);
	memset(session, 0, sizeof(*session));
}

void session_close(struct session *session)
{
	kr_require(session_is_empty(session));
	if (session->sflags.closing) {
		return;
	}

	uv_handle_t *handle = session->handle;
	io_stop_read(handle);
	session->sflags.closing = true;

	if (!uv_is_closing((uv_handle_t *)&session->timeout)) {
		uv_timer_stop(&session->timeout);
		if (session->tls_client_ctx) {
			tls_close(&session->tls_client_ctx->c);
		}
		if (session->tls_ctx) {
			tls_close(&session->tls_ctx->c);
		}

		session->timeout.data = session;
		uv_close((uv_handle_t *)&session->timeout, on_session_timer_close);
	}
}

int session_start_read(struct session *session)
{
	return io_start_read(session->handle);
}

int session_stop_read(struct session *session)
{
	return io_stop_read(session->handle);
}

int session_waitinglist_push(struct session *session, struct qr_task *task)
{
	queue_push(session->waiting, task);
	worker_task_ref(task);
	return kr_ok();
}

struct qr_task *session_waitinglist_get(const struct session *session)
{
	return (queue_len(session->waiting) > 0) ? (queue_head(session->waiting)) : NULL;
}

struct qr_task *session_waitinglist_pop(struct session *session, bool deref)
{
	struct qr_task *t = session_waitinglist_get(session);
	queue_pop(session->waiting);
	if (deref) {
		worker_task_unref(t);
	}
	return t;
}

int session_tasklist_add(struct session *session, struct qr_task *task)
{
	trie_t *t = session->tasks;
	uint16_t task_msg_id = 0;
	const char *key = NULL;
	size_t key_len = 0;
	if (session->sflags.outgoing) {
		knot_pkt_t *pktbuf = worker_task_get_pktbuf(task);
		task_msg_id = knot_wire_get_id(pktbuf->wire);
		key = (const char *)&task_msg_id;
		key_len = sizeof(task_msg_id);
	} else {
		key = (const char *)&task;
		key_len = sizeof(char *);
	}
	trie_val_t *v = trie_get_ins(t, key, key_len);
	if (kr_fails_assert(v))
		return kr_error(ENOMEM);
	if (*v == NULL) {
		*v = task;
		worker_task_ref(task);
	} else if (kr_fails_assert(*v == task)) {
		return kr_error(EINVAL);
	}
	return kr_ok();
}

int session_tasklist_del(struct session *session, struct qr_task *task)
{
	trie_t *t = session->tasks;
	uint16_t task_msg_id = 0;
	const char *key = NULL;
	size_t key_len = 0;
	trie_val_t val;
	if (session->sflags.outgoing) {
		knot_pkt_t *pktbuf = worker_task_get_pktbuf(task);
		task_msg_id = knot_wire_get_id(pktbuf->wire);
		key = (const char *)&task_msg_id;
		key_len = sizeof(task_msg_id);
	} else {
		key = (const char *)&task;
		key_len = sizeof(char *);
	}
	int ret = trie_del(t, key, key_len, &val);
	if (ret == KNOT_EOK) {
		kr_require(val == task);
		worker_task_unref(val);
	}
	return ret;
}

struct qr_task *session_tasklist_get_first(struct session *session)
{
	trie_val_t *val = trie_get_first(session->tasks, NULL, NULL);
	return val ? (struct qr_task *) *val : NULL;
}

struct qr_task *session_tasklist_del_first(struct session *session, bool deref)
{
	trie_val_t val = NULL;
	int res = trie_del_first(session->tasks, NULL, NULL, &val);
	if (res != KNOT_EOK) {
		val = NULL;
	} else if (deref) {
		worker_task_unref(val);
	}
	return (struct qr_task *)val;
}
struct qr_task* session_tasklist_del_msgid(const struct session *session, uint16_t msg_id)
{
	if (kr_fails_assert(session->sflags.outgoing))
		return NULL;
	trie_t *t = session->tasks;
	struct qr_task *ret = NULL;
	const char *key = (const char *)&msg_id;
	size_t key_len = sizeof(msg_id);
	trie_val_t val;
	int res = trie_del(t, key, key_len, &val);
	if (res == KNOT_EOK) {
		if (worker_task_numrefs(val) > 1) {
			ret = val;
		}
		worker_task_unref(val);
	}
	return ret;
}

struct qr_task* session_tasklist_find_msgid(const struct session *session, uint16_t msg_id)
{
	if (kr_fails_assert(session->sflags.outgoing))
		return NULL;
	trie_t *t = session->tasks;
	struct qr_task *ret = NULL;
	trie_val_t *val = trie_get_try(t, (char *)&msg_id, sizeof(msg_id));
	if (val) {
		ret = *val;
	}
	return ret;
}

struct session_flags *session_flags(struct session *session)
{
	return &session->sflags;
}

struct sockaddr *session_get_peer(struct session *session)
{
	return &session->peer.ip;
}

struct sockaddr *session_get_sockname(struct session *session)
{
	return &session->sockname.ip;
}

struct tls_ctx *session_tls_get_server_ctx(const struct session *session)
{
	return session->tls_ctx;
}

void session_tls_set_server_ctx(struct session *session, struct tls_ctx *ctx)
{
	session->tls_ctx = ctx;
}

struct tls_client_ctx *session_tls_get_client_ctx(const struct session *session)
{
	return session->tls_client_ctx;
}

void session_tls_set_client_ctx(struct session *session, struct tls_client_ctx *ctx)
{
	session->tls_client_ctx = ctx;
}

struct tls_common_ctx *session_tls_get_common_ctx(const struct session *session)
{
	struct tls_common_ctx *tls_ctx = session->sflags.outgoing ? &session->tls_client_ctx->c :
								    &session->tls_ctx->c;
	return tls_ctx;
}

#if ENABLE_DOH2
struct http_ctx *session_http_get_server_ctx(const struct session *session)
{
	return session->http_ctx;
}

void session_http_set_server_ctx(struct session *session, struct http_ctx *ctx)
{
	session->http_ctx = ctx;
}
#endif

uv_handle_t *session_get_handle(struct session *session)
{
	return session->handle;
}

struct session *session_get(uv_handle_t *h)
{
	return h->data;
}

struct session *session_new(uv_handle_t *handle, bool has_tls, bool has_http)
{
	if (!handle) {
		return NULL;
	}
	struct session *session = calloc(1, sizeof(struct session));
	if (!session) {
		return NULL;
	}

	queue_init(session->waiting);
	session->tasks = trie_create(NULL);
	if (handle->type == UV_TCP) {
		size_t wire_buffer_size = KNOT_WIRE_MAX_PKTSIZE;
		if (has_tls) {
			/* When decoding large packets,
			 * gnutls gives the application chunks of size 16 kb each. */
			wire_buffer_size += TLS_CHUNK_SIZE;
			session->sflags.has_tls = true;
		}
#if ENABLE_DOH2
		if (has_http) {
			/* When decoding large packets,
			 * HTTP/2 frames can be up to 16 KB by default. */
			wire_buffer_size += HTTP_MAX_FRAME_SIZE;
			session->sflags.has_http = true;
		}
#endif
		uint8_t *wire_buf = malloc(wire_buffer_size);
		if (!wire_buf) {
			free(session);
			return NULL;
		}
		session->wire_buf = wire_buf;
		session->wire_buf_size = wire_buffer_size;
	} else if (handle->type == UV_UDP) {
		/* We use the singleton buffer from worker for all UDP (!)
		 * libuv documentation doesn't really guarantee this is OK,
		 * but the implementation for unix systems does not hold
		 * the buffer (both UDP and TCP) - always makes a NON-blocking
		 * syscall that fills the buffer and immediately calls
		 * the callback, whatever the result of the operation.
		 * We still need to keep in mind to only touch the buffer
		 * in this callback... */
		kr_require(the_worker);
		session->wire_buf = the_worker->wire_buf;
		session->wire_buf_size = sizeof(the_worker->wire_buf);
	} else {
		kr_assert(handle->type == UV_POLL/*XDP*/);
		/* - wire_buf* are left zeroed, as they make no sense
		 * - timer is unused but OK for simplicity (server-side sessions are few)
		 */
	}

	uv_timer_init(handle->loop, &session->timeout);

	session->handle = handle;
	handle->data = session;
	session->timeout.data = session;
	session_touch(session);

	return session;
}

size_t session_tasklist_get_len(const struct session *session)
{
	return trie_weight(session->tasks);
}

size_t session_waitinglist_get_len(const struct session *session)
{
	return queue_len(session->waiting);
}

bool session_tasklist_is_empty(const struct session *session)
{
	return session_tasklist_get_len(session) == 0;
}

bool session_waitinglist_is_empty(const struct session *session)
{
	return session_waitinglist_get_len(session) == 0;
}

bool session_is_empty(const struct session *session)
{
	return session_tasklist_is_empty(session) &&
	       session_waitinglist_is_empty(session);
}

bool session_has_tls(const struct session *session)
{
	return session->sflags.has_tls;
}

void session_set_has_tls(struct session *session, bool has_tls)
{
	session->sflags.has_tls = has_tls;
}

void session_waitinglist_retry(struct session *session, bool increase_timeout_cnt)
{
	while (!session_waitinglist_is_empty(session)) {
		struct qr_task *task = session_waitinglist_pop(session, false);
		if (increase_timeout_cnt) {
			worker_task_timeout_inc(task);
		}
		worker_task_step(task, &session->peer.ip, NULL);
		worker_task_unref(task);
	}
}

void session_waitinglist_finalize(struct session *session, int status)
{
	while (!session_waitinglist_is_empty(session)) {
		struct qr_task *t = session_waitinglist_pop(session, false);
		worker_task_finalize(t, status);
		worker_task_unref(t);
	}
}

void session_tasklist_finalize(struct session *session, int status)
{
	while (session_tasklist_get_len(session) > 0) {
		struct qr_task *t = session_tasklist_del_first(session, false);
		kr_require(worker_task_numrefs(t) > 0);
		worker_task_finalize(t, status);
		worker_task_unref(t);
	}
}

int session_tasklist_finalize_expired(struct session *session)
{
	int ret = 0;
	queue_t(struct qr_task *) q;
	uint64_t now = kr_now();
	trie_t *t = session->tasks;
	trie_it_t *it;
	queue_init(q);
	for (it = trie_it_begin(t); !trie_it_finished(it); trie_it_next(it)) {
		trie_val_t *v = trie_it_val(it);
		struct qr_task *task = (struct qr_task *)*v;
		if ((now - worker_task_creation_time(task)) >= KR_RESOLVE_TIME_LIMIT) {
			queue_push(q, task);
			worker_task_ref(task);
		}
	}
	trie_it_free(it);

	struct qr_task *task = NULL;
	uint16_t msg_id = 0;
	char *key = (char *)&task;
	int32_t keylen = sizeof(struct qr_task *);
	if (session->sflags.outgoing) {
		key = (char *)&msg_id;
		keylen = sizeof(msg_id);
	}
	while (queue_len(q) > 0) {
		task = queue_head(q);
		if (session->sflags.outgoing) {
			knot_pkt_t *pktbuf = worker_task_get_pktbuf(task);
			msg_id = knot_wire_get_id(pktbuf->wire);
		}
		int res = trie_del(t, key, keylen, NULL);
		if (!worker_task_finished(task)) {
			/* task->pending_count must be zero,
			 * but there are can be followers,
			 * so run worker_task_subreq_finalize() to ensure retrying
			 * for all the followers. */
			worker_task_subreq_finalize(task);
			worker_task_finalize(task, KR_STATE_FAIL);
		}
		if (res == KNOT_EOK) {
			worker_task_unref(task);
		}
		queue_pop(q);
		worker_task_unref(task);
		++ret;
	}

	queue_deinit(q);
	return ret;
}

int session_timer_start(struct session *session, uv_timer_cb cb,
			uint64_t timeout, uint64_t repeat)
{
	uv_timer_t *timer = &session->timeout;
	// Session might be closing and get here e.g. through a late on_send callback.
	const bool is_closing = uv_is_closing((uv_handle_t *)timer);
	if (is_closing || kr_fails_assert(is_closing == session->sflags.closing))
		return kr_error(EINVAL);

	if (kr_fails_assert(timer->data == session))
		return kr_error(EINVAL);
	int ret = uv_timer_start(timer, cb, timeout, repeat);
	if (ret != 0) {
		uv_timer_stop(timer);
		return kr_error(ret);
	}
	return kr_ok();
}

int session_timer_restart(struct session *session)
{
	kr_require(!uv_is_closing((uv_handle_t *)&session->timeout));
	return uv_timer_again(&session->timeout);
}

int session_timer_stop(struct session *session)
{
	return uv_timer_stop(&session->timeout);
}

ssize_t session_wirebuf_consume(struct session *session, const uint8_t *data, ssize_t len)
{
	if (data != &session->wire_buf[session->wire_buf_end_idx]) {
		/* shouldn't happen */
		return kr_error(EINVAL);
	}

	if (len < 0) {
		/* shouldn't happen */
		return kr_error(EINVAL);
	}

	if (session->wire_buf_end_idx + len > session->wire_buf_size) {
		/* shouldn't happen */
		return kr_error(EINVAL);
	}

	session->wire_buf_end_idx += len;
	return len;
}

knot_pkt_t *session_produce_packet(struct session *session, knot_mm_t *mm)
{
	session->sflags.wirebuf_error = false;
	if (session->wire_buf_end_idx == 0) {
		return NULL;
	}

	if (session->wire_buf_start_idx == session->wire_buf_end_idx) {
		session->wire_buf_start_idx = 0;
		session->wire_buf_end_idx = 0;
		return NULL;
	}

	if (session->wire_buf_start_idx > session->wire_buf_end_idx) {
		session->sflags.wirebuf_error = true;
		session->wire_buf_start_idx = 0;
		session->wire_buf_end_idx = 0;
		return NULL;
	}

	const uv_handle_t *handle = session->handle;
	uint8_t *msg_start = &session->wire_buf[session->wire_buf_start_idx];
	ssize_t wirebuf_msg_data_size = session->wire_buf_end_idx - session->wire_buf_start_idx;
	uint16_t msg_size = 0;

	if (!handle) {
		session->sflags.wirebuf_error = true;
		return NULL;
	} else if (handle->type == UV_TCP) {
		if (wirebuf_msg_data_size < 2) {
			return NULL;
		}
		msg_size = knot_wire_read_u16(msg_start);
		if (msg_size >= session->wire_buf_size) {
			session->sflags.wirebuf_error = true;
			return NULL;
		}
		if (msg_size + 2 > wirebuf_msg_data_size) {
			return NULL;
		}
		if (msg_size == 0) {
			session->sflags.wirebuf_error = true;
			return NULL;
		}
		msg_start += 2;
	} else if (wirebuf_msg_data_size < UINT16_MAX) {
		msg_size = wirebuf_msg_data_size;
	} else {
		session->sflags.wirebuf_error = true;
		return NULL;
	}


	knot_pkt_t *pkt = knot_pkt_new(msg_start, msg_size, mm);
	session->sflags.wirebuf_error = (pkt == NULL);
	return pkt;
}

int session_discard_packet(struct session *session, const knot_pkt_t *pkt)
{
	uv_handle_t *handle = session->handle;
	/* Pointer to data start in wire_buf */
	uint8_t *wirebuf_data_start = &session->wire_buf[session->wire_buf_start_idx];
	/* Number of data bytes in wire_buf */
	size_t wirebuf_data_size = session->wire_buf_end_idx - session->wire_buf_start_idx;
	/* Pointer to message start in wire_buf */
	uint8_t *wirebuf_msg_start = wirebuf_data_start;
	/* Number of message bytes in wire_buf.
	 * For UDP it is the same number as wirebuf_data_size. */
	size_t wirebuf_msg_size = wirebuf_data_size;
	/* Wire data from parsed packet. */
	uint8_t *pkt_msg_start = pkt->wire;
	/* Number of bytes in packet wire buffer. */
	size_t pkt_msg_size = pkt->size;
	if (knot_pkt_has_tsig(pkt)) {
		pkt_msg_size += pkt->tsig_wire.len;
	}

	session->sflags.wirebuf_error = true;

	if (!handle) {
		return kr_error(EINVAL);
	} else if (handle->type == UV_TCP) {
		/* wire_buf contains TCP DNS message. */
		if (kr_fails_assert(wirebuf_data_size >= 2)) {
			/* TCP message length field isn't in buffer, must not happen. */
			session->wire_buf_start_idx = 0;
			session->wire_buf_end_idx = 0;
			return kr_error(EINVAL);
		}
		wirebuf_msg_size = knot_wire_read_u16(wirebuf_msg_start);
		wirebuf_msg_start += 2;
		if (kr_fails_assert(wirebuf_msg_size + 2 <= wirebuf_data_size)) {
			/* TCP message length field is greater then
			 * number of bytes in buffer, must not happen. */
			session->wire_buf_start_idx = 0;
			session->wire_buf_end_idx = 0;
			return kr_error(EINVAL);
		}
	}

	if (kr_fails_assert(wirebuf_msg_start == pkt_msg_start)) {
		/* packet wirebuf must be located at the beginning
		 * of the session wirebuf, must not happen. */
		session->wire_buf_start_idx = 0;
		session->wire_buf_end_idx = 0;
		return kr_error(EINVAL);
	}

	if (kr_fails_assert(wirebuf_msg_size >= pkt_msg_size)) {
		/* Message length field is lesser then packet size,
		 * must not happen. */
		session->wire_buf_start_idx = 0;
		session->wire_buf_end_idx = 0;
		return kr_error(EINVAL);
	}

	if (handle->type == UV_TCP) {
		session->wire_buf_start_idx += wirebuf_msg_size + 2;
	} else {
		session->wire_buf_start_idx += pkt_msg_size;
	}
	session->sflags.wirebuf_error = false;

	wirebuf_data_size = session->wire_buf_end_idx - session->wire_buf_start_idx;
	if (wirebuf_data_size == 0) {
		session_wirebuf_discard(session);
	} else if (wirebuf_data_size < KNOT_WIRE_HEADER_SIZE) {
		session_wirebuf_compress(session);
	}

	return kr_ok();
}

void session_wirebuf_discard(struct session *session)
{
	session->wire_buf_start_idx = 0;
	session->wire_buf_end_idx = 0;
}

void session_wirebuf_compress(struct session *session)
{
	if (session->wire_buf_start_idx == 0) {
		return;
	}
	uint8_t *wirebuf_data_start = &session->wire_buf[session->wire_buf_start_idx];
	size_t wirebuf_data_size = session->wire_buf_end_idx - session->wire_buf_start_idx;
	if (session->wire_buf_start_idx < wirebuf_data_size) {
		memmove(session->wire_buf, wirebuf_data_start, wirebuf_data_size);
	} else {
		memcpy(session->wire_buf, wirebuf_data_start, wirebuf_data_size);
	}
	session->wire_buf_start_idx = 0;
	session->wire_buf_end_idx = wirebuf_data_size;
}

bool session_wirebuf_error(struct session *session)
{
	return session->sflags.wirebuf_error;
}

uint8_t *session_wirebuf_get_start(struct session *session)
{
	return session->wire_buf;
}

size_t session_wirebuf_get_size(struct session *session)
{
	return session->wire_buf_size;
}

uint8_t *session_wirebuf_get_free_start(struct session *session)
{
	return &session->wire_buf[session->wire_buf_end_idx];
}

size_t session_wirebuf_get_free_size(struct session *session)
{
	return session->wire_buf_size - session->wire_buf_end_idx;
}

void session_poison(struct session *session)
{
	kr_asan_poison(session, sizeof(*session));
}

void session_unpoison(struct session *session)
{
	kr_asan_unpoison(session, sizeof(*session));
}

int session_wirebuf_process(struct session *session, const struct sockaddr *peer)
{
	int ret = 0;
	if (session->wire_buf_start_idx == session->wire_buf_end_idx)
		return ret;

	size_t wirebuf_data_size = session->wire_buf_end_idx - session->wire_buf_start_idx;
	uint32_t max_iterations = (wirebuf_data_size /
		(KNOT_WIRE_HEADER_SIZE + KNOT_WIRE_QUESTION_MIN_SIZE)) + 1;
	knot_pkt_t *pkt = NULL;

	while (((pkt = session_produce_packet(session, &the_worker->pkt_pool)) != NULL) &&
	       (ret < max_iterations)) {
		if (kr_fails_assert(!session_wirebuf_error(session)))
			return -1;
		int res = worker_submit(session, peer, NULL, NULL, NULL, pkt);
		/* Errors from worker_submit() are intetionally *not* handled in order to
		 * ensure the entire wire buffer is processed. */
		if (res == kr_ok())
			ret += 1;
		if (session_discard_packet(session, pkt) < 0) {
			/* Packet data isn't stored in memory as expected.
			 * something went wrong, normally should not happen. */
			break;
		}
	}

	/* worker_submit() may cause the session to close (e.g. due to IO
	 * write error when the packet triggers an immediate answer). This is
	 * an error state, as well as any wirebuf error. */
	if (session->sflags.closing || session_wirebuf_error(session))
		ret = -1;

	return ret;
}

void session_kill_ioreq(struct session *session, struct qr_task *task)
{
	if (!session || session->sflags.closing)
		return;
	if (kr_fails_assert(session->sflags.outgoing && session->handle))
		return;
	session_tasklist_del(session, task);
	if (session->handle->type == UV_UDP) {
		session_close(session);
		return;
	}
}

/** Update timestamp */
void session_touch(struct session *session)
{
	session->last_activity = kr_now();
}

uint64_t session_last_activity(struct session *session)
{
	return session->last_activity;
}
