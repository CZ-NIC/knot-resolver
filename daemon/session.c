#include <assert.h>

#include <libknot/packet/pkt.h>

#include "lib/defines.h"
#include "daemon/session.h"
#include "daemon/engine.h"
#include "daemon/tls.h"
#include "daemon/worker.h"
#include "daemon/io.h"

/** List of tasks. */
typedef array_t(struct qr_task *) session_tasklist_t;

/* Per-session (TCP or UDP) persistent structure,
 * that exists between remote counterpart and a local socket.
 */
struct session {
	struct session_flags sflags; /**< miscellaneous flags. */
	union inaddr peer;           /**< address of peer; is not set for client's UDP sessions. */
	uv_handle_t *handle;         /**< libuv handle for IO operations. */
	uv_timer_t timeout;          /**< libuv handle for timer. */

	struct tls_ctx_t *tls_ctx;   /**< server side tls-related data. */
	struct tls_client_ctx_t *tls_client_ctx; /**< client side tls-related data. */

	session_tasklist_t tasks;    /**< list of tasks which assotiated with given session. */
	session_tasklist_t waiting;  /**< list of tasks been waiting for IO (subset of taska). */

	uint8_t *wire_buf;           /**< Buffer for DNS message. */
	ssize_t wire_buf_size;       /**< Buffer size. */
	ssize_t wire_buf_start_idx;  /**< Data start offset in wire_buf. */
	ssize_t wire_buf_end_idx;    /**< Data end offset in wire_buf. */
};

static void on_session_close(uv_handle_t *handle)
{
	struct session *session = handle->data;
	assert(session->handle == handle); (void)session;
	io_free(handle);
}

static void on_session_timer_close(uv_handle_t *timer)
{
	struct session *session = timer->data;
	uv_handle_t *handle = session->handle;
	assert(handle && handle->data == session);
	assert (session->sflags.outgoing || handle->type == UV_TCP);
	if (!uv_is_closing(handle)) {
		uv_close(handle, on_session_close);
	}
}

void session_free(struct session *session)
{
	if (session) {
		assert(session->tasks.len == 0 && session->waiting.len == 0);
		session_clear(session);
		free(session);
	}
}

void session_clear(struct session *session)
{
	assert(session->tasks.len == 0 && session->waiting.len == 0);
	if (session->handle && session->handle->type == UV_TCP) {
		free(session->wire_buf);
	}
	array_clear(session->tasks);
	array_clear(session->waiting);
	tls_free(session->tls_ctx);
	tls_client_ctx_free(session->tls_client_ctx);
	memset(session, 0, sizeof(*session));
}

struct session *session_new(void)
{
	return calloc(1, sizeof(struct session));
}

void session_close(struct session *session)
{
	assert(session->tasks.len == 0 && session->waiting.len == 0);

	if (session->sflags.closing) {
		return;
	}

	uv_handle_t *handle = session->handle;
	io_stop_read(handle);
	session->sflags.closing = true;
	if (session->sflags.outgoing &&
	    session->peer.ip.sa_family != AF_UNSPEC) {
		struct worker_ctx *worker = handle->loop->data;
		struct sockaddr *peer = &session->peer.ip;
		worker_del_tcp_connected(worker, peer);
		session->sflags.connected = false;
	}

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

int session_waitinglist_add(struct session *session, struct qr_task *task)
{
	for (int i = 0; i < session->waiting.len; ++i) {
		if (session->waiting.at[i] == task) {
			return i;
		}
	}
	int ret = array_push(session->waiting, task);
	if (ret >= 0) {
		worker_task_ref(task);
	}
	return ret;
}

int session_waitinglist_del(struct session *session, struct qr_task *task)
{
	int ret = kr_error(ENOENT);
	for (int i = 0; i < session->waiting.len; ++i) {
		if (session->waiting.at[i] == task) {
			array_del(session->waiting, i);
			worker_task_unref(task);
			ret = kr_ok();
			break;
		}
	}
	return ret;
}

int session_waitinglist_del_index(struct session *session, int index)
{
	int ret = kr_error(ENOENT);
	if (index < session->waiting.len) {
		struct qr_task *task = session->waiting.at[index];
		array_del(session->waiting, index);
		worker_task_unref(task);
		ret = kr_ok();
	}
	return ret;
}

int session_tasklist_add(struct session *session, struct qr_task *task)
{
	for (int i = 0; i < session->tasks.len; ++i) {
		if (session->tasks.at[i] == task) {
			return i;
		}
	}
	int ret = array_push(session->tasks, task);
	if (ret >= 0) {
		worker_task_ref(task);
	}
	return ret;
}

int session_tasklist_del(struct session *session, struct qr_task *task)
{
	int ret = kr_error(ENOENT);
	for (int i = 0; i < session->tasks.len; ++i) {
		if (session->tasks.at[i] == task) {
			array_del(session->tasks, i);
			worker_task_unref(task);
			ret = kr_ok();
			break;
		}
	}
	return ret;
}

int session_tasklist_del_index(struct session *session, int index)
{
	int ret = kr_error(ENOENT);
	if (index < session->tasks.len) {
		struct qr_task *task = session->tasks.at[index];
		array_del(session->tasks, index);
		worker_task_unref(task);
		ret = kr_ok();
	}
	return ret;
}

struct qr_task* session_tasklist_find(const struct session *session, uint16_t msg_id)
{
	struct qr_task *ret = NULL;
	const session_tasklist_t *tasklist = &session->tasks;
	for (size_t i = 0; i < tasklist->len; ++i) {
		struct qr_task *task = tasklist->at[i];
		knot_pkt_t *pktbuf = worker_task_get_pktbuf(task);
		uint16_t task_msg_id = knot_wire_get_id(pktbuf->wire);
		if (task_msg_id == msg_id) {
			ret = task;
			break;
		}
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

struct tls_ctx_t *session_tls_get_server_ctx(const struct session *session)
{
	return session->tls_ctx;
}

void session_tls_set_server_ctx(struct session *session, struct tls_ctx_t *ctx)
{
	session->tls_ctx = ctx;
}

struct tls_client_ctx_t *session_tls_get_client_ctx(const struct session *session)
{
	return session->tls_client_ctx;
}

void session_tls_set_client_ctx(struct session *session, struct tls_client_ctx_t *ctx)
{
	session->tls_client_ctx = ctx;
}

struct tls_common_ctx *session_tls_get_common_ctx(const struct session *session)
{
	struct tls_common_ctx *tls_ctx = session->sflags.outgoing ? &session->tls_client_ctx->c :
								    &session->tls_ctx->c;
	return tls_ctx;
}

uv_handle_t *session_get_handle(struct session *session)
{
	return session->handle;
}

int session_set_handle(struct session *session, uv_handle_t *handle)
{
	if (!handle) {
		return kr_error(EINVAL);
	}

	assert(session->handle == NULL);

	if (handle->type == UV_TCP) {
		uint8_t *wire_buf = malloc(KNOT_WIRE_MAX_PKTSIZE);
		if (!wire_buf) {
			return kr_error(ENOMEM);
		}
		session->wire_buf = wire_buf;
		session->wire_buf_size = KNOT_WIRE_MAX_PKTSIZE;
	} else if (handle->type == UV_UDP) {
		/* We use the singleton buffer from worker for all UDP (!)
		 * libuv documentation doesn't really guarantee this is OK,
		 * but the implementation for unix systems does not hold
		 * the buffer (both UDP and TCP) - always makes a NON-blocking
		 * syscall that fills the buffer and immediately calls
		 * the callback, whatever the result of the operation.
		 * We still need to keep in mind to only touch the buffer
		 * in this callback... */
		assert(handle->loop->data);
		struct worker_ctx *worker = handle->loop->data;
		session->wire_buf = worker->wire_buf;
		session->wire_buf_size = sizeof(worker->wire_buf);
	}
	
	session->handle = handle;
	handle->data = session;
	return kr_ok();
}

uv_timer_t *session_get_timer(struct session *session)
{
	return &session->timeout;
}

size_t session_tasklist_get_len(const struct session *session)
{
	return session->tasks.len;
}

size_t session_waitinglist_get_len(const struct session *session)
{
	return session->waiting.len;
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

struct qr_task *session_waitinglist_get_first(const struct session *session)
{
	struct qr_task *t = NULL;
	if (session->waiting.len > 0) {
		t = session->waiting.at[0];
	}
	return t;
}

struct qr_task *session_tasklist_get_first(const struct session *session)
{
	struct qr_task *t = NULL;
	if (session->tasks.len > 0) {
		t = session->tasks.at[0];
	}
	return t;
}

void session_waitinglist_retry(struct session *session, bool increase_timeout_cnt)
{
	while (session->waiting.len > 0) {
		struct qr_task *task = session->waiting.at[0];
		session_tasklist_del(session, task);
		array_del(session->waiting, 0);
		assert(worker_task_numrefs(task) > 1);
		if (increase_timeout_cnt) {
			worker_task_timeout_inc(task);
		}
		worker_task_unref(task);
		worker_task_step(task, NULL, NULL);
	}
}

void session_waitinglist_finalize(struct session *session, int status)
{
	while (session->waiting.len > 0) {
		struct qr_task *t = session->waiting.at[0];
		array_del(session->waiting, 0);
		session_tasklist_del(session, t);
		if (session->sflags.outgoing) {
			worker_task_finalize(t, status);
		} else {
			struct request_ctx *ctx = worker_task_get_request(t);
			assert(worker_request_get_source_session(ctx) == session);
			worker_request_set_source_session(ctx, NULL);
		}
		worker_task_unref(t);
	}
}

void session_tasklist_finalize(struct session *session, int status)
{
	while (session->tasks.len > 0) {
		struct qr_task *t = session->tasks.at[0];
		array_del(session->tasks, 0);
		if (session->sflags.outgoing) {
			worker_task_finalize(t, status);
		} else {
			struct request_ctx *ctx = worker_task_get_request(t);
			assert(worker_request_get_source_session(ctx) == session);
			worker_request_set_source_session(ctx, NULL);
		}
		worker_task_unref(t);
	}
}

void session_tasks_finalize(struct session *session, int status)
{
	session_waitinglist_finalize(session, status);
	session_tasklist_finalize(session, status);
}

int session_timer_start(struct session *session, uv_timer_cb cb,
			uint64_t timeout, uint64_t repeat)
{
	uv_timer_t *timer = &session->timeout;
	assert(timer->data == session);
	int ret = uv_timer_start(timer, cb, timeout, repeat);
	if (ret != 0) {
		uv_timer_stop(timer);
		return kr_error(ENOMEM);
	}
	return 0;
}

int session_timer_restart(struct session *session)
{
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
	uint16_t msg_size = wirebuf_msg_data_size;
	
	if (!handle) {
		session->sflags.wirebuf_error = true;
		return NULL;
	} else if (handle->type == UV_TCP) {
		if (msg_size < 2) {
			return NULL;
		}
		msg_size = knot_wire_read_u16(msg_start);
		if (msg_size + 2 > wirebuf_msg_data_size) {
			session->sflags.wirebuf_error = false;
			return NULL;
		}
		msg_start += 2;
	}

	knot_pkt_t *pkt = knot_pkt_new(msg_start, msg_size, mm);
	if (pkt) {
		session->sflags.wirebuf_error = false;
	}
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
		if (wirebuf_data_size < 2) {
			/* TCP message length field isn't in buffer, must not happen. */
			assert(0);
			session->wire_buf_start_idx = 0;
			session->wire_buf_end_idx = 0;
			return kr_error(EINVAL);
		}
		wirebuf_msg_size = knot_wire_read_u16(wirebuf_msg_start);
		wirebuf_msg_start += 2;
		if (wirebuf_msg_size + 2 > wirebuf_data_size) {
			/* TCP message length field is greater then
			 * number of bytes in buffer, must not happen. */
			assert(0);
			session->wire_buf_start_idx = 0;
			session->wire_buf_end_idx = 0;
			return kr_error(EINVAL);
		}
	}

	if (wirebuf_msg_start != pkt_msg_start) {
		/* packet wirebuf must be located at the beginning
		 * of the session wirebuf, must not happen. */
		assert(0);
		session->wire_buf_start_idx = 0;
		session->wire_buf_end_idx = 0;
		return kr_error(EINVAL);
	}

	if (wirebuf_msg_size < pkt_msg_size) {
		/* Message length field is lesser then packet size,
		 * must not happen. */
		assert(0);
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

size_t session_wirebuf_get_len(struct session *session)
{
	return session->wire_buf_end_idx;
}

size_t session_wirebuf_get_size(struct session *session)
{
	return sizeof(session->wire_buf);
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

int session_wirebuf_process(struct session *session)
{
	int ret = 0;
	if (session->wire_buf_start_idx == session->wire_buf_end_idx) {
		return ret;
	}
	struct worker_ctx *worker = session_get_handle(session)->loop->data;
	knot_pkt_t *query = NULL;
	while (((query = session_produce_packet(session, &worker->pkt_pool)) != NULL) && (ret < 100)) {
		assert (!session_wirebuf_error(session));
		worker_submit(session, query);
		if (session_discard_packet(session, query) < 0) {
			break;
		}
		ret += 1;
	}
	if (session_wirebuf_error(session)) {
		ret = -1;
	}
	return ret;
}

static void on_session_idle_timeout(uv_timer_t *timer)
{
	struct session *s = timer->data;
	assert(s);
	uv_timer_stop(timer);
	if (s->sflags.closing) {
		return;
	}
	/* session was not in use during timer timeout
	 * remove it from connection list and close
	 */
	assert(session_is_empty(s));
	session_close(s);
}

void session_kill_ioreq(struct session *s, struct qr_task *task)
{
	assert(s && s->sflags.outgoing && s->handle);
	if (s->sflags.closing) {
		return;
	}
	if (s->handle->type == UV_UDP) {
		uv_timer_stop(&s->timeout);
		session_tasklist_del(s, task);
		assert(session_tasklist_is_empty(s));
		session_close(s);
		return;
	}
	/* TCP-specific code now. */
	if (s->handle->type != UV_TCP) abort();
	session_waitinglist_del(s, task);
	session_tasklist_del(s, task);

	int res = 0;

	const struct sockaddr *peer = &s->peer.ip;
	if (peer->sa_family != AF_UNSPEC && session_is_empty(s) && !s->sflags.closing) {
		assert(peer->sa_family == AF_INET || peer->sa_family == AF_INET6);
		res = 1;
		if (s->sflags.connected) {
			/* This is outbound TCP connection which can be reused.
			* Close it after timeout */
			s->timeout.data = s;
			uv_timer_stop(&s->timeout);
			res = uv_timer_start(&s->timeout, on_session_idle_timeout,
					     KR_CONN_RTT_MAX, 0);
		}
	}

	if (res != 0) {
		/* if any errors, close the session immediately */
		session_close(s);
	}
}

