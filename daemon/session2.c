/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <ucw/lib.h>
#include <sys/socket.h>

#include "lib/log.h"
#include "lib/utils.h"
#include "daemon/io.h"
#include "daemon/udp_queue.h"
#include "daemon/worker.h"

#include "daemon/session2.h"


static int session2_transport_pushv(struct session2 *s,
                                    struct iovec *iov, int iovcnt,
                                    const void *target,
                                    protolayer_finished_cb cb, void *baton);
static inline int session2_transport_push(struct session2 *s,
                                          char *buf, size_t buf_len,
                                          const void *target,
                                          protolayer_finished_cb cb, void *baton);
static int session2_transport_event(struct session2 *s,
                                    enum protolayer_event_type event,
                                    void *baton);

struct protolayer_globals protolayer_globals[PROTOLAYER_PROTOCOL_COUNT] = {0};


enum protolayer_protocol protolayer_grp_doudp[] = {
	PROTOLAYER_UDP,
	PROTOLAYER_DNS_DGRAM,
	PROTOLAYER_NULL
};

enum protolayer_protocol protolayer_grp_dotcp[] = {
	PROTOLAYER_TCP,
	PROTOLAYER_DNS_MSTREAM,
	PROTOLAYER_NULL
};

enum protolayer_protocol protolayer_grp_dot[] = {
	PROTOLAYER_TCP,
	PROTOLAYER_TLS,
	PROTOLAYER_DNS_MSTREAM,
	PROTOLAYER_NULL
};

enum protolayer_protocol protolayer_grp_doh[] = {
	PROTOLAYER_TCP,
	PROTOLAYER_TLS,
	PROTOLAYER_HTTP,
	PROTOLAYER_DNS_DGRAM,
	PROTOLAYER_NULL
};


enum protolayer_protocol *protolayer_grps[PROTOLAYER_GRP_COUNT] = {
#define XX(cid, vid, name) [PROTOLAYER_GRP_##cid] = protolayer_grp_##vid,
	PROTOLAYER_GRP_MAP(XX)
#undef XX
};

char *protolayer_grp_names[PROTOLAYER_GRP_COUNT] = {
	[PROTOLAYER_GRP_NULL] = "(null)",
#define XX(cid, vid, name) [PROTOLAYER_GRP_##cid] = name,
	PROTOLAYER_GRP_MAP(XX)
#undef XX
};

char *protolayer_event_names[PROTOLAYER_EVENT_COUNT] = {
	[PROTOLAYER_EVENT_NULL] = "(null)",
#define XX(cid) [PROTOLAYER_EVENT_##cid] = #cid,
	PROTOLAYER_EVENT_MAP(XX)
#undef XX
};

char *protolayer_payload_names[PROTOLAYER_PAYLOAD_COUNT] = {
	[PROTOLAYER_PAYLOAD_NULL] = "(null)",
#define XX(cid, name) [PROTOLAYER_PAYLOAD_##cid] = name,
	PROTOLAYER_PAYLOAD_MAP(XX)
#undef XX
};


struct protolayer_payload protolayer_as_buffer(const struct protolayer_payload *payload)
{
	if (payload->type == PROTOLAYER_PAYLOAD_BUFFER)
		return *payload;

	if (payload->type == PROTOLAYER_PAYLOAD_WIRE_BUF) {
		struct protolayer_payload new_payload = {
			.type = PROTOLAYER_PAYLOAD_BUFFER,
			.buffer = {
				.buf = wire_buf_data(payload->wire_buf),
				.len = wire_buf_data_length(payload->wire_buf)
			}
		};
		wire_buf_reset(payload->wire_buf);
		return new_payload;
	}

	kr_assert(false && "Unsupported payload type.");
	return (struct protolayer_payload){
		.type = PROTOLAYER_PAYLOAD_NULL
	};
}


/** Gets layer-specific session data for the layer with the specified index
 * from the manager. */
static inline struct protolayer_data *protolayer_sess_data_get(
		struct protolayer_manager *m, size_t layer_ix)
{
	if (kr_fails_assert(layer_ix < m->num_layers))
		return NULL;

	/* See doc comment of `struct protolayer_manager::data` */
	const ssize_t *offsets = (ssize_t *)m->data;
	char *pl_data_beg = &m->data[2 * m->num_layers * sizeof(*offsets)];
	ssize_t offset = offsets[layer_ix];

	if (offset < 0) /* No session data for this layer */
		return NULL;

	return (struct protolayer_data *)(pl_data_beg + offset);
}

/** Gets layer-specific iteration data for the layer with the specified index
 * from the context. */
static inline struct protolayer_data *protolayer_iter_data_get(
		struct protolayer_cb_ctx *ctx, size_t layer_ix)
{
	struct protolayer_manager *m = ctx->manager;
	if (kr_fails_assert(layer_ix < m->num_layers))
		return NULL;

	/* See doc comment of `struct protolayer_manager::data` */
	const ssize_t *offsets = (ssize_t *)&m->data[m->num_layers * sizeof(*offsets)];
	ssize_t offset = offsets[layer_ix];

	if (offset < 0) /* No iteration data for this layer */
		return NULL;

	return (struct protolayer_data *)(ctx->data + offset);
}

static inline ssize_t protolayer_manager_get_protocol(
		struct protolayer_manager *m, enum protolayer_protocol protocol)
{
	for (ssize_t i = 0; i < m->num_layers; i++) {
		enum protolayer_protocol found = protolayer_grps[m->grp][i];
		if (protocol == found)
			return i;
	}

	return -1;
}

static inline bool protolayer_cb_ctx_is_last(struct protolayer_cb_ctx *ctx)
{
	unsigned int last_ix = (ctx->direction == PROTOLAYER_UNWRAP)
		? ctx->manager->num_layers - 1
		: 0;
	return ctx->layer_ix == last_ix;
}

static inline void protolayer_cb_ctx_next(struct protolayer_cb_ctx *ctx)
{
	if (ctx->direction == PROTOLAYER_UNWRAP)
		ctx->layer_ix++;
	else
		ctx->layer_ix--;
}

static int protolayer_cb_ctx_finish(struct protolayer_cb_ctx *ctx, int ret)
{
	struct session2 *session = ctx->manager->session;

	struct protolayer_manager *m = ctx->manager;
	struct protolayer_globals *globals = &protolayer_globals[m->grp];
	for (size_t i = 0; i < m->num_layers; i++) {
		struct protolayer_data *d = protolayer_iter_data_get(ctx, i);
		if (globals->iter_deinit)
			globals->iter_deinit(m, d);
	}

	if (ret)
		kr_log_debug(PROTOLAYER, "layer context of group '%s' ended with return code %d\n",
				protolayer_grp_names[ctx->manager->grp], ret);

	if (ctx->status)
		kr_log_debug(PROTOLAYER, "iteration of group '%s' layer %u ended with status %d\n",
				protolayer_grp_names[ctx->manager->grp], ctx->layer_ix, ctx->status);

	if (ctx->finished_cb)
		ctx->finished_cb(ret, session, ctx->finished_cb_target,
				ctx->finished_cb_baton);

	free(ctx);

	return ret;
}

static void protolayer_push_finished(int status, struct session2 *s, const void *target, void *baton)
{
	struct protolayer_cb_ctx *ctx = baton;
	ctx->status = status;
	protolayer_cb_ctx_finish(ctx, PROTOLAYER_RET_NORMAL);
}

/** Pushes the specified protocol layer's payload to the session's transport. */
static int protolayer_push(struct protolayer_cb_ctx *ctx)
{
	struct session2 *session = ctx->manager->session;

	if (ctx->payload.type == PROTOLAYER_PAYLOAD_WIRE_BUF) {
		ctx->payload = protolayer_as_buffer(&ctx->payload);
	}

	if (kr_log_is_debug(PROTOLAYER, NULL)) {
		kr_log_debug(PROTOLAYER, "Pushing %s\n",
				protolayer_payload_names[ctx->payload.type]);
	}

	int status;
	if (ctx->payload.type == PROTOLAYER_PAYLOAD_BUFFER) {
		status = session2_transport_push(session,
				ctx->payload.buffer.buf, ctx->payload.buffer.len,
				ctx->target, protolayer_push_finished, ctx);
	} else if (ctx->payload.type == PROTOLAYER_PAYLOAD_IOVEC) {
		status = session2_transport_pushv(session,
				ctx->payload.iovec.iov, ctx->payload.iovec.cnt,
				ctx->target, protolayer_push_finished, ctx);
	} else {
		kr_assert(false && "Invalid payload type");
		status = kr_error(EINVAL);
	}

	if (status < 0) {
		ctx->status = status;
		return protolayer_cb_ctx_finish(ctx, status);
	}

	return PROTOLAYER_RET_ASYNC;
}

/** Processes as many layers as possible synchronously, returning when either
 * a layer has gone asynchronous, or when the whole sequence has finished.
 *
 * May be called multiple times on the same `ctx` to continue processing
 * after an asynchronous operation. */
static int protolayer_step(struct protolayer_cb_ctx *ctx)
{
	while (true) {
		enum protolayer_protocol protocol = protolayer_grps[ctx->manager->grp][ctx->layer_ix];
		struct protolayer_globals *globals = &protolayer_globals[protocol];

		ctx->async_mode = false;
		ctx->status = 0;
		ctx->action = PROTOLAYER_CB_ACTION_NULL;

		protolayer_cb cb = (ctx->direction == PROTOLAYER_UNWRAP)
			? globals->unwrap : globals->wrap;

		if (cb) {
			struct protolayer_data *sess_data = protolayer_sess_data_get(
					ctx->manager, ctx->layer_ix);
			struct protolayer_data *iter_data = protolayer_iter_data_get(
					ctx, ctx->layer_ix);
			enum protolayer_cb_result result = cb(sess_data, iter_data, ctx);
			if (kr_fails_assert(result == PROTOLAYER_CB_RESULT_MAGIC)) {
				/* Callback did not use a continuation function to return. */
				return protolayer_cb_ctx_finish(ctx, kr_error(EINVAL));
			}
		} else {
			ctx->action = PROTOLAYER_CB_ACTION_CONTINUE;
		}


		if (!ctx->action) {
			/* Next step is from a callback */
			ctx->async_mode = true;
			return PROTOLAYER_RET_ASYNC;
		}

		if (ctx->action == PROTOLAYER_CB_ACTION_BREAK) {
			return protolayer_cb_ctx_finish(
					ctx, PROTOLAYER_RET_NORMAL);
		}

		if (kr_fails_assert(ctx->status == 0)) {
			/* Status should be zero without a BREAK. */
			return protolayer_cb_ctx_finish(ctx, kr_error(ECANCELED));
		}

		if (ctx->action == PROTOLAYER_CB_ACTION_CONTINUE) {
			if (protolayer_cb_ctx_is_last(ctx)) {
				if (ctx->direction == PROTOLAYER_WRAP)
					return protolayer_push(ctx);

				return protolayer_cb_ctx_finish(
						ctx, PROTOLAYER_RET_NORMAL);
			}

			protolayer_cb_ctx_next(ctx);
			continue;
		}

		/* Should never get here */
		kr_assert(false && "Invalid layer callback action");
		return protolayer_cb_ctx_finish(ctx, kr_error(EINVAL));
	}
}

/** Submits the specified buffer to the sequence of layers represented by the
 * specified protolayer manager. The sequence will be processed in the
 * specified direction.
 *
 * Returns 0 when all layers have finished, 1 when some layers are asynchronous
 * and waiting for continuation, 2 when a layer is waiting for more data,
 * or a negative number for errors (kr_error). */
static int protolayer_manager_submit(
		struct protolayer_manager *manager,
		enum protolayer_direction direction, size_t layer_ix,
		struct protolayer_payload payload, const void *target,
		protolayer_finished_cb cb, void *baton)
{
	struct protolayer_cb_ctx *ctx = malloc(manager->cb_ctx_size);
	kr_require(ctx);

	if (kr_log_is_debug(PROTOLAYER, NULL)) {
		const char *sess_dir = manager->session->outgoing ? "out" : "in";
		kr_log_debug(PROTOLAYER, "[%s] %s submitted to grp '%s' in %s direction (layer %zu)\n",
				sess_dir,
				protolayer_payload_names[payload.type],
				protolayer_grp_names[manager->grp],
				(direction == PROTOLAYER_UNWRAP) ? "unwrap" : "wrap",
				layer_ix);
	}

	*ctx = (struct protolayer_cb_ctx) {
		.payload = payload,
		.target = target,
		.direction = direction,
		.layer_ix = layer_ix,
		.manager = manager,
		.finished_cb = cb,
		.finished_cb_target = target,
		.finished_cb_baton = baton
	};

	for (size_t i = 0; i < manager->num_layers; i++) {
		enum protolayer_protocol p = protolayer_grps[manager->grp][i];
		struct protolayer_globals *globals = &protolayer_globals[p];
		struct protolayer_data *iter_data = protolayer_iter_data_get(ctx, i);
		if (iter_data) {
			bzero(iter_data, globals->iter_size);
			iter_data->protocol = p;
			iter_data->session = manager->session;
		}

		if (globals->iter_init)
			globals->iter_init(manager, iter_data);
	}

	return protolayer_step(ctx);
}

static void *get_init_param(enum protolayer_protocol p,
                            struct protolayer_data_param *layer_param,
                            size_t layer_param_count)
{
	if (!layer_param || !layer_param_count)
		return NULL;
	for (size_t i = 0; i < layer_param_count; i++) {
		if (layer_param[i].protocol == p)
			return layer_param[i].param;
	}
	return NULL;
}

/** Allocates and initializes a new manager. */
static struct protolayer_manager *protolayer_manager_new(
		struct session2 *s,
		enum protolayer_grp grp,
		struct protolayer_data_param *layer_param,
		size_t layer_param_count)
{
	if (kr_fails_assert(s && grp))
		return NULL;

	size_t num_layers = 0;
	size_t manager_size = sizeof(struct protolayer_manager);
	size_t cb_ctx_size = sizeof(struct protolayer_cb_ctx);

	enum protolayer_protocol *protocols = protolayer_grps[grp];
	if (kr_fails_assert(protocols))
		return NULL;
	enum protolayer_protocol *p = protocols;

	/* Space for offset index */
	for (; *p; p++)
		num_layers++;
	if (kr_fails_assert(num_layers))
		return NULL;

	ssize_t offsets[2 * num_layers];
	manager_size += sizeof(offsets);

	ssize_t *sess_offsets = offsets;
	ssize_t *iter_offsets = &offsets[num_layers];

	/* Space for layer-specific data, guaranteeing alignment */
	size_t total_sess_data_size = 0;
	size_t total_iter_data_size = 0;
	for (size_t i = 0; i < num_layers; i++) {
		sess_offsets[i] = protolayer_globals[protocols[i]].sess_size
			? total_sess_data_size : -1;
		total_sess_data_size += ALIGN_TO(protolayer_globals[protocols[i]].sess_size,
				CPU_STRUCT_ALIGN);

		iter_offsets[i] = protolayer_globals[protocols[i]].iter_size
			? total_iter_data_size : -1;
		total_iter_data_size += ALIGN_TO(protolayer_globals[protocols[i]].iter_size,
				CPU_STRUCT_ALIGN);
	}
	manager_size += total_sess_data_size;
	cb_ctx_size += total_iter_data_size;

	/* Allocate and initialize manager */
	struct protolayer_manager *m = calloc(1, manager_size);
	kr_require(m);
	m->grp = grp;
	m->session = s;
	m->num_layers = num_layers;
	m->cb_ctx_size = cb_ctx_size;
	memcpy(m->data, offsets, sizeof(offsets));

	/* Initialize the layer's session data */
	for (size_t i = 0; i < num_layers; i++) {
		struct protolayer_globals *globals = &protolayer_globals[protocols[i]];
		struct protolayer_data *sess_data = protolayer_sess_data_get(m, i);
		if (sess_data) {
			bzero(sess_data, globals->sess_size);
			sess_data->session = s;
			sess_data->protocol = protocols[i];
		}

		void *param = get_init_param(protocols[i], layer_param, layer_param_count);
		if (globals->sess_init)
			globals->sess_init(m, sess_data, param);
	}

	return m;
}

/** Deinitializes all layer data in the manager and deallocates it. */
static void protolayer_manager_free(struct protolayer_manager *m)
{
	if (!m) return;

	for (size_t i = 0; i < m->num_layers; i++) {
		enum protolayer_protocol p = protolayer_grps[m->grp][i];
		struct protolayer_globals *globals = &protolayer_globals[p];
		if (globals->sess_deinit) {
			struct protolayer_data *sess_data = protolayer_sess_data_get(m, i);
			globals->sess_deinit(m, sess_data);
		}
	}

	free(m);
}

enum protolayer_cb_result protolayer_continue(struct protolayer_cb_ctx *ctx)
{
	if (ctx->async_mode) {
		protolayer_cb_ctx_next(ctx);
		protolayer_step(ctx);
	} else {
		ctx->action = PROTOLAYER_CB_ACTION_CONTINUE;
	}
	return PROTOLAYER_CB_RESULT_MAGIC;
}

enum protolayer_cb_result protolayer_break(struct protolayer_cb_ctx *ctx, int status)
{
	ctx->status = status;
	if (ctx->async_mode) {
		protolayer_cb_ctx_finish(ctx, PROTOLAYER_RET_NORMAL);
	} else {
		ctx->action = PROTOLAYER_CB_ACTION_BREAK;
	}
	return PROTOLAYER_CB_RESULT_MAGIC;
}


int wire_buf_init(struct wire_buf *wb, size_t initial_size)
{
	char *buf = malloc(initial_size);
	kr_require(buf);

	*wb = (struct wire_buf){
		.buf = buf,
		.size = initial_size
	};

	return kr_ok();
}

void wire_buf_deinit(struct wire_buf *wb)
{
	free(wb->buf);
}

int wire_buf_reserve(struct wire_buf *wb, size_t size)
{
	if (wb->buf && wb->size >= size)
		return kr_ok();

	wb->buf = realloc(wb->buf, size);
	kr_require(wb->buf);
	wb->size = size;
	return kr_ok();
}

int wire_buf_consume(struct wire_buf *wb, size_t length)
{
	size_t ne = wb->end + length;
	if (kr_fails_assert(wb->buf && ne <= wb->size))
		return kr_error(EINVAL);

	wb->end = ne;
	return kr_ok();
}

int wire_buf_trim(struct wire_buf *wb, size_t length)
{
	size_t ns = wb->start + length;
	if (kr_fails_assert(ns <= wb->end))
		return kr_error(EINVAL);

	wb->start = ns;
	return kr_ok();
}

int wire_buf_movestart(struct wire_buf *wb)
{
	if (kr_fails_assert(wb->buf))
		return kr_error(EINVAL);
	if (wb->start == 0)
		return kr_ok();

	size_t len = wire_buf_data_length(wb);
	if (len)
		memmove(wb->buf, wire_buf_data(wb), len);
	wb->start = 0;
	wb->end = len;
	return kr_ok();
}

int wire_buf_reset(struct wire_buf *wb)
{
	wb->start = 0;
	wb->end = 0;
	return kr_ok();
}


struct session2 *session2_new(enum session2_transport_type transport_type,
                              enum protolayer_grp layer_grp,
                              struct protolayer_data_param *layer_param,
                              size_t layer_param_count,
                              bool outgoing)
{
	kr_require(transport_type && layer_grp);

	struct session2 *s = malloc(sizeof(*s));
	kr_require(s);

	*s = (struct session2) {
		.transport = {
			.type = transport_type,
		},
		.outgoing = outgoing,
		.tasks = trie_create(NULL),
	};

	struct protolayer_manager *layers = protolayer_manager_new(s, layer_grp,
			layer_param, layer_param_count);
	if (!layers) {
		free(s);
		return NULL;
	}
	s->layers = layers;

	mm_ctx_mempool(&s->pool, CPU_PAGE_SIZE);
	queue_init(s->waiting);

	int ret = wire_buf_init(&s->wire_buf, KNOT_WIRE_MAX_PKTSIZE);
	kr_require(!ret);

	ret = uv_timer_init(uv_default_loop(), &s->timer);
	kr_require(!ret);
	s->timer.data = s;

	session2_touch(s);

	return s;
}

static void session2_timer_on_close(uv_handle_t *handle)
{
	struct session2 *s = handle->data;
	protolayer_manager_free(s->layers);
	wire_buf_deinit(&s->wire_buf);
	mm_ctx_delete(&s->pool);
	trie_free(s->tasks);
	queue_deinit(s->waiting);
	free(s);
}

void session2_free(struct session2 *s)
{
	uv_close((uv_handle_t *)&s->timer, session2_timer_on_close);
}

int session2_start_read(struct session2 *session)
{
	if (session->transport.type == SESSION2_TRANSPORT_IO)
		return io_start_read(session->transport.io.handle);

	/* TODO - probably just some event for this */
	kr_assert(false && "Parent start_read unsupported");
	return kr_error(EINVAL);
}

int session2_stop_read(struct session2 *session)
{
	if (session->transport.type == SESSION2_TRANSPORT_IO)
		return io_stop_read(session->transport.io.handle);

	/* TODO - probably just some event for this */
	kr_assert(false && "Parent stop_read unsupported");
	return kr_error(EINVAL);
}

struct sockaddr *session2_get_peer(struct session2 *s)
{
	while (s && s->transport.type == SESSION2_TRANSPORT_PARENT)
		s = s->transport.parent;

	return (s && s->transport.type == SESSION2_TRANSPORT_IO)
		? &s->transport.io.peer.ip
		: NULL;
}

struct sockaddr *session2_get_sockname(struct session2 *s)
{
	while (s && s->transport.type == SESSION2_TRANSPORT_PARENT)
		s = s->transport.parent;

	return (s && s->transport.type == SESSION2_TRANSPORT_IO)
		? &s->transport.io.sockname.ip
		: NULL;
}

uv_handle_t *session2_get_handle(struct session2 *s)
{
	while (s && s->transport.type == SESSION2_TRANSPORT_PARENT)
		s = s->transport.parent;

	return (s && s->transport.type == SESSION2_TRANSPORT_IO)
		? s->transport.io.handle
		: NULL;
}

static void session2_on_timeout(uv_timer_t *timer)
{
	struct session2 *s = timer->data;
	session2_event(s, PROTOLAYER_EVENT_TIMEOUT, NULL);
}

int session2_timer_start(struct session2 *s, uint64_t timeout, uint64_t repeat)
{
	return uv_timer_start(&s->timer, session2_on_timeout, timeout, repeat);
}

int session2_timer_restart(struct session2 *s)
{
	return uv_timer_again(&s->timer);
}

int session2_timer_stop(struct session2 *s)
{
	return uv_timer_stop(&s->timer);
}

int session2_tasklist_add(struct session2 *session, struct qr_task *task)
{
	trie_t *t = session->tasks;
	uint16_t task_msg_id = 0;
	const char *key = NULL;
	size_t key_len = 0;
	if (session->outgoing) {
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

int session2_tasklist_del(struct session2 *session, struct qr_task *task)
{
	trie_t *t = session->tasks;
	uint16_t task_msg_id = 0;
	const char *key = NULL;
	size_t key_len = 0;
	trie_val_t val;
	if (session->outgoing) {
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

struct qr_task *session2_tasklist_get_first(struct session2 *session)
{
	trie_val_t *val = trie_get_first(session->tasks, NULL, NULL);
	return val ? (struct qr_task *) *val : NULL;
}

struct qr_task *session2_tasklist_del_first(struct session2 *session, bool deref)
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

struct qr_task *session2_tasklist_find_msgid(const struct session2 *session, uint16_t msg_id)
{
	if (kr_fails_assert(session->outgoing))
		return NULL;
	trie_t *t = session->tasks;
	struct qr_task *ret = NULL;
	trie_val_t *val = trie_get_try(t, (char *)&msg_id, sizeof(msg_id));
	if (val) {
		ret = *val;
	}
	return ret;
}

struct qr_task *session2_tasklist_del_msgid(const struct session2 *session, uint16_t msg_id)
{
	if (kr_fails_assert(session->outgoing))
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

void session2_tasklist_finalize(struct session2 *session, int status)
{
	while (session2_tasklist_get_len(session) > 0) {
		struct qr_task *t = session2_tasklist_del_first(session, false);
		kr_require(worker_task_numrefs(t) > 0);
		worker_task_finalize(t, status);
		worker_task_unref(t);
	}
}

int session2_tasklist_finalize_expired(struct session2 *session)
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
			struct kr_request *req = worker_task_request(task);
			if (!kr_fails_assert(req))
				kr_query_inform_timeout(req, req->current_query);
			queue_push(q, task);
			worker_task_ref(task);
		}
	}
	trie_it_free(it);

	struct qr_task *task = NULL;
	uint16_t msg_id = 0;
	char *key = (char *)&task;
	int32_t keylen = sizeof(struct qr_task *);
	if (session->outgoing) {
		key = (char *)&msg_id;
		keylen = sizeof(msg_id);
	}
	while (queue_len(q) > 0) {
		task = queue_head(q);
		if (session->outgoing) {
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

int session2_waitinglist_push(struct session2 *session, struct qr_task *task)
{
	queue_push(session->waiting, task);
	worker_task_ref(task);
	return kr_ok();
}

struct qr_task *session2_waitinglist_get(const struct session2 *session)
{
	return (queue_len(session->waiting) > 0) ? (queue_head(session->waiting)) : NULL;
}

struct qr_task *session2_waitinglist_pop(struct session2 *session, bool deref)
{
	struct qr_task *t = session2_waitinglist_get(session);
	queue_pop(session->waiting);
	if (deref) {
		worker_task_unref(t);
	}
	return t;
}

void session2_waitinglist_retry(struct session2 *session, bool increase_timeout_cnt)
{
	while (!session2_waitinglist_is_empty(session)) {
		struct qr_task *task = session2_waitinglist_pop(session, false);
		if (increase_timeout_cnt) {
			worker_task_timeout_inc(task);
		}
		worker_task_step(task, session2_get_peer(session), NULL);
		worker_task_unref(task);
	}
}

void session2_waitinglist_finalize(struct session2 *session, int status)
{
	while (!session2_waitinglist_is_empty(session)) {
		struct qr_task *t = session2_waitinglist_pop(session, false);
		worker_task_finalize(t, status);
		worker_task_unref(t);
	}
}

int session2_unwrap(struct session2 *s, struct protolayer_payload payload,
                    const void *target, protolayer_finished_cb cb, void *baton)
{
	return protolayer_manager_submit(s->layers, PROTOLAYER_UNWRAP, 0,
			payload, target, cb, baton);
}

int session2_unwrap_after(struct session2 *s, enum protolayer_protocol protocol,
                         struct protolayer_payload payload, const void *target,
                         protolayer_finished_cb cb, void *baton)
{
	ssize_t layer_ix = protolayer_manager_get_protocol(s->layers, protocol) + 1;
	if (layer_ix < 0)
		return layer_ix;
	return protolayer_manager_submit(s->layers, PROTOLAYER_UNWRAP, layer_ix,
			payload, target, cb, baton);
}

int session2_wrap(struct session2 *s, struct protolayer_payload payload,
                  const void *target, protolayer_finished_cb cb, void *baton)
{
	return protolayer_manager_submit(s->layers, PROTOLAYER_WRAP,
			s->layers->num_layers - 1,
			payload, target, cb, baton);
}

int session2_wrap_after(struct session2 *s, enum protolayer_protocol protocol,
                       struct protolayer_payload payload, const void *target,
                       protolayer_finished_cb cb, void *baton)
{
	ssize_t layer_ix = protolayer_manager_get_protocol(s->layers, protocol) - 1;
	if (layer_ix < 0)
		return layer_ix;
	return protolayer_manager_submit(s->layers, PROTOLAYER_WRAP, layer_ix,
			payload, target, cb, baton);
}

static void session2_event_wrap(struct session2 *s, enum protolayer_event_type event, void *baton)
{
	bool cont;
	struct protolayer_manager *m = s->layers;
	for (ssize_t i = m->num_layers - 1; i >= 0; i--) {
		enum protolayer_protocol p = protolayer_grps[s->layers->grp][i];
		struct protolayer_globals *globals = &protolayer_globals[p];
		if (globals->event_wrap) {
			struct protolayer_data *sess_data = protolayer_sess_data_get(m, i);
			cont = globals->event_wrap(event, &baton, m, sess_data);
		} else {
			cont = true;
		}

		if (!cont)
			return;
	}

	session2_transport_event(s, event, baton);
}

void session2_event_unwrap(struct session2 *s, ssize_t start_ix, enum protolayer_event_type event, void *baton)
{
	bool cont;
	struct protolayer_manager *m = s->layers;
	for (ssize_t i = start_ix; i < m->num_layers; i++) {
		enum protolayer_protocol p = protolayer_grps[s->layers->grp][i];
		struct protolayer_globals *globals = &protolayer_globals[p];
		if (globals->event_unwrap) {
			struct protolayer_data *sess_data = protolayer_sess_data_get(m, i);
			cont = globals->event_unwrap(event, &baton, m, sess_data);
		} else {
			cont = true;
		}

		if (!cont)
			return;
	}

	/* Immediately bounce back in the `wrap` direction.
	 *
	 * TODO: This might be undesirable for cases with sub-sessions - the
	 * current idea is for the layers managing sub-sessions to just return
	 * `false` on `event_unwrap`, but a more "automatic" mechanism may be
	 * added when this is relevant, to make it less error-prone. */
	session2_event_wrap(s, event, baton);
}

void session2_event(struct session2 *s, enum protolayer_event_type event, void *baton)
{
	session2_event_unwrap(s, 0, event, baton);
}

void session2_event_after(struct session2 *s, enum protolayer_protocol protocol,
                          enum protolayer_event_type event, void *baton)
{
	ssize_t start_ix = protolayer_manager_get_protocol(s->layers, protocol);
	if (kr_fails_assert(start_ix >= 0))
		return;
	session2_event_unwrap(s, start_ix + 1, event, baton);
}


struct session2_pushv_ctx {
	struct session2 *session;
	protolayer_finished_cb cb;
	const void *target;
	void *baton;

	char *buf;
	size_t buf_len;
};

static void session2_transport_parent_pushv_finished(int status,
                                                     struct session2 *session,
                                                     const void *target,
                                                     void *baton)
{
	struct session2_pushv_ctx *ctx = baton;
	if (ctx->cb)
		ctx->cb(status, ctx->session, target, ctx->baton);
	free(ctx->buf);
	free(ctx);
}

static void session2_transport_udp_queue_pushv_finished(int status, void *baton)
{
	struct session2_pushv_ctx *ctx = baton;
	if (ctx->cb)
		ctx->cb(status, ctx->session, ctx->target, ctx->baton);
	free(ctx->buf);
	free(ctx);
}

static void session2_transport_udp_pushv_finished(uv_udp_send_t *req, int status)
{
	struct session2_pushv_ctx *ctx = req->data;
	if (ctx->cb)
		ctx->cb(status, ctx->session, ctx->target, ctx->baton);
	free(ctx->buf);
	free(ctx);
	free(req);
}

static void session2_transport_stream_pushv_finished(uv_write_t *req, int status)
{
	struct session2_pushv_ctx *ctx = req->data;
	if (ctx->cb)
		ctx->cb(status, ctx->session, ctx->target, ctx->baton);
	free(ctx->buf);
	free(ctx);
	free(req);
}

static int session2_transport_pushv(struct session2 *s,
                                    struct iovec *iov, int iovcnt,
                                    const void *target,
                                    protolayer_finished_cb cb, void *baton)
{
	if (kr_fails_assert(s))
		return kr_error(EINVAL);

	struct session2_pushv_ctx *ctx = malloc(sizeof(*ctx));
	kr_require(ctx);
	*ctx = (struct session2_pushv_ctx){
		.session = s,
		.cb = cb,
		.baton = baton,
		.target = target
	};

	switch (s->transport.type) {
	case SESSION2_TRANSPORT_IO:;
		uv_handle_t *handle = s->transport.io.handle;
		if (kr_fails_assert(handle)) {
			free(ctx);
			return kr_error(EINVAL);
		}

		/* TODO: XDP */
		if (handle->type == UV_UDP) {
			if (ENABLE_SENDMMSG && !s->outgoing) {
				int fd;
				int ret = uv_fileno(handle, &fd);
				if (kr_fails_assert(!ret))
					return kr_error(EIO);

				/* TODO: support multiple iovecs properly? */
				if (kr_fails_assert(iovcnt == 1))
					return kr_error(EINVAL);

				udp_queue_push(fd, target, iov->iov_base, iov->iov_len,
						session2_transport_udp_queue_pushv_finished,
						ctx);
				return kr_ok();
			} else {
				uv_udp_send_t *req = malloc(sizeof(*req));
				req->data = ctx;
				uv_udp_send(req, (uv_udp_t *)handle,
						(uv_buf_t *)iov, iovcnt, target,
						session2_transport_udp_pushv_finished);
				return kr_ok();
			}
		} else if (handle->type == UV_TCP) {
			uv_write_t *req = malloc(sizeof(*req));
			req->data = ctx;
			uv_write(req, (uv_stream_t *)handle, (uv_buf_t *)iov, iovcnt,
					session2_transport_stream_pushv_finished);
			return kr_ok();
		} else {
			kr_assert(false && "Unsupported handle");
			free(ctx);
			return kr_error(EINVAL);
		}

	case SESSION2_TRANSPORT_PARENT:;
		struct session2 *parent = s->transport.parent;
		if (kr_fails_assert(parent)) {
			free(ctx);
			return kr_error(EINVAL);
		}
		int ret = session2_wrap(parent, protolayer_iovec(iov, iovcnt),
				target, session2_transport_parent_pushv_finished,
				ctx);
		return (ret < 0) ? ret : kr_ok();

	default:
		kr_assert(false && "Invalid transport");
		free(ctx);
		return kr_error(EINVAL);
	}
}

struct push_ctx {
	struct iovec iov;
	protolayer_finished_cb cb;
	void *baton;
};

static void session2_transport_single_push_finished(int status,
                                                    struct session2 *s,
                                                    const void *target,
                                                    void *baton)
{
	struct push_ctx *ctx = baton;
	if (ctx->cb)
		ctx->cb(status, s, target, ctx->baton);
	free(ctx);
}

static inline int session2_transport_push(struct session2 *s,
                                          char *buf, size_t buf_len,
                                          const void *target,
                                          protolayer_finished_cb cb, void *baton)
{
	struct push_ctx *ctx = malloc(sizeof(*ctx));
	kr_require(ctx);
	*ctx = (struct push_ctx){
		.iov = {
			.iov_base = buf,
			.iov_len = buf_len
		},
		.cb = cb,
		.baton = baton
	};

	return session2_transport_pushv(s, &ctx->iov, 1, target,
			session2_transport_single_push_finished, ctx);
}

static void on_session2_handle_close(uv_handle_t *handle)
{
	struct session2 *session = handle->data;
	kr_require(session->transport.type == SESSION2_TRANSPORT_IO &&
			session->transport.io.handle == handle);
	io_free(handle);
}

static int session2_handle_close(struct session2 *s, uv_handle_t *handle)
{
	io_stop_read(handle);
	uv_close(handle, on_session2_handle_close);
	return kr_ok();
}

static int session2_transport_event(struct session2 *s,
                                    enum protolayer_event_type event,
                                    void *baton)
{
	if (s->closing)
		return kr_ok();

	bool is_close_event = (event == PROTOLAYER_EVENT_CLOSE ||
			event == PROTOLAYER_EVENT_FORCE_CLOSE);
	if (is_close_event) {
		kr_require(session2_is_empty(s));
		session2_timer_stop(s);
		s->closing = true;
	}

	switch (s->transport.type) {
	case SESSION2_TRANSPORT_IO:;
		uv_handle_t *handle = s->transport.io.handle;
		if (kr_fails_assert(handle)) {
			return kr_error(EINVAL);
		}

		if (is_close_event)
			return session2_handle_close(s, handle);

		return kr_ok();

	case SESSION2_TRANSPORT_PARENT:;
		session2_event_wrap(s, event, baton);
		return kr_ok();

	default:
		kr_assert(false && "Invalid transport");
		return kr_error(EINVAL);
	}
}

void session2_kill_ioreq(struct session2 *session, struct qr_task *task)
{
	if (!session || session->closing)
		return;
	if (kr_fails_assert(session->outgoing
				&& session->transport.type == SESSION2_TRANSPORT_IO
				&& session->transport.io.handle))
		return;
	session2_tasklist_del(session, task);
	if (session->transport.io.handle->type == UV_UDP)
		session2_event(session, PROTOLAYER_EVENT_CLOSE, NULL);
}
