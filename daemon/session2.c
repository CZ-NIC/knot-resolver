/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <ucw/lib.h>
#include <sys/socket.h>

#include "lib/log.h"
#include "lib/utils.h"

#include "daemon/session2.h"


typedef void (*session2_push_cb)(struct session2 *s, int status,
                                 void *target, void *baton);

static int session2_transport_pushv(struct session2 *s,
                                    const struct iovec *iov, int iovcnt,
                                    void *target,
                                    session2_push_cb cb, void *baton);
static inline int session2_transport_push(struct session2 *s,
                                          char *buf, size_t buf_len,
                                          void *target,
                                          session2_push_cb cb, void *baton);

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
#define XX(id, name, desc) [PROTOLAYER_GRP_##id] = protolayer_grp_##name,
	PROTOLAYER_GRP_MAP(XX)
#undef XX
};

char *protolayer_grp_descs[PROTOLAYER_GRP_COUNT] = {
#define XX(id, name, desc) [PROTOLAYER_GRP_##id] = desc,
	PROTOLAYER_GRP_MAP(XX)
#undef XX
};


/** Gets context for the layer with the specified index from the manager. */
static inline struct protolayer_data *protolayer_manager_get(
		struct protolayer_manager *m, size_t layer_ix)
{
	if (kr_fails_assert(layer_ix < m->num_layers))
		return NULL;

	const size_t *offsets = (size_t *)m->data;
	char *pl_data_beg = m->data + (m->num_layers * sizeof(*offsets));
	return (struct protolayer_data *)(pl_data_beg + offsets[layer_ix]);
}

static inline void protolayer_cb_ctx_next(struct protolayer_cb_ctx *ctx)
{
	if (ctx->direction == PROTOLAYER_UNWRAP)
		ctx->layer_ix++;
	else
		ctx->layer_ix--;
}

static int protolayer_cb_ctx_finish(struct protolayer_cb_ctx *ctx, int ret,
                                    bool reset_layers)
{
	if (reset_layers) {
		struct protolayer_manager *m = ctx->manager;
		struct protolayer_globals *globals = &protolayer_globals[m->grp];
		for (size_t i = 0; i < m->num_layers; i++) {
			struct protolayer_data *d = protolayer_manager_get(m, i);
			if (globals->reset)
				globals->reset(m, d);
		}
	}

	if (ctx->status)
		kr_log_debug(PROTOLAYER, "layer iteration of group '%s' ended with status %d",
				protolayer_grp_descs[ctx->manager->grp], ret);

	if (ctx->finished_cb)
		ctx->finished_cb(ret, ctx->finished_cb_target,
				ctx->finished_cb_baton);
	free(ctx);
	return ret;
}

/** Processes as many layers as possible synchronously, returning when either
 * a layer has gone asynchronous, or when the whole sequence has finished.
 *
 * May be called multiple times on the same `ctx` to continue processing
 * after an asynchronous operation. */
static int protolayer_step(struct protolayer_cb_ctx *ctx)
{
	while (true) {
		struct protolayer_data *ldata = protolayer_manager_get(
				ctx->manager, ctx->layer_ix);
		if (kr_fails_assert(ldata)) {
			/* Probably layer index or data corruption */
			return kr_error(EINVAL);
		}

		enum protolayer_protocol protocol = ldata->protocol;
		struct protolayer_globals *globals = &protolayer_globals[protocol];

		if (!ldata->processed) { /* Avoid repetition */
			ctx->async_mode = false;
			ctx->status = 0;
			ctx->result = PROTOLAYER_CB_NULL;

			protolayer_cb cb = (ctx->direction == PROTOLAYER_UNWRAP)
				? globals->unwrap : globals->wrap;

			cb(ldata, ctx);
			ldata->processed = true;
		}

		if (!ctx->result) {
			ctx->async_mode = true;
			return PROTOLAYER_RET_ASYNC; /* Next step is callback */
		}

		if (ctx->result == PROTOLAYER_CB_WAIT) {
			kr_assert(ctx->status == 0);
			return protolayer_cb_ctx_finish(
					ctx, PROTOLAYER_RET_WAITING, false);
		}

		if (ctx->result == PROTOLAYER_CB_BREAK) {
			kr_assert(ctx->status <= 0);
			return protolayer_cb_ctx_finish(
					ctx, PROTOLAYER_RET_NORMAL, true);
		}

		if (kr_fails_assert(ctx->status == 0)) {
			/* Status should be zero without a BREAK. */
			return protolayer_cb_ctx_finish(
					ctx, kr_error(ECANCELED), true);
		}

		if (ctx->result == PROTOLAYER_CB_CONTINUE) {
			protolayer_cb_ctx_next(ctx);
			continue;
		}

		/* Should never get here */
		kr_assert(false);
		return protolayer_cb_ctx_finish(ctx, kr_error(EINVAL), true);
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
		enum protolayer_direction direction,
		char *buf, size_t buf_len, void *target,
		protolayer_finished_cb cb, void *baton)
{
	size_t layer_ix = (direction == PROTOLAYER_UNWRAP)
		? 0 : manager->num_layers - 1;

	struct protolayer_cb_ctx *ctx = malloc(sizeof(*ctx)); // TODO - mempool?
	kr_require(ctx);

	*ctx = (struct protolayer_cb_ctx) {
		.data = { .target = target },
		.direction = direction,
		.layer_ix = layer_ix,
		.manager = manager,
		.finished_cb = cb,
		.finished_cb_target = target,
		.finished_cb_baton = baton
	};
	protolayer_set_buffer(ctx, buf, buf_len);

	return protolayer_step(ctx);
}


struct protolayer_manager *protolayer_manager_new(struct session2 *s,
                                                  enum protolayer_grp grp)
{
	if (kr_fails_assert(grp))
		return NULL;

	size_t num_layers = 0;
	size_t size = sizeof(struct protolayer_manager);
	enum protolayer_protocol *protocols = protolayer_grps[grp];
	if (kr_fails_assert(protocols))
		return NULL;
	enum protolayer_protocol *p = protocols;

	/* Space for offset index */
	for (; *p; p++)
		num_layers++;
	if (kr_fails_assert(num_layers))
		return NULL;
	size_t offsets[num_layers];
	size += sizeof(offsets);

	/* Space for layer-specific data, guaranteeing alignment */
	size_t total_data_size = 0;
	for (size_t i = 0; i < num_layers; i++) {
		offsets[i] = total_data_size;
		size_t d = protolayer_globals[protocols[i]].data_size;
		size += ALIGN_TO(d, CPU_STRUCT_ALIGN);
	}
	size += total_data_size;

	/* Allocate and initialize manager */
	struct protolayer_manager *m = malloc(size);
	kr_require(m);
	m->grp = grp;
	m->session = s;
	m->num_layers = num_layers;
	memcpy(m->data, offsets, sizeof(offsets));

	/* Initialize layer data */
	for (size_t i = 0; i < num_layers; i++) {
		struct protolayer_globals *globals = &protolayer_globals[protocols[i]];
		struct protolayer_data *data = protolayer_manager_get(m, i);
		data->protocol = protocols[i];
		data->size = globals->data_size;
		globals->init(m, data);
	}

	return m;
}

void protolayer_manager_free(struct protolayer_manager *m)
{
	if (!m) return;

	for (size_t i = 0; i < m->num_layers; i++) {
		struct protolayer_data *data = protolayer_manager_get(m, i);
		protolayer_globals[data->protocol].deinit(m, data);
	}

	free(m);
}

void protolayer_continue(struct protolayer_cb_ctx *ctx)
{
	if (ctx->async_mode) {
		protolayer_cb_ctx_next(ctx);
		protolayer_step(ctx);
	} else {
		ctx->result = PROTOLAYER_CB_CONTINUE;
	}
}

void protolayer_wait(struct protolayer_cb_ctx *ctx)
{
	if (ctx->async_mode) {
		protolayer_cb_ctx_finish(ctx, PROTOLAYER_RET_WAITING, false);
	} else {
		ctx->result = PROTOLAYER_CB_WAIT;
	}
}

void protolayer_break(struct protolayer_cb_ctx *ctx, int status)
{
	ctx->status = status;
	if (ctx->async_mode) {
		protolayer_cb_ctx_finish(ctx, PROTOLAYER_RET_NORMAL, true);
	} else {
		ctx->result = PROTOLAYER_CB_BREAK;
	}
}

static void protolayer_push_finished(struct session2 *s, int status, void *target, void *baton)
{
	protolayer_break(baton, status);
}

void protolayer_pushv(struct protolayer_cb_ctx *ctx,
                      struct iovec *iov, int iovcnt,
                      void *target)
{
	int ret = session2_transport_pushv(ctx->manager->session, iov, iovcnt,
			target, protolayer_push_finished, ctx);
	if (ret && ctx->finished_cb)
		ctx->finished_cb(ret, ctx->finished_cb_target,
				ctx->finished_cb_baton);
}

void protolayer_push(struct protolayer_cb_ctx *ctx, char *buf, size_t buf_len,
                     void *target)
{
	int ret = session2_transport_push(ctx->manager->session, buf, buf_len,
			target, protolayer_push_finished, ctx);
	if (ret && ctx->finished_cb)
		ctx->finished_cb(ret, ctx->finished_cb_target,
				ctx->finished_cb_baton);
}


struct session2 *session2_new(enum session2_transport_type transport_type,
                              void *transport_ctx,
                              enum protolayer_grp layer_grp,
                              bool outgoing)
{
	kr_require(transport_type && transport_ctx && layer_grp);

	struct session2 *s = malloc(sizeof(*s));
	kr_require(s);

	s->transport.type = transport_type;
	s->transport.ctx = transport_ctx;

	s->layers = protolayer_manager_new(s, layer_grp);
	if (!s->layers) {
		free(s);
		return NULL;
	}

	s->outgoing = outgoing;

	return s;
}

void session2_free(struct session2 *s)
{
	protolayer_manager_free(s->layers);
	free(s);
}

int session2_unwrap(struct session2 *s, char *buf, size_t buf_len, void *target,
                    protolayer_finished_cb cb, void *baton)
{
	return protolayer_manager_submit(s->layers, PROTOLAYER_UNWRAP,
			buf, buf_len, target, cb, baton);
}

int session2_wrap(struct session2 *s, char *buf, size_t buf_len, void *target,
                  protolayer_finished_cb cb, void *baton)
{
	return protolayer_manager_submit(s->layers, PROTOLAYER_WRAP,
			buf, buf_len, target, cb, baton);
}


struct parent_pushv_ctx {
	struct session2 *session;
	session2_push_cb cb;
	void *target;
	void *baton;

	char *buf;
	size_t buf_len;
};

static void session2_transport_parent_pushv_finished(int status, void *target, void *baton)
{
	struct parent_pushv_ctx *ctx = baton;
	if (ctx->cb)
		ctx->cb(ctx->session, status, target, ctx->baton);
	free(ctx->buf);
	free(ctx);
}

static void session2_transport_udp_pushv_finished(uv_udp_send_t *req, int status)
{
	struct parent_pushv_ctx *ctx = req->data;
	if (ctx->cb)
		ctx->cb(ctx->session, status, ctx->target, ctx->baton);
	free(ctx->buf);
	free(ctx);
	free(req);
}

static void session2_transport_stream_pushv_finished(uv_write_t *req, int status)
{
	struct parent_pushv_ctx *ctx = req->data;
	if (ctx->cb)
		ctx->cb(ctx->session, status, ctx->target, ctx->baton);
	free(ctx->buf);
	free(ctx);
	free(req);
}

static int concat_iovs(const struct iovec *iov, int iovcnt, char **buf, size_t *buf_len)
{
	if (!iov || iovcnt <= 0)
		return kr_error(ENODATA);

	size_t len = 0;
	for (int i = 0; i < iovcnt; i++) {
		size_t old_len = len;
		len += iov[i].iov_len;
		if (kr_fails_assert(len >= old_len)) {
			*buf = NULL;
			return kr_error(EFBIG);
		}
	}

	*buf_len = len;
	if (len == 0) {
		*buf = NULL;
		return kr_ok();
	}

	*buf = malloc(len);
	kr_require(*buf);

	char *c = *buf;
	for (int i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len == 0)
			continue;
		memcpy(c, iov[i].iov_base, iov[i].iov_len);
		c += iov[i].iov_len;
	}

	return kr_ok();
}

static int session2_transport_pushv(struct session2 *s,
                                    const struct iovec *iov, int iovcnt,
                                    void *target,
                                    session2_push_cb cb, void *baton)
{
	if (kr_fails_assert(s))
		return kr_error(EINVAL);

	struct parent_pushv_ctx *ctx = malloc(sizeof(*ctx));
	kr_require(ctx);
	*ctx = (struct parent_pushv_ctx) {
		.session = s,
		.cb = cb,
		.baton = baton,
		.target = target
	};

	switch (s->transport.type) {
	case SESSION2_TRANSPORT_HANDLE:;
		uv_handle_t *handle = s->transport.handle;
		if (kr_fails_assert(handle)) {
			free(ctx);
			return kr_error(EINVAL);
		}

		if (handle->type == UV_UDP) {
			uv_udp_send_t *req = malloc(sizeof(*req));
			req->data = ctx;
			uv_udp_send(req, (uv_udp_t *)handle,
					(uv_buf_t *)iov, iovcnt, target,
					session2_transport_udp_pushv_finished);
			return kr_ok();
		} else if (handle->type == UV_TCP) {
			uv_write_t *req = malloc(sizeof(*req));
			req->data = ctx;
			uv_write(req, (uv_stream_t *)handle, (uv_buf_t *)iov, iovcnt,
					session2_transport_stream_pushv_finished);
			return kr_ok();
		}

		kr_assert(false && "Unsupported handle");
		free(ctx);
		return kr_error(EINVAL);

	case SESSION2_TRANSPORT_PARENT:;
		struct session2 *parent = s->transport.parent;
		if (kr_fails_assert(parent)) {
			free(ctx);
			return kr_error(EINVAL);
		}
		int ret = concat_iovs(iov, iovcnt, &ctx->buf, &ctx->buf_len);
		if (ret) {
			free(ctx);
			return ret;
		}
		session2_wrap(parent, ctx->buf, ctx->buf_len, target,
				session2_transport_parent_pushv_finished, ctx);
		return kr_ok();

	default:
		kr_assert(false && "Invalid transport");
		free(ctx);
		return kr_error(EINVAL);
	}
}

struct push_ctx {
	struct iovec iov;
	session2_push_cb cb;
	void *baton;
};

static void session2_transport_single_push_finished(struct session2 *s,
                                                    int status,
                                                    void *target, void *baton)
{
	struct push_ctx *ctx = baton;
	if (ctx->cb)
		ctx->cb(s, status, target, ctx->baton);
	free(ctx);
}

static inline int session2_transport_push(struct session2 *s,
                                          char *buf, size_t buf_len,
                                          void *target,
                                          session2_push_cb cb, void *baton)
{
	struct push_ctx *ctx = malloc(sizeof(*ctx));
	kr_require(ctx);
	*ctx = (struct push_ctx) {
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
