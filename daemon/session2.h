/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <uv.h>

#include "contrib/mempattern.h"

/* Forward declarations */
struct session2;
struct protolayer_cb_ctx;

/** Protocol types - individual implementations of protocol layers. */
enum protolayer_protocol {
	PROTOLAYER_NULL = 0,
	PROTOLAYER_TCP,
	PROTOLAYER_UDP,
	PROTOLAYER_TLS,
	PROTOLAYER_HTTP,

	PROTOLAYER_UDP_TO_QCONN,
	PROTOLAYER_QCONN_TO_QSTREAM,

	PROTOLAYER_DNS_DGRAM,
	PROTOLAYER_DNS_MSTREAM, /* DoTCP allows multiple packets per stream */
	PROTOLAYER_DNS_SSTREAM, /* DoQ only allows a single packet per stream */

	PROTOLAYER_PROTOCOL_COUNT
};

#define PROTOLAYER_GRP_MAP(XX) \
	XX(DOUDP, doudp, "DNS UDP") \
	XX(DOTCP, dotcp, "DNS TCP") \
	XX(DOT, dot, "DNS-over-TLS") \
	XX(DOH, doh, "DNS-over-HTTPS")

/** Pre-defined sequences of protocol layers. */
enum protolayer_grp {
	PROTOLAYER_GRP_NULL = 0,
#define XX(id, name, desc) PROTOLAYER_GRP_##id,
	PROTOLAYER_GRP_MAP(XX)
#undef XX
	PROTOLAYER_GRP_COUNT
};

/** Maps protocol layer group IDs to human-readable descriptions.
 * E.g. PROTOLAYER_GRP_DOH has description 'DNS-over-HTTPS'. */
extern char *protolayer_grp_descs[];

/** Flow control indicators for protocol layer `wrap` and `unwrap` callbacks.
 * Use with `protolayer_continue`, `protolayer_wait` and `protolayer_break`
 * functions. */
enum protolayer_cb_result {
	PROTOLAYER_CB_NULL = 0,

	PROTOLAYER_CB_CONTINUE,
	PROTOLAYER_CB_WAIT,
	PROTOLAYER_CB_BREAK,
	PROTOLAYER_CB_PUSH,
};

enum protolayer_direction {
	PROTOLAYER_WRAP,
	PROTOLAYER_UNWRAP,
};

enum protolayer_ret {
	/** Returned when a protolayer context iteration has finished
	 * processing, i.e. with _BREAK. */
	PROTOLAYER_RET_NORMAL = 0,

	/** Returned when a protolayer context iteration is waiting for an
	 * asynchronous callback to a continuation function. This will never be
	 * passed to `protolayer_finished_cb`, only returned by
	 * `session2_unwrap` or `session2_wrap`. */
	PROTOLAYER_RET_ASYNC,

	/** Returned when a protolayer context iteration has ended on a layer
	 * that needs more data from another buffer. */
	PROTOLAYER_RET_WAITING,
};

/** Called when a context iteration (started by `session2_unwrap` or
 * `session2_wrap`) has ended - i.e. the input buffer will not be processed
 * any further.
 *
 * `status` may be one of `enum protolayer_ret` or a negative
 * number indicating an error.
 * `target` is the `target` parameter passed to the `session2_(un)wrap`
 * function.
 * `baton` is the `baton` parameter passed to the
 * `session2_(un)wrap` function. */
typedef void (*protolayer_finished_cb)(int status, void *target, void *baton);

enum protolayer_cb_data_type {
	PROTOLAYER_CB_DATA_NULL = 0,
	PROTOLAYER_CB_DATA_BUFFER,
	PROTOLAYER_CB_DATA_IOVEC,
};

/** Context for protocol layer callbacks, containing buffer data and internal
 * information for protocol layer manager. */
struct protolayer_cb_ctx {
	/* read-write */

	/** Data processed by the sequence of layers. All the data is always
	 * owned by its creator. It is also the layer (group) implementor's
	 * responsibility to keep data compatible in between layers. No data is
	 * ever (de-)allocated by the protolayer manager! */
	struct {
		enum protolayer_cb_data_type type;
		union {
			/** Only valid if `type` is `_BUFFER`. */
			struct {
				char *buf;
				size_t len;
			} buffer;

			/** Only valid if `type` is `_IOVEC`. */
			struct {
				struct iovec *iov;
				int cnt;
			} iovec;
		};
		/** Always valid; may be `NULL`. */
		void *target;
	} data;

	/* internal manager information - private */
	enum protolayer_direction direction;
	bool async_mode;
	unsigned int layer_ix;
	struct protolayer_manager *manager;
	int status;
	enum protolayer_cb_result result;

	/* callback for when the layer iteration has ended - read-only */
	protolayer_finished_cb finished_cb;
	void *finished_cb_target;
	void *finished_cb_baton;
};

/** Convenience function to put a buffer pointer to the specified context. */
static inline void protolayer_set_buffer(struct protolayer_cb_ctx *ctx,
                                         char *buf, size_t len)
{
	ctx->data.type = PROTOLAYER_CB_DATA_BUFFER;
	ctx->data.buffer.buf = buf;
	ctx->data.buffer.len = len;
}

/** Convenience function to put an iovec pointer to the specified context. */
static inline void protolayer_set_iovec(struct protolayer_cb_ctx *ctx,
                                        struct iovec *iov, int iovcnt)
{
	ctx->data.type = PROTOLAYER_CB_DATA_IOVEC;
	ctx->data.iovec.iov = iov;
	ctx->data.iovec.cnt = iovcnt;
}


/** Common header for per-session layer-specific data. When implementing
 * a new layer, this is to be put at the beginning of the struct. */
#define PROTOLAYER_DATA_HEADER struct {\
	enum protolayer_protocol protocol;\
	size_t size; /**< Size of the entire struct (incl. header) */\
	bool processed; /**< Safeguard so that the layer does not get executed
	                 * multiple times. */\
}

/** Per-session layer-specific data - generic struct. */
struct protolayer_data {
	PROTOLAYER_DATA_HEADER;
	uint8_t data[];
};

typedef void (*protolayer_cb)(struct protolayer_data *layer,
                              struct protolayer_cb_ctx *ctx);
typedef int (*protolayer_data_cb)(struct protolayer_manager *manager,
                                  struct protolayer_data *layer);

/** The default implementation for the `struct protolayer_globals::reset`
 * callback. Simply calls the `deinit` and `init` callbacks. */
int protolayer_data_reset_default(struct protolayer_manager *manager,
                                  struct protolayer_data *layer);


/** A collection of protocol layers and their layer-specific data. */
struct protolayer_manager {
	enum protolayer_grp grp;
	struct session2 *session;
	size_t num_layers;
	char data[];
};

/** Allocates and initializes a new manager. */
struct protolayer_manager *protolayer_manager_new(struct session2 *s,
                                                  enum protolayer_grp grp);

/** Deinitializes all layer data in the manager and deallocates it. */
void protolayer_manager_free(struct protolayer_manager *m);


/** Global data for a specific layered protocol. */
struct protolayer_globals {
	size_t data_size;          /**< Size of the layer-specific data struct. */
	protolayer_data_cb init;   /**< Initializes the layer-specific data struct. */
	protolayer_data_cb deinit; /**< De-initializes the layer-specific data struct. */
	protolayer_data_cb reset;  /**< Resets the layer-specific data struct
	                            * after finishing a sequence. Default
	                            * implementation is available as
	                            * `protolayer_data_reset_default`. */
	protolayer_cb unwrap;      /**< Strips the buffer of protocol-specific
	                            * data. E.g. a HTTP layer removes HTTP
	                            * status and headers. */
	protolayer_cb wrap;        /**< Wraps the buffer into protocol-specific
	                            * data. E.g. a HTTP layer adds HTTP status
	                            * and headers. */
};

/** Global data about layered protocols. Indexed by `enum protolayer_protocol`. */
extern struct protolayer_globals protolayer_globals[PROTOLAYER_PROTOCOL_COUNT];

/** *Continuation function* - signals the protolayer manager to continue
 * processing the next layer. */
void protolayer_continue(struct protolayer_cb_ctx *ctx);

/** *Continuation function* - signals that the layer needs more data to produce
 * a new buffer for the next layer. */
void protolayer_wait(struct protolayer_cb_ctx *ctx);

/** *Continuation function* - signals that the layer wants to stop processing
 * of the buffer and clean up, possibly due to an error (indicated by
 * `status`).
 *
 * `status` must be 0 or a negative integer. */
void protolayer_break(struct protolayer_cb_ctx *ctx, int status);

/** *Continuation function* - pushes data to the session's transport and
 * signals that the layer wants to stop processing of the buffer and clean up.
 *
 * `target` is the target data for the transport - in most cases, it will be
 * unused and may be `NULL`; except for UDP, where it must point to a `struct
 * sockaddr_*` to indicate the target address.
 *
 * This function is meant to be called by the `wrap` callback of first layer in
 * the sequence.  */
void protolayer_pushv(struct protolayer_cb_ctx *ctx,
                      struct iovec *iov, int iovcnt, void *target);

/** *Continuation function* - pushes data to the session's transport and
 * signals that the layer wants to stop processing of the buffer and clean up.
 *
 * `target` is the target data for the transport - in most cases, it will be
 * unused and may be `NULL`; except for UDP, where it must point to a `struct
 * sockaddr_*` to indicate the target address.
 *
 * This function is meant to be called by the `wrap` callback of first layer in
 * the sequence.  */
void protolayer_push(struct protolayer_cb_ctx *ctx, char *buf, size_t buf_len,
                     void *target);


/** Indicates how a session sends data in the `wrap` direction and receives
 * data in the `unwrap` direction. */
enum session2_transport_type {
	SESSION2_TRANSPORT_NULL = 0,
	SESSION2_TRANSPORT_HANDLE,
	SESSION2_TRANSPORT_PARENT,
};

struct session2 {
	struct {
		enum session2_transport_type type;
		union {
			void *ctx;
			uv_handle_t *handle;
			struct session2 *parent;
		};
	} transport;

	struct protolayer_manager *layers;
	bool outgoing : 1;
};

/** Allocates and initializes a new session with the specified protocol layer
 * group, and the provided transport context. */
struct session2 *session2_new(enum session2_transport_type transport_type,
                              void *transport_ctx,
                              enum protolayer_grp layer_grp,
                              bool outgoing);

/** Allocates and initializes a new session with the specified protocol layer
 * group, using a *libuv handle* as its transport. */
static inline struct session2 *session2_new_handle(uv_handle_t *handle,
                                                   enum protolayer_grp layer_grp,
                                                   bool outgoing)
{
	return session2_new(SESSION2_TRANSPORT_HANDLE, handle, layer_grp,
			outgoing);
}

/** Allocates and initializes a new session with the specified protocol layer
 * group, using a *parent session* as its transport. */
static inline struct session2 *session2_new_child(struct session2 *parent,
                                                  enum protolayer_grp layer_grp,
                                                  bool outgoing)
{
	return session2_new(SESSION2_TRANSPORT_PARENT, parent, layer_grp,
			outgoing);
}

/** De-allocates the session. */
void session2_free(struct session2 *s);

/** Sends the specified buffer to be processed in the `unwrap` direction by the
 * session's protocol layers. The `target` parameter may contain a pointer to
 * transport-specific data, e.g. for UDP, it shall contain a pointer to the
 * sender's `struct sockaddr_*`.
 *
 * Once all layers are processed, `cb` is called with `baton` passed as one
 * of its parameters. `cb` may also be `NULL`. See `protolayer_finished_cb` for
 * more info.
 *
 * Returns one of `enum protolayer_ret` or a negative number
 * indicating an error. */
int session2_unwrap(struct session2 *s, char *buf, size_t buf_len, void *target,
                    protolayer_finished_cb cb, void *baton);

/** Sends the specified buffer to be processed in the `wrap` direction by the
 * session's protocol layers. The `target` parameter may contain a pointer to
 * some data specific to the producer-consumer layer of this session.
 *
 * Once all layers are processed, `cb` is called with `baton` passed as one
 * of its parameters. `cb` may also be `NULL`. See `protolayer_finished_cb` for
 * more info.
 *
 * Returns one of `enum protolayer_ret` or a negative number
 * indicating an error. */
int session2_wrap(struct session2 *s, char *buf, size_t buf_len, void *target,
                  protolayer_finished_cb cb, void *baton);
