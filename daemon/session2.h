/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <uv.h>

#include "contrib/mempattern.h"
#include "lib/generic/queue.h"
#include "lib/generic/trie.h"
#include "lib/utils.h"

/* Forward declarations */
struct session2;
struct protolayer_cb_ctx;

/** Information about the transport - addresses and proxy. */
struct comm_info {
	/** The original address the data came from. May be that of a proxied
	 * client, if they came through a proxy. May be `NULL` if
	 * the communication did not come from network. */
	const struct sockaddr *src_addr;

	/** The actual address the resolver is communicating with. May be
	 * the address of a proxy if the communication came through one,
	 * otherwise it will be the same as `src_addr`. May be `NULL` if
	 * the communication did not come from network. */
	const struct sockaddr *comm_addr;

	/** The original destination address. May be the resolver's address, or
	 * the address of a proxy if the communication came through one. May be
	 * `NULL` if the communication did not come from network. */
	const struct sockaddr *dst_addr;

	/** Data parsed from a PROXY header. May be `NULL` if the communication
	 * did not come through a proxy, or if the PROXYv2 protocol was not used. */
	const struct proxy_result *proxy;
};

/** Protocol types - individual implementations of protocol layers. */
enum protolayer_protocol {
	PROTOLAYER_NULL = 0,
	PROTOLAYER_UDP,
	PROTOLAYER_TCP,
	PROTOLAYER_TLS,
	PROTOLAYER_HTTP,

	PROTOLAYER_UDP_TO_QCONN,
	PROTOLAYER_QCONN_TO_QSTREAM,

	PROTOLAYER_DNS_DGRAM,
	PROTOLAYER_DNS_MSTREAM, /* DoTCP allows multiple packets per stream */
	PROTOLAYER_DNS_SSTREAM, /* DoQ only allows a single packet per stream */

	PROTOLAYER_PROTOCOL_COUNT
};

/** Protocol layer groups. Each of these represents a sequence of layers in
 * the unwrap direction. This macro is used to generate `enum protolayer_grp`
 * and `protolayer_grp_descs[]`.
 *
 * Parameters are:
 *   1. Constant name (for e.g. PROTOLAYER_GRP_* constants)
 *   2. Variable name (for e.g. protolayer_grp_* arrays)
 *   3. Human-readable name for logging */
#define PROTOLAYER_GRP_MAP(XX) \
	XX(DOUDP, doudp, "DNS UDP") \
	XX(DOTCP, dotcp, "DNS TCP") \
	XX(DOTLS, dot, "DNS-over-TLS") \
	XX(DOHTTPS, doh, "DNS-over-HTTPS")

/** Pre-defined sequences of protocol layers. */
enum protolayer_grp {
	PROTOLAYER_GRP_NULL = 0,
#define XX(cid, vid, name) PROTOLAYER_GRP_##cid,
	PROTOLAYER_GRP_MAP(XX)
#undef XX
	PROTOLAYER_GRP_COUNT
};

/** Maps protocol layer group IDs to human-readable descriptions.
 * E.g. PROTOLAYER_GRP_DOH has description 'DNS-over-HTTPS'. */
extern char *protolayer_grp_names[];

/** Flow control indicators for protocol layer `wrap` and `unwrap` callbacks.
 * Use via `protolayer_continue`, `protolayer_wait`, `protolayer_break`, and
 * `protolayer_push` functions. */
enum protolayer_cb_action {
	PROTOLAYER_CB_ACTION_NULL = 0,

	PROTOLAYER_CB_ACTION_CONTINUE,
	PROTOLAYER_CB_ACTION_WAIT,
	PROTOLAYER_CB_ACTION_BREAK,
};

/** Direction of layer sequence processing. */
enum protolayer_direction {
	/** Processes buffers in order of layers as defined in the layer group.
	 * In this direction, protocol data should be removed from the buffer,
	 * parsing additional data provided by the protocol. */
	PROTOLAYER_UNWRAP,

	/** Processes buffers in reverse order of layers as defined in the layer
	 * group. In this direction, protocol data should be added. */
	PROTOLAYER_WRAP,
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
typedef void (*protolayer_finished_cb)(int status, struct session2 *session,
                                       const void *target, void *baton);


#define PROTOLAYER_EVENT_MAP(XX) \
	XX(CLOSE) /**< Signal to gracefully close the session -
	           * i.e. layers add their standard disconnection
	           * ceremony (e.g. `gnutls_bye()`). */\
	XX(FORCE_CLOSE) /**< Signal to forcefully close the
	                 * session - i.e. layers SHOULD NOT add
	                 * any disconnection ceremony, if
	                 * avoidable. */\
	XX(TIMEOUT) /**< Signal that the session has timed out. */\
	XX(CONNECT) /**< Signal that a connection has been established. */

/** Event type, to be interpreted by a layer. */
enum protolayer_event_type {
	PROTOLAYER_EVENT_NULL = 0,
#define XX(cid) PROTOLAYER_EVENT_##cid,
	PROTOLAYER_EVENT_MAP(XX)
#undef XX
	PROTOLAYER_EVENT_COUNT
};

extern char *protolayer_event_names[];


#define PROTOLAYER_PAYLOAD_MAP(XX) \
	XX(BUFFER, "Buffer") \
	XX(IOVEC, "IOVec") \
	XX(WIRE_BUF, "Wire buffer")

/** Defines whether the data for a `struct protolayer_cb_ctx` is represented
 * by a single buffer, an array of `struct iovec`, or an `enum protolayer_event`. */
enum protolayer_payload_type {
	PROTOLAYER_PAYLOAD_NULL = 0,
#define XX(cid, name) PROTOLAYER_PAYLOAD_##cid,
	PROTOLAYER_PAYLOAD_MAP(XX)
#undef XX
	PROTOLAYER_PAYLOAD_COUNT
};

extern char *protolayer_payload_names[];

/** Data processed by the sequence of layers. All pointed-to memory is always
 * owned by its creator. It is also the layer (group) implementor's
 * responsibility to keep data compatible in between layers. No payload memory
 * is ever (de-)allocated by the protolayer manager! */
struct protolayer_payload {
	enum protolayer_payload_type type;
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

		/** Only valid if `type` is `_WIRE_BUF`. */
		struct wire_buf *wire_buf;
	};
};

/** Context for protocol layer callbacks, containing buffer data and internal
 * information for protocol layer manager. */
struct protolayer_cb_ctx {
	/* read-write */
	/** The payload */
	struct protolayer_payload payload;
	/** Transport information (e.g. UDP sender address). May be `NULL`. */
	const void *target;
	/** Communication information. Typically written into by one of the
	 * first layers facilitating transport protocol processing.
	 * Zero-initialized in the beginning. */
	struct comm_info comm;

	/* callback for when the layer iteration has ended - read-only */
	protolayer_finished_cb finished_cb;
	const void *finished_cb_target;
	void *finished_cb_baton;
	struct wire_buf *converted_wire_buf;

	/* internal information for the manager - private */
	enum protolayer_direction direction;
	bool async_mode;
	unsigned int layer_ix;
	struct protolayer_manager *manager;
	int status;
	enum protolayer_cb_action action;
};

/** Convenience function to get a buffer-type payload. */
static inline struct protolayer_payload protolayer_buffer(char *buf, size_t len)
{
	return (struct protolayer_payload){
		.type = PROTOLAYER_PAYLOAD_BUFFER,
		.buffer = {
			.buf = buf,
			.len = len
		}
	};
}

/** Convenience function to get an iovec-type payload. */
static inline struct protolayer_payload protolayer_iovec(
		struct iovec *iov, int iovcnt)
{
	return (struct protolayer_payload){
		.type = PROTOLAYER_PAYLOAD_IOVEC,
		.iovec = {
			.iov = iov,
			.cnt = iovcnt
		}
	};
}

/** Convenience function to get a wire-buf-type payload. */
static inline struct protolayer_payload protolayer_wire_buf(struct wire_buf *wire_buf)
{
	return (struct protolayer_payload){
		.type = PROTOLAYER_PAYLOAD_WIRE_BUF,
		.wire_buf = wire_buf
	};
}

/** Convenience function to represent the specified payload as a buffer-type.
 * Supports only `_BUFFER` and `_WIRE_BUF` on the input, otherwise returns
 * `_NULL` type or aborts on assertion if allowed. */
struct protolayer_payload protolayer_as_buffer(const struct protolayer_payload *payload);


/** Per-session layer-specific data - generic struct. */
struct protolayer_data {
	enum protolayer_protocol protocol;
	bool processed : 1; /**< Internal safeguard so that the layer does not
	                     * get executed multiple times on the same buffer. */
	size_t sess_size; /**< Size of the session data (aligned). */
	size_t iter_size; /**< Size of the iteration data (aligned). */
	uint8_t data[]; /**< Memory for the layer-specific structs. */
};

/** Get a pointer to the session data of the layer. This data shares
 * its lifetime with a session. */
static inline void *protolayer_sess_data(struct protolayer_data *d)
{
	return d->data;
}

/** Gets a pointer to the iteration data of the layer. This data shares its
 * lifetime with an iteration through layers; it is also kept intact when
 * an iteration ends with a `_WAIT` action. */
static inline void *protolayer_iter_data(struct protolayer_data *d)
{
	return d->data + d->sess_size;
}

/** Return value of `protolayer_cb` callbacks. To be generated by continuation
 * functions, never returned directly. */
enum protolayer_cb_result {
	PROTOLAYER_CB_RESULT_MAGIC = 0x364F392E,
};

/** Function type for `wrap` and `unwrap` callbacks of layers. Return value
 * determines the flow of iteration; see the enum docs for more info. */
typedef enum protolayer_cb_result (*protolayer_cb)(
		struct protolayer_data *layer, struct protolayer_cb_ctx *ctx);

/** Function type for `event_wrap` and `event_unwrap` callbacks of layers.
 * `baton` always points to some memory; it may be modified accommodate for
 * the behaviour of the next layer in the sequence.
 *
 * When `true` is returned, iteration proceeds as normal. When `false` is
 * returned, iteration stops. */
typedef bool (*protolayer_event_cb)(enum protolayer_event_type event,
                                    void **baton,
                                    struct protolayer_manager *manager,
                                    struct protolayer_data *layer);

/** Function type for (de)initialization callbacks of layers.
 *
 * Returning 0 means success, other return values mean error and halt the
 * initialization. */
typedef int (*protolayer_data_cb)(struct protolayer_manager *manager,
                                  struct protolayer_data *layer);

/** A collection of protocol layers and their layer-specific data. */
struct protolayer_manager {
	enum protolayer_grp grp;
	bool iter_data_inited : 1; /**< True: layers' iteration data is
	                            * initialized (e.g. from a previous
	                            * iteration). */
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
	size_t sess_size; /**< Size of the layer-specific session data struct. */
	size_t iter_size; /**< Size of the layer-specific iteration data struct. */
	protolayer_data_cb sess_init;   /**< Called upon session creation to
	                                 * initialize layer-specific session
	                                 * data. */
	protolayer_data_cb sess_deinit; /**< Called upon session destruction to
	                                 * deinitialize layer-specific session
	                                 * data. */
	protolayer_data_cb iter_init;   /**< Called at the beginning of a layer
	                                 * sequence to initialize layer-specific
	                                 * iteration data. */
	protolayer_data_cb iter_deinit; /**< Called at the end of a layer
	                                 * sequence to deinitialize
	                                 * layer-specific iteration data. */

	protolayer_cb unwrap; /**< Strips the buffer of protocol-specific
	                       * data. E.g. a HTTP layer removes HTTP
	                       * status and headers. */
	protolayer_cb wrap;   /**< Wraps the buffer into protocol-specific
	                       * data. E.g. a HTTP layer adds HTTP status
	                       * and headers. */

	protolayer_event_cb event_unwrap; /**< Processes events in the unwrap order. */
	protolayer_event_cb event_wrap; /**< Processes events in the wrap order. */
};

/** Global data about layered protocols. Indexed by `enum protolayer_protocol`. */
extern struct protolayer_globals protolayer_globals[PROTOLAYER_PROTOCOL_COUNT];

/** *Continuation function* - signals the protolayer manager to continue
 * processing the next layer. */
enum protolayer_cb_result protolayer_continue(struct protolayer_cb_ctx *ctx);

/** *Continuation function* - signals that the layer needs more data to produce
 * a new buffer for the next layer. */
enum protolayer_cb_result protolayer_wait(struct protolayer_cb_ctx *ctx);

/** *Continuation function* - signals that the layer wants to stop processing
 * of the buffer and clean up, possibly due to an error (indicated by
 * `status`).
 *
 * `status` must be 0 or a negative integer. */
enum protolayer_cb_result protolayer_break(struct protolayer_cb_ctx *ctx, int status);

/** *Continuation function* - pushes data to the session's transport and
 * signals that the layer wants to stop processing of the buffer and clean up.
 *
 * This function is meant to be called by the `wrap` callback of first layer in
 * the sequence.  */
enum protolayer_cb_result protolayer_push(struct protolayer_cb_ctx *ctx);

static inline enum protolayer_cb_result protolayer_async()
{
	return PROTOLAYER_CB_RESULT_MAGIC;
}


/** Wire buffer.
 *
 * May be initialized via `wire_buf_init` or to zero (ZII), then reserved via
 * `wire_buf_reserve`. */
struct wire_buf {
	char *buf; /**< Buffer memory. */
	size_t size; /**< Current size of the buffer memory. */
	size_t start; /**< Index at which the valid data of the buffer starts (inclusive). */
	size_t end; /**< Index at which the valid data of the buffer ends (exclusive). */
	bool error; /**< Whether there has been an error. */
};

/** Allocates the wire buffer with the specified `initial_size`. */
int wire_buf_init(struct wire_buf *wb, size_t initial_size);

/** De-allocates the wire buffer. */
void wire_buf_deinit(struct wire_buf *wb);

/** Ensures that the wire buffer's size is at least `size`. `*wb` must be
 * initialized, either to zero or via `wire_buf_init`. */
int wire_buf_reserve(struct wire_buf *wb, size_t size);

/** Adds `length` to the end index of the valid data, marking `length` more
 * bytes as valid.
 *
 * Returns 0 on success.
 * Returns `kr_error(EINVAL)` if the end index would exceed the
 * buffer size. */
int wire_buf_consume(struct wire_buf *wb, size_t length);

/** Adds `length` to the start index of the valid data, marking `length` less
 * bytes as valid.
 *
 * Returns 0 on success.
 * Returns `kr_error(EINVAL)` if the start index would exceed
 * the end index. */
int wire_buf_trim(struct wire_buf *wb, size_t length);

/** Moves the valid bytes of the buffer to the buffer's beginning. */
int wire_buf_movestart(struct wire_buf *wb);

/** Resets the valid bytes of the buffer to zero, as well as the error flag. */
int wire_buf_reset(struct wire_buf *wb);

static inline void *wire_buf_data(const struct wire_buf *wb)
{
	return &wb->buf[wb->start];
}

static inline size_t wire_buf_data_length(const struct wire_buf *wb)
{
	return wb->end - wb->start;
}

static inline void *wire_buf_free_space(const struct wire_buf *wb)
{
	return &wb->buf[wb->end];
}

static inline size_t wire_buf_free_space_length(const struct wire_buf *wb)
{
	return wb->size - wb->end;
}


/** Indicates how a session sends data in the `wrap` direction and receives
 * data in the `unwrap` direction. */
enum session2_transport_type {
	SESSION2_TRANSPORT_NULL = 0,
	SESSION2_TRANSPORT_IO,
	SESSION2_TRANSPORT_PARENT,
};

struct session2 {
	/** Data for sending data out in the `wrap` direction and receiving new
	 * data in the `unwrap` direction. */
	struct {
		enum session2_transport_type type; /**< See `enum session2_transport_type` */
		union {
			/** For `_IO` type transport. Contains a libuv handle
			 * and session-related addresses. */
			struct {
				uv_handle_t *handle;
				union kr_sockaddr peer;
				union kr_sockaddr sockname;
			} io;

			/** For `_PARENT` type transport. */
			struct session2 *parent;
		};
	} transport;

	struct protolayer_manager *layers; /**< Protocol layers of this session. */
	knot_mm_t pool;

	uv_timer_t timer; /**< For session-wide timeout events. */

	trie_t *tasks; /**< List of tasks associated with given session. */
	queue_t(struct qr_task *) waiting; /**< List of tasks waiting for
	                                    * sending to upstream. */

	struct wire_buf wire_buf;

	uint64_t last_activity; /**< Time of last IO activity (if any occurs).
	                         * Otherwise session creation time. */

	void *data; /**< Pointer to arbitrary data for callbacks. */

	bool outgoing : 1; /**< True: session's transport is towards an upstream
	                    * server. Otherwise, it is towards a client
	                    * connected to the resolver. */
	bool closing : 1; /**< True: session is at the end of its lifecycle and
	                   * is going to close. */
	bool connected : 1; /**< For connection-based sessions. True: connection
	                     * is established. */
	bool throttled : 1; /**< True: session is being rate-limited. */
	bool secure : 1; /**< True: encryption takes place in this session.
	                  * Layers may use this to determine whether padding
	                  * should be applied. */
};

/** Allocates and initializes a new session with the specified protocol layer
 * group, and the provided transport context. */
struct session2 *session2_new(enum session2_transport_type transport_type,
                              enum protolayer_grp layer_grp,
                              bool outgoing);

/** Allocates and initializes a new session with the specified protocol layer
 * group, using a *libuv handle* as its transport. */
static inline struct session2 *session2_new_io(uv_handle_t *handle,
                                               enum protolayer_grp layer_grp,
                                               bool outgoing)
{
	struct session2 *s = session2_new(SESSION2_TRANSPORT_IO, layer_grp, outgoing);
	s->transport.io.handle = handle;
	handle->data = s;
	return s;
}

/** Allocates and initializes a new session with the specified protocol layer
 * group, using a *parent session* as its transport. */
static inline struct session2 *session2_new_child(struct session2 *parent,
                                                  enum protolayer_grp layer_grp,
                                                  bool outgoing)
{
	struct session2 *s = session2_new(SESSION2_TRANSPORT_PARENT, layer_grp, outgoing);
	s->transport.parent = parent;
	return s;
}

/** De-allocates the session. */
void session2_free(struct session2 *s);

/** Start reading from the underlying transport. */
int session2_start_read(struct session2 *session);

/** Stop reading from the underlying transport. */
int session2_stop_read(struct session2 *session);

/** Gets the peer address from the specified session, iterating through the
 * session hierarchy (child-to-parent) until an `_IO` session is found if
 * needed.
 *
 * May return `NULL` if no peer is set.  */
struct sockaddr *session2_get_peer(struct session2 *s);

/** Gets the sockname from the specified session, iterating through the
 * session hierarchy (child-to-parent) until an `_IO` session is found if
 * needed.
 *
 * May return `NULL` if no peer is set.  */
struct sockaddr *session2_get_sockname(struct session2 *s);

/** Gets the libuv handle from the specified session, iterating through the
 * session hierarchy (child-to-parent) until an `_IO` session is found if
 * needed.
 *
 * May return `NULL` if no peer is set.  */
KR_EXPORT uv_handle_t *session2_get_handle(struct session2 *s);

/** Start the session timer. When the timer ends, a `_TIMEOUT` event is sent
 * in the `_UNWRAP` direction. */
int session2_timer_start(struct session2 *s, uint64_t timeout, uint64_t repeat);

/** Restart the session timer without changing any of its parameters. */
int session2_timer_restart(struct session2 *s);

/** Stop the session timer. */
int session2_timer_stop(struct session2 *s);

int session2_tasklist_add(struct session2 *session, struct qr_task *task);
int session2_tasklist_del(struct session2 *session, struct qr_task *task);
struct qr_task *session2_tasklist_get_first(struct session2 *session);
struct qr_task *session2_tasklist_del_first(struct session2 *session, bool deref);
struct qr_task *session2_tasklist_find_msgid(const struct session2 *session, uint16_t msg_id);
struct qr_task *session2_tasklist_del_msgid(const struct session2 *session, uint16_t msg_id);
void session2_tasklist_finalize(struct session2 *session, int status);
int session2_tasklist_finalize_expired(struct session2 *session);

static inline size_t session2_tasklist_get_len(const struct session2 *session)
{
	return trie_weight(session->tasks);
}

static inline bool session2_tasklist_is_empty(const struct session2 *session)
{
	return session2_tasklist_get_len(session) == 0;
}

int session2_waitinglist_push(struct session2 *session, struct qr_task *task);
struct qr_task *session2_waitinglist_get(const struct session2 *session);
struct qr_task *session2_waitinglist_pop(struct session2 *session, bool deref);
void session2_waitinglist_retry(struct session2 *session, bool increase_timeout_cnt);
void session2_waitinglist_finalize(struct session2 *session, int status);

static inline size_t session2_waitinglist_get_len(const struct session2 *session)
{
	return queue_len(session->waiting);
}

static inline bool session2_waitinglist_is_empty(const struct session2 *session)
{
	return session2_waitinglist_get_len(session) == 0;
}

static inline bool session2_is_empty(const struct session2 *session)
{
	return session2_tasklist_is_empty(session) &&
	       session2_waitinglist_is_empty(session);
}

/** Sends the specified `payload` to be processed in the `unwrap` direction by
 * the session's protocol layers. The `target` parameter may contain a pointer
 * to transport-specific data, e.g. for UDP, it shall contain a pointer to the
 * sender's `struct sockaddr_*`.
 *
 * Once all layers are processed, `cb` is called with `baton` passed as one
 * of its parameters. `cb` may also be `NULL`. See `protolayer_finished_cb` for
 * more info.
 *
 * Returns one of `enum protolayer_ret` or a negative number
 * indicating an error. */
int session2_unwrap(struct session2 *s, struct protolayer_payload payload,
                    const void *target, protolayer_finished_cb cb, void *baton);

/** Sends the specified `payload` to be processed in the `wrap` direction by the
 * session's protocol layers. The `target` parameter may contain a pointer to
 * some data specific to the producer-consumer layer of this session.
 *
 * Once all layers are processed, `cb` is called with `baton` passed as one
 * of its parameters. `cb` may also be `NULL`. See `protolayer_finished_cb` for
 * more info.
 *
 * Returns one of `enum protolayer_ret` or a negative number
 * indicating an error. */
int session2_wrap(struct session2 *s, struct protolayer_payload payload,
                  const void *target, protolayer_finished_cb cb, void *baton);

/** Sends an event to be synchronously processed by the protocol layers of the
 * specified session. The layers are first iterated through in the `_UNWRAP`
 * direction, then bounced back in the `_WRAP` direction. */
void session2_event(struct session2 *s, enum protolayer_event_type type, void *baton);

/** Removes the specified request task from the session's tasklist. The session
 * must be outgoing. If the session is UDP, a signal to close is also sent to it. */
void session2_kill_ioreq(struct session2 *session, struct qr_task *task);

/** Update `last_activity` to the current timestamp. */
static inline void session2_touch(struct session2 *session)
{
	session->last_activity = kr_now();
}
