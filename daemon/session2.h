/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/* HINT: If you are looking to implement a new protocol, start with the doc
 * comment of `enum protolayer_protocol` and continue from there. */

#pragma once

#include <stdalign.h>
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

/** Protocol layer types - the individual implementations of protocol layers.
 *
 * To define a new protocol, add a new identifier to this enum, and, within
 * some logical compilation unit (e.g. `daemon/worker.c`), create a function
 * that will initialize the protocol's `protolayer_globals[]`, ideally at the
 * start of the program. See the docs of `struct protolayer_globals` for more
 * details. */
enum protolayer_protocol {
	PROTOLAYER_NULL = 0,

	/* General transport protocols */
	PROTOLAYER_UDP,
	PROTOLAYER_TCP,
	PROTOLAYER_TLS,
	PROTOLAYER_HTTP,

	/* QUIC (not yet implemented) */
	PROTOLAYER_UDP_TO_QCONN,
	PROTOLAYER_QCONN_TO_QSTREAM,

	/* DNS (`worker`) */
	PROTOLAYER_DNS_DGRAM,
	PROTOLAYER_DNS_MSTREAM,
	PROTOLAYER_DNS_SSTREAM,

	PROTOLAYER_PROTOCOL_COUNT /* must be the last! */
};

/** Protocol layer groups. Each of these represents a sequence of layers in the
 * unwrap direction (wrap direction being the opposite). This macro is used to
 * generate `enum protolayer_grp` and `protolayer_grp_descs[]`.
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

/** The identifiers of pre-defined protocol layer sequences. */
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
 * Use via `protolayer_continue`, `protolayer_break`, and `protolayer_push`
 * functions. */
enum protolayer_cb_action {
	PROTOLAYER_CB_ACTION_NULL = 0,

	PROTOLAYER_CB_ACTION_CONTINUE,
	PROTOLAYER_CB_ACTION_BREAK,
};

/** Direction of layer sequence processing. */
enum protolayer_direction {
	/** Processes buffers in order of layers as defined in the layer group.
	 * In this direction, protocol ceremony data should be removed from the
	 * buffer, parsing additional data provided by the protocol. */
	PROTOLAYER_UNWRAP,

	/** Processes buffers in reverse order of layers as defined in the
	 * layer group. In this direction, protocol ceremony data should be
	 * added. */
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
 * `status` may be one of `enum protolayer_ret` or a negative number indicating
 * an error.
 * `target` is the `target` parameter passed to the `session2_(un)wrap`
 * function.
 * `baton` is the `baton` parameter passed to the `session2_(un)wrap` function. */
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
	XX(CONNECT) /**< Signal that a connection has been established. */\
	XX(CONNECT_FAIL) /**< Signal that a connection could not have been established. */\
	XX(DISCONNECT) /**< Signal that a connection has ended. */\
	XX(STATS_SEND_ERR) /**< Failed task send - update stats. */\
	XX(STATS_QRY_OUT) /**< Outgoing query submission - update stats. */

/** Event type, to be interpreted by a layer. */
enum protolayer_event_type {
	PROTOLAYER_EVENT_NULL = 0,
#define XX(cid) PROTOLAYER_EVENT_##cid,
	PROTOLAYER_EVENT_MAP(XX)
#undef XX
	PROTOLAYER_EVENT_COUNT
};

extern char *protolayer_event_names[];


/** Payload types.
 *
 * Parameters are:
 *   1. Constant name
 *   2. Human-readable name for logging */
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

	/* internal information for the manager - private */
	enum protolayer_direction direction;
	bool async_mode;
	unsigned int layer_ix;
	struct protolayer_manager *manager;
	int status;
	enum protolayer_cb_action action;

	/** This contains variably-sized layer-specific data. See `struct
	 * protolayer_manager::data`. */
	alignas(CPU_STRUCT_ALIGN) char data[];
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
 * `_NULL` type or aborts on assertion if allowed.
 *
 * If the input payload is `_WIRE_BUF`, the pointed-to wire buffer is reset
 * to indicate that all of its contents have been used and the buffer is ready
 * to be reused. */
struct protolayer_payload protolayer_as_buffer(const struct protolayer_payload *payload);

/** Mandatory header members for any layer-specific data. */
#define PROTOLAYER_DATA_HEADER() struct {\
	enum protolayer_protocol protocol;\
	struct session2 *session; /**< Pointer to the owner session. */\
}

/** Layer-specific data - generic struct. */
struct protolayer_data {
	PROTOLAYER_DATA_HEADER();
};

/** Return value of `protolayer_cb` callbacks. To be generated by continuation
 * functions, never returned directly. */
enum protolayer_cb_result {
	PROTOLAYER_CB_RESULT_MAGIC = 0x364F392E,
};

/** Function type for `wrap` and `unwrap` callbacks of layers. The function
 * processes the provided `ctx->payload` and decides on the next action for the
 * currently processed sequence.
 *
 * The pointed-to function (or another function, that the pointed-to function
 * causes to be called, e.g. through an asynchronous operation), must call one
 * of the *layer sequence return functions* to advance (or end) the layer
 * iteration. The pointed-to function must return the result of such a return
 * function. */
typedef enum protolayer_cb_result (*protolayer_cb)(
		void *sess_data,
		void *iter_data,
		struct protolayer_cb_ctx *ctx);

/** Function type for `event_wrap` and `event_unwrap` callbacks of layers.
 * The `baton` parameter points to the mutable, iteration-specific baton
 * pointer, initialized by the `baton` parameter of one of the `session2_event`
 * functions. The pointed-to value of `baton` may be modified to accommodate
 * for the next layer in the sequence.
 *
 * When `true` is returned, iteration over the sequence of layers continues.
 * When `false` is returned, iteration stops. */
typedef bool (*protolayer_event_cb)(enum protolayer_event_type event,
                                    void **baton,
                                    struct protolayer_manager *manager,
                                    void *sess_data);

/** Function type for initialization callbacks of layer session data. The
 * `param` value is the one associated with the currently initialized layer,
 * from the `layer_param` array of `session2_new()` - may be NULL if none is
 * provided for the current layer.
 *
 * `data` points to the layer-specific data struct.
 *
 * Returning 0 means success, other return values mean error and halt the
 * initialization. */
typedef int (*protolayer_data_sess_init_cb)(struct protolayer_manager *manager,
                                            void *data,
                                            void *param);

/** Function type for (de)initialization callbacks of layers.
 *
 * `data` points to the layer-specific data struct.
 *
 * Returning 0 means success, other return values mean error and halt the
 * initialization. */
typedef int (*protolayer_data_cb)(struct protolayer_manager *manager,
                                  void *data);

/** A collection of protocol layers and their layer-specific data, tied to a
 * session. The manager contains a sequence of protocol layers (determined by
 * `grp`), which define how the data processed by the session is to be
 * interpreted. */
struct protolayer_manager {
	enum protolayer_grp grp;
	struct session2 *session;
	size_t num_layers;
	size_t cb_ctx_size; /**< Size of a single callback context, including
	                     * layer-specific per-iteration data. */

	/** The following flexible array has basically this structure:
	 *
	 * struct {
	 * 	size_t sess_offsets[num_layers];
	 * 	size_t iter_offsets[num_layers];
	 * 	variably-sized-data sess_data[num_layers];
	 * }
	 *
	 * It is done this way, because different layer groups will have
	 * different numbers of layers and differently-sized layer-specific
	 * data. C does not have a convenient way to define this in structs, so
	 * we do it via this flexible array.
	 *
	 * `sess_offsets` determines data offsets in `sess_data`.
	 *
	 * `iter_offsets` determines data offsets in
	 * `struct protolayer_cb_ctx::data`. */
	alignas(CPU_STRUCT_ALIGN) char data[];
};

/** Initialization parameters for protocol layer session data. */
struct protolayer_data_param {
	enum protolayer_protocol protocol; /**< Which protocol these parameters
	                                     * are meant for. */
	void *param; /**< Pointer to protolayer-related initialization parameters.
	              * Only needs to be valid for session initialization. */
};

/** Global data for a specific layered protocol. This is to be initialized in
 * the `protolayer_globals` global array (below) during the start of the
 * resolver. It contains pointers to the specific protocol's functions. */
struct protolayer_globals {
	/** Size of the layer-specific data struct, that is valid per-session.
	 *
	 * The struct MUST begin with the `PROTOLAYER_DATA_HEADER()` macro. If
	 * no session struct is used by the layer, the value may be zero. */
	size_t sess_size;

	/** Size of the layer-specific data struct, that is valid
	 * per-iteration. It gets created and destroyed together with a `struct
	 * protolayer_cb_ctx`.
	 *
	 * The struct MUST begin with the `PROTOLAYER_DATA_HEADER()` macro. If
	 * no iteration struct is used by the layer, the value may be zero. */
	size_t iter_size;

	/** Called during session creation to initialize layer-specific
	 * session data. */
	protolayer_data_sess_init_cb sess_init;

	/** Called during session destruction to deinitialize layer-specific
	 * session data. */
	protolayer_data_cb sess_deinit;

	/** Called at the beginning of a layer sequence to initialize
	 * layer-specific iteration data. */
	protolayer_data_cb iter_init;

	/** Called at the end of a layer sequence to deinitialize
	 * layer-specific iteration data. */
	protolayer_data_cb iter_deinit;

	/** Strips the buffer of protocol-specific data. E.g. a HTTP layer
	 * removes HTTP status and headers. */
	protolayer_cb unwrap;

	/** Wraps the buffer into protocol-specific data. E.g. a HTTP layer
	 * adds HTTP status and headers. */
	protolayer_cb wrap;

	/** Processes events in the unwrap order (sent from the outside). */
	protolayer_event_cb event_unwrap;

	/** Processes events in the wrap order (bounced back by the session). */
	protolayer_event_cb event_wrap;
};

/** Global data about layered protocols. Indexed by `enum protolayer_protocol`. */
extern struct protolayer_globals protolayer_globals[PROTOLAYER_PROTOCOL_COUNT];

/** *Layer sequence return function* - signalizes the protolayer manager to
 * continue processing the next layer. */
enum protolayer_cb_result protolayer_continue(struct protolayer_cb_ctx *ctx);

/** *Layer sequence return function* - signalizes that the layer wants to stop
 * processing of the buffer and clean up, possibly due to an error (indicated
 * by a non-zero `status`). */
enum protolayer_cb_result protolayer_break(struct protolayer_cb_ctx *ctx, int status);

/** *Layer sequence return function* - signalizes that the current sequence
 * will continue in an asynchronous manner. The layer should store the context
 * and call another sequence return function at another point. This may be used
 * in layers that work through libraries whose operation is asynchronous, like
 * GnuTLS.
 *
 * Note that this return function is just a readability hint - another return
 * function may be called in another stack frame before it and the sequence
 * will continue correctly. */
static inline enum protolayer_cb_result protolayer_async()
{
	return PROTOLAYER_CB_RESULT_MAGIC;
}


/** A buffer, with indices marking the chunk containing valid data.
 *
 * May be initialized in two possible ways:
 *  - via `wire_buf_init`
 *  - to zero, then reserved via `wire_buf_reserve`. */
struct wire_buf {
	char *buf; /**< Buffer memory. */
	size_t size; /**< Current size of the buffer memory. */
	size_t start; /**< Index at which the valid data of the buffer starts (inclusive). */
	size_t end; /**< Index at which the valid data of the buffer ends (exclusive). */
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

/** Gets a pointer to the data marked as valid in the wire buffer. */
static inline void *wire_buf_data(const struct wire_buf *wb)
{
	return &wb->buf[wb->start];
}

/** Gets the length of the data marked as valid in the wire buffer. */
static inline size_t wire_buf_data_length(const struct wire_buf *wb)
{
	return wb->end - wb->start;
}

/** Gets a pointer to the free space after the valid data of the wire buffer. */
static inline void *wire_buf_free_space(const struct wire_buf *wb)
{
	return &wb->buf[wb->end];
}

/** Gets the lengthof the free space after the valid data of the wire buffer. */
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

/** A data unit for a single sequential data source. The data may be organized
 * as a stream or a sequence of datagrams - this is up to the actual individual
 * protocols used by the session, as defined by the `layers` member - see
 * `struct protolayer_manager` and the types of its members for more info.
 *
 * A session processes data in two directions:
 *
 *  - `_UNWRAP` deals with raw data received from the session's transport. It
 *    strips the ceremony of individual protocols from the buffers. The last
 *    (bottommost) layer is generally responsible for submitting the unwrapped
 *    data to be processed by an internal system, e.g. to be resolved as a DNS
 *    query.
 *
 *  - `_WRAP` deals with data generated by an internal system. It adds the
 *    required protocol ceremony to it (e.g. encryption). The first (topmost)
 *    layer is responsible for preparing the data to be sent through the
 *    session's transport. */
struct session2 {
	/** Data for sending data out in the `wrap` direction and receiving new
	 * data in the `unwrap` direction. */
	struct {
		enum session2_transport_type type; /**< See `enum session2_transport_type` */
		union {
			/** For `_IO` type transport. Contains a libuv handle
			 * and session-related address storage. */
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

	/** Managed buffer for data received by `io`. */
	struct wire_buf wire_buf;

	/** Time of last IO activity (if any occurs). Otherwise session
	 * creation time. */
	uint64_t last_activity;

	/** If true, the session's transport is towards an upstream server.
	 * Otherwise, it is towards a client. */
	bool outgoing : 1;

	/** If true, the session is at the end of its lifecycle and is about
	 * to close. */
	bool closing : 1;

	/** If true, encryption takes place in this session. Layers may use
	 * this to determine whether padding should be applied. A layer that
	 * provides security shall set this to `true` during session
	 * initialization. */
	bool secure : 1;

	/** If true, the session contains a stream-based protocol layer.
	 * Set during protocol layer initialization by the stream-based layer. */
	bool stream : 1;

	/** If true, a connection is established. Only applicable to sessions
	 * using connection-based protocols. One of the stream-based protocol
	 * layers is going to be the writer for this flag. */
	bool connected : 1;

	/** If true, session is being rate-limited. One of the protocol layers
	 * is going to be the writer for this flag. */
	bool throttled : 1;
};

/** Allocates and initializes a new session with the specified protocol layer
 * group, and the provided transport context.
 *
 * `layer_param` is a pointer to an array of size `layer_param_count`. The
 * parameters are passed to the layer session initializers. The parameters and
 * the pointed-to data are only required to be valid while calling this
 * function. */
struct session2 *session2_new(enum session2_transport_type transport_type,
                              enum protolayer_grp layer_grp,
                              struct protolayer_data_param *layer_param,
                              size_t layer_param_count,
                              bool outgoing);

/** Allocates and initializes a new session with the specified protocol layer
 * group, using a *libuv handle* as its transport. */
static inline struct session2 *session2_new_io(uv_handle_t *handle,
                                               enum protolayer_grp layer_grp,
                                               struct protolayer_data_param *layer_param,
                                               size_t layer_param_count,
                                               bool outgoing)
{
	struct session2 *s = session2_new(SESSION2_TRANSPORT_IO, layer_grp,
			layer_param, layer_param_count, outgoing);
	s->transport.io.handle = handle;
	handle->data = s;
	return s;
}

/** Allocates and initializes a new session with the specified protocol layer
 * group, using a *parent session* as its transport. */
static inline struct session2 *session2_new_child(struct session2 *parent,
                                                  enum protolayer_grp layer_grp,
                                                  struct protolayer_data_param *layer_param,
                                                  size_t layer_param_count,
                                                  bool outgoing)
{
	struct session2 *s = session2_new(SESSION2_TRANSPORT_PARENT, layer_grp,
			layer_param, layer_param_count, outgoing);
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

/** Sends the specified `payload` to be processed in the `_UNWRAP` direction by
 * the session's protocol layers. The `target` parameter may contain a pointer
 * to transport-specific data, e.g. for UDP, it shall contain a pointer to the
 * sender's `struct sockaddr_*`.
 *
 * Note that the payload data may be modified by any of the layers, to avoid
 * making copies. Once the payload is passed to this function, the content of
 * the referenced data is undefined to the caller.
 *
 * Once all layers are processed, `cb` is called with `baton` passed as one
 * of its parameters. `cb` may also be `NULL`. See `protolayer_finished_cb` for
 * more info.
 *
 * Returns one of `enum protolayer_ret` or a negative number
 * indicating an error. */
int session2_unwrap(struct session2 *s, struct protolayer_payload payload,
                    const void *target, protolayer_finished_cb cb, void *baton);

/** Same as `session2_unwrap`, but looks up the specified `protocol` in the
 * session's assigned protocol group and sends the `payload` to the layer that
 * is next in the sequence in the `_UNWRAP` direction.
 *
 * Layers may use this to generate their own data to send in the sequence, e.g.
 * for protocol-specific ceremony. */
int session2_unwrap_after(struct session2 *s, enum protolayer_protocol protocol,
                         struct protolayer_payload payload, const void *target,
                         protolayer_finished_cb cb, void *baton);

/** Sends the specified `payload` to be processed in the `_WRAP` direction by
 * the session's protocol layers. The `target` parameter may contain a pointer
 * to some data specific to the bottommost layer of this session.
 *
 * Note that the payload data may be modified by any of the layers, to avoid
 * making copies. Once the payload is passed to this function, the content of
 * the referenced data is undefined to the caller.
 *
 * Once all layers are processed, `cb` is called with `baton` passed as one
 * of its parameters. `cb` may also be `NULL`. See `protolayer_finished_cb` for
 * more info.
 *
 * Returns one of `enum protolayer_ret` or a negative number
 * indicating an error. */
int session2_wrap(struct session2 *s, struct protolayer_payload payload,
                  const void *target, protolayer_finished_cb cb, void *baton);

/** Same as `session2_wrap`, but looks up the specified `protocol` in the
 * session's assigned protocol group and sends the `payload` to the layer that
 * is next in the sequence in the `_WRAP` direction.
 *
 * Layers may use this to generate their own data to send in the sequence, e.g.
 * for protocol-specific ceremony. */
int session2_wrap_after(struct session2 *s, enum protolayer_protocol protocol,
                       struct protolayer_payload payload, const void *target,
                       protolayer_finished_cb cb, void *baton);

/** Sends an event to be synchronously processed by the protocol layers of the
 * specified session. The layers are first iterated through in the `_UNWRAP`
 * direction, then bounced back in the `_WRAP` direction. */
void session2_event(struct session2 *s, enum protolayer_event_type type, void *baton);

/** Sends an event to be synchronously processed by the protocol layers of the
 * specified session, starting from the specified `protocol` in the `_UNWRAP`
 * direction. The layers are first iterated through in the `_UNWRAP` direction,
 * then bounced back in the `_WRAP` direction. */
void session2_event_after(struct session2 *s, enum protolayer_protocol protocol,
                          enum protolayer_event_type type, void *baton);

/** Removes the specified request task from the session's tasklist. The session
 * must be outgoing. If the session is UDP, a signal to close is also sent to it. */
void session2_kill_ioreq(struct session2 *session, struct qr_task *task);

/** Update `last_activity` to the current timestamp. */
static inline void session2_touch(struct session2 *session)
{
	session->last_activity = kr_now();
}
