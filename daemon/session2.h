/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/* High-level explanation of layered protocols: ./layered-protocols.rst */

/* HINT: If you are looking to implement support for a new transport protocol,
 * start with the doc comment of the `PROTOLAYER_TYPE_MAP` macro and
 * continue from there. */

/* GLOSSARY:
 *
 * Event:
 *   - An Event may be processed by the protocol layer sequence much like a
 *   Payload, but with a special callback. Events may be used to notify layers
 *   that e.g. a connection has been established; a timeout has occurred; a
 *   malformed packet has been received, etc. Events are generally not sent
 *   through the transport - they may, however, trigger a new payload to be
 *   sent, e.g. a HTTP error status response.
 *
 * Iteration:
 *   - The processing of Payload data or an event using a particular sequence
 *   of Protocol layers, either in Wrap or Unwrap direction. For payload
 *   processing, it is also the lifetime of `struct protolayer_iter_ctx` and
 *   layer-specific data contained therein.
 *
 * Layer sequence return function:
 *   - One of `protolayer_break()`, `protolayer_continue()`, or
 *   `protolayer_async()` - a function that a protolayer's `_wrap` or `_unwrap`
 *   callback should call to get its return value. They may either be called
 *   synchronously directly in the callback to end/pause the processing, or, if
 *   the processing went asynchronous, called to resume the iteration of layers.
 *
 * Payload:
 *   - Data processed by protocol layers in a particular sequence. In the wrap
 *   direction, this data generally starts as a DNS packet, which is then
 *   wrapped in protocol ceremony data by each layer. In the unwrap direction,
 *   the opposite takes place - ceremony data is removed until a raw DNS packet
 *   is retrieved.
 *
 * Protocol layer:
 *   - Not to be confused with `struct kr_layer_api`. An implementation of a
 *   particular protocol. A protocol layer transforms payloads to conform to a
 *   particular protocol, e.g. UDP, TCP, TLS, HTTP, QUIC, etc. While
 *   transforming a payload, a layer may also modify metadata - e.g. the UDP and
 *   TCP layers in the Unwrap direction implement the PROXYv2 protocol, using
 *   which they retrieve the IP address of the actual originating client and
 *   store it in the appropriate struct.
 *
 * Protolayer:
 *   - Short for 'protocol layer'.
 *
 * Unwrap:
 *   - The direction of data transformation, which starts with the transport
 *   (e.g. bytes that came from the network) and ends with an internal subsystem
 *   (e.g. DNS query resolution).
 *
 * Wrap:
 *   - The direction of data transformation, which starts with an internal
 *   subsystem (e.g. an answer to a resolved DNS query) and ends with the
 *   transport (e.g. bytes that are going to be sent to the client). */

#pragma once

#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <uv.h>

#include "contrib/mempattern.h"
#include "lib/generic/queue.h"
#include "lib/generic/trie.h"
#include "lib/proto.h"
#include "lib/utils.h"

/* Forward declarations */
struct session2;
struct protolayer_iter_ctx;


/** Type of MAC addresses. */
typedef uint8_t ethaddr_t[6];

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
	 * did not come through a proxy, or if the PROXYv2 protocol was not
	 * used. */
	const struct proxy_result *proxy;

	/** Pointer to protolayer-specific data, e.g. a key to decide, which
	 * sub-session to use. */
	void *target;

	/* XDP data */
	ethaddr_t eth_from;
	ethaddr_t eth_to;
	bool xdp:1;
};

/** Just a simple struct able to hold three IPv6 or IPv4 addresses, so that we
 * can hold them somewhere. */
struct comm_addr_storage {
	union kr_sockaddr src_addr;
	union kr_sockaddr comm_addr;
	union kr_sockaddr dst_addr;
};


/** A buffer control struct, with indices marking a chunk containing received
 * but as of yet unprocessed data - the data in this chunk is called "valid
 * data". The struct may be manipulated using `wire_buf_` functions, which
 * contain bounds checks to ensure correct behaviour.
 *
 * The struct may be used to retrieve data piecewise (e.g. from a stream-based
 * transport like TCP) by writing data to the buffer's free space, then
 * "consuming" that space with `wire_buf_consume`. It can also be handy for
 * processing message headers, then trimming the beginning of the buffer (using
 * `wire_buf_trim`) so that the next part of the data may be processed by
 * another part of a pipeline.
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

/** Initializes the wire buffer with the specified `initial_size` and allocates
 * the underlying memory. */
int wire_buf_init(struct wire_buf *wb, size_t initial_size);

/** De-allocates the wire buffer's underlying memory (the struct itself is left
 * intact). */
void wire_buf_deinit(struct wire_buf *wb);

/** Ensures that the wire buffer's size is at least `size`. The memory at `wb`
 * must be initialized, either to zero or via `wire_buf_init`. */
int wire_buf_reserve(struct wire_buf *wb, size_t size);

/** Adds `length` to the end index of the valid data, marking `length` more
 * bytes as valid.
 *
 * Returns 0 on success.
 * Assert-fails and/or returns `kr_error(EINVAL)` if the end index would exceed
 * the buffer size. */
int wire_buf_consume(struct wire_buf *wb, size_t length);

/** Adds `length` to the start index of the valid data, marking `length` less
 * bytes as valid.
 *
 * Returns 0 on success.
 * Assert-fails and/or returns `kr_error(EINVAL)` if the start index would
 * exceed the end index. */
int wire_buf_trim(struct wire_buf *wb, size_t length);

/** Moves the valid bytes of the buffer to the buffer's beginning. */
int wire_buf_movestart(struct wire_buf *wb);

/** Marks the wire buffer as empty. */
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
	return (wb->buf) ? &wb->buf[wb->end] : NULL;
}

/** Gets the length of the free space after the valid data of the wire buffer. */
static inline size_t wire_buf_free_space_length(const struct wire_buf *wb)
{
	if (kr_fails_assert(wb->end <= wb->size))
		return 0;
	return (wb->buf) ? wb->size - wb->end : 0;
}


/** Protocol layer types map - an enumeration of individual protocol layer
 * implementations
 *
 * This macro is used to generate `enum protolayer_type` as well as other
 * additional data on protocols, e.g. name string constants.
 *
 * To define a new protocol, add a new identifier to this macro, and, within
 * some logical compilation unit (e.g. `daemon/worker.c` for DNS layers),
 * initialize the protocol's `protolayer_globals[]`, ideally in a function
 * called at the start of the program (e.g. `worker_init()`). See the docs of
 * `struct protolayer_globals` for details on what data this structure should
 * contain.
 *
 * To use protocols within sessions, protocol layer groups also need to be
 * defined, to indicate the order in which individual protocols are to be
 * processed. See `KR_PROTO_MAP` below for more details. */
#define PROTOLAYER_TYPE_MAP(XX) \
	/* General transport protocols */\
	XX(UDP)\
	XX(TCP)\
	XX(TLS)\
	XX(HTTP)\
	\
	/* PROXYv2 */\
	XX(PROXYV2_DGRAM)\
	XX(PROXYV2_STREAM)\
	\
	/* DNS (`worker`) */\
	XX(DNS_DGRAM) /**< Packets WITHOUT prepended size, one per (un)wrap,
	               * limited to UDP sizes, multiple sources (single
	               * session for multiple clients). */\
	XX(DNS_UNSIZED_STREAM) /**< Singular packet WITHOUT prepended size, one
	                        * per (un)wrap, no UDP limits, single source. */\
	XX(DNS_MULTI_STREAM) /**< Multiple packets WITH prepended sizes in a
	                      * stream (may span multiple (un)wraps). */\
	XX(DNS_SINGLE_STREAM) /**< Singular packet WITH prepended size in a
	                       * stream (may span multiple (un)wraps). */\
	/* Prioritization of requests */\
	XX(DEFER) \
	/* DNS Tunneling*/\
	XX(TUNNEL)

/** The identifiers of protocol layer types. */
enum protolayer_type {
	PROTOLAYER_TYPE_NULL = 0,
#define XX(cid) PROTOLAYER_TYPE_ ## cid,
	PROTOLAYER_TYPE_MAP(XX)
#undef XX
	PROTOLAYER_TYPE_COUNT /* must be the last! */
};

/** Gets the constant string name of the specified protocol. */
const char *protolayer_layer_name(enum protolayer_type p);

/** Flow control indicators for protocol layer `wrap` and `unwrap` callbacks.
 * Use via `protolayer_continue`, `protolayer_break`, and `protolayer_push`
 * functions. */
enum protolayer_iter_action {
	PROTOLAYER_ITER_ACTION_NULL = 0,

	PROTOLAYER_ITER_ACTION_CONTINUE,
	PROTOLAYER_ITER_ACTION_BREAK,
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

/** Returned by a successful call to `session2_wrap()` or `session2_unwrap()`
 * functions. */
enum protolayer_ret {
	/** Returned when a protolayer context iteration has finished
	 * processing, i.e. with `protolayer_break()`. */
	PROTOLAYER_RET_NORMAL = 0,

	/** Returned when a protolayer context iteration is waiting for an
	 * asynchronous callback to a continuation function. This will never be
	 * passed to `protolayer_finished_cb`, only returned by
	 * `session2_unwrap` or `session2_wrap`. */
	PROTOLAYER_RET_ASYNC,
};

/** Called when a payload iteration (started by `session2_unwrap` or
 * `session2_wrap`) has ended - i.e. the input buffer will not be processed any
 * further.
 *
 * `status` may be one of `enum protolayer_ret` or a negative number indicating
 * an error.
 * `target` is the `target` parameter passed to the `session2_(un)wrap`
 * function.
 * `baton` is the `baton` parameter passed to the `session2_(un)wrap` function. */
typedef void (*protolayer_finished_cb)(int status, struct session2 *session,
                                       const struct comm_info *comm, void *baton);


/** Protocol layer event type map
 *
 * This macro is used to generate `enum protolayer_event_type` as well as the
 * relevant name string constants for each event type.
 *
 * Event types are used to distinguish different events that can be passed to
 * sessions using `session2_event()`. */
#define PROTOLAYER_EVENT_MAP(XX) \
	/** Closes the session gracefully - i.e. layers add their standard
	 * disconnection ceremony (e.g. `gnutls_bye()`). */\
	XX(CLOSE) \
	/** Closes the session forcefully - i.e. layers SHOULD NOT add any
	 * disconnection ceremony, if avoidable. */\
	XX(FORCE_CLOSE) \
	/** Signal that a connection could not be established due to a timeout. */\
	XX(CONNECT_TIMEOUT) \
	/** Signal that a general application-defined timeout has occurred. */\
	XX(GENERAL_TIMEOUT) \
	/** Signal that a connection has been established. */\
	XX(CONNECT) \
	/** Signal that a connection could not have been established. */\
	XX(CONNECT_FAIL) \
	/** Signal that a malformed request has been received. */\
	XX(MALFORMED) \
	/** Signal that a connection has ended. */\
	XX(DISCONNECT) \
	/** Signal EOF from peer (e.g. half-closed TCP connection). */\
	XX(EOF) \
	/** Failed task send - update stats. */\
	XX(STATS_SEND_ERR) \
	/** Outgoing query submission - update stats. */\
	XX(STATS_QRY_OUT) \
	/** OS buffers are full, so not sending any more data. */\
	XX(OS_BUFFER_FULL) \
	//

/** Event type, to be interpreted by a layer. */
enum protolayer_event_type {
	PROTOLAYER_EVENT_NULL = 0,
#define XX(cid) PROTOLAYER_EVENT_ ## cid,
	PROTOLAYER_EVENT_MAP(XX)
#undef XX
	PROTOLAYER_EVENT_COUNT
};

/** Gets the constant string name of the specified event. */
const char *protolayer_event_name(enum protolayer_event_type e);


/** Payload types.
 *
 * Parameters are:
 *   1. Constant name
 *   2. Human-readable name for logging */
#define PROTOLAYER_PAYLOAD_MAP(XX) \
	XX(BUFFER, "Buffer") \
	XX(IOVEC, "IOVec") \
	XX(WIRE_BUF, "Wire buffer")

/** Determines which union member of `struct protolayer_payload` is currently
 * valid. */
enum protolayer_payload_type {
	PROTOLAYER_PAYLOAD_NULL = 0,
#define XX(cid, name) PROTOLAYER_PAYLOAD_##cid,
	PROTOLAYER_PAYLOAD_MAP(XX)
#undef XX
	PROTOLAYER_PAYLOAD_COUNT
};

/** Gets the constant string name of the specified payload type. */
const char *protolayer_payload_name(enum protolayer_payload_type p);

/** Data processed by the sequence of layers. All pointed-to memory is always
 * owned by its creator. It is also the layer (group) implementor's
 * responsibility to keep data compatible in between layers. No payload memory
 * is ever (de-)allocated by the protolayer manager! */
struct protolayer_payload {
	enum protolayer_payload_type type;

	/** Time-to-live hint (e.g. for HTTP Cache-Control) */
	unsigned int ttl;

	/** If `true`, signifies that the memory this payload points to may
	 * become invalid when we return from one of the functions in the
	 * current stack. That is fine as long as all the protocol layer
	 * processing for this payload takes place in a single `session2_wrap()`
	 * or `session2_unwrap()` call, but may become a problem, when a layer
	 * goes asynchronous (via `protolayer_async()`).
	 *
	 * Setting this to `true` will ensure that the payload will get copied
	 * into a separate memory buffer if and only if a layer goes
	 * asynchronous. It makes sure that if all processing for the payload is
	 * synchronous, no copies or reallocations for the payload are done. */
	bool short_lived;

	union {
		/** Only valid if `type` is `_BUFFER`. */
		struct {
			void *buf;
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

/** Context for protocol layer iterations, containing payload data,
 * layer-specific data, and internal information for the protocol layer
 * manager. */
struct protolayer_iter_ctx {
/* read-write for layers: */
	/** The payload */
	struct protolayer_payload payload;
	/** Pointer to communication information. For TCP, this will generally
	 * point to the storage in the session. For UDP, this will generally
	 * point to the storage in this context. */
	struct comm_info *comm;
	/** Communication information storage. This will generally be set by one
	 * of the first layers in the sequence, if used, e.g. UDP PROXYv2. */
	struct comm_info comm_storage;
	struct comm_addr_storage comm_addr_storage;
	/** Per-iter memory pool. Has no `free` procedure, gets freed as a whole
	 * when the context is being destroyed. Initialized and destroyed
	 * automatically - layers may use it to allocate memory. */
	knot_mm_t pool;

/* callback for when the layer iteration has ended - read-only for layers: */
	protolayer_finished_cb finished_cb;
	void *finished_cb_baton;

/* internal information for the manager - should only be used by the protolayer
 * system, never by layers: */
	enum protolayer_direction direction;
	/** If `true`, the processing of the layer sequence has been paused and
	 * is waiting to be resumed (`protolayer_continue()`) or cancelled
	 * (`protolayer_break()`). */
	bool async_mode;
	/** The index of the layer that is currently being (or has just been)
	 * processed. */
	unsigned int layer_ix;
	struct session2 *session;
	/** Status passed to the finish callback. */
	int status;
	enum protolayer_iter_action action;

	/** Contains a sequence of variably-sized CPU-aligned layer-specific
	 * structs. See `struct session2::layer_data` for details. */
	alignas(CPU_STRUCT_ALIGN) char data[];
};

/** Gets the total size of the data in the specified payload. */
size_t protolayer_payload_size(const struct protolayer_payload *payload);

/** Copies the specified payload to `dest`. Only `max_len` or the size of the
 * payload is written, whichever is less.
 *
 * Returns the actual length of copied data. */
size_t protolayer_payload_copy(void *dest,
                               const struct protolayer_payload *payload,
                               size_t max_len);

/** Convenience function to get a buffer-type payload. */
static inline struct protolayer_payload protolayer_payload_buffer(
		void *buf, size_t len, bool short_lived)
{
	return (struct protolayer_payload){
		.type = PROTOLAYER_PAYLOAD_BUFFER,
		.short_lived = short_lived,
		.buffer = {
			.buf = buf,
			.len = len
		}
	};
}

/** Convenience function to get an iovec-type payload. */
static inline struct protolayer_payload protolayer_payload_iovec(
		struct iovec *iov, int iovcnt, bool short_lived)
{
	return (struct protolayer_payload){
		.type = PROTOLAYER_PAYLOAD_IOVEC,
		.short_lived = short_lived,
		.iovec = {
			.iov = iov,
			.cnt = iovcnt
		}
	};
}

/** Convenience function to get a wire-buf-type payload. */
static inline struct protolayer_payload protolayer_payload_wire_buf(
		struct wire_buf *wire_buf, bool short_lived)
{
	return (struct protolayer_payload){
		.type = PROTOLAYER_PAYLOAD_WIRE_BUF,
		.short_lived = short_lived,
		.wire_buf = wire_buf
	};
}

/** Convenience function to represent the specified payload as a buffer-type.
 * Supports only `_BUFFER` and `_WIRE_BUF` on the input, otherwise returns
 * `_NULL` type or aborts on assertion if allowed.
 *
 * If the input payload is `_WIRE_BUF`, the pointed-to wire buffer is reset to
 * indicate that all of its contents have been used up, and the buffer is ready
 * to be reused. */
struct protolayer_payload protolayer_payload_as_buffer(
		const struct protolayer_payload *payload);

/** A predefined queue type for iteration context. */
typedef queue_t(struct protolayer_iter_ctx *) protolayer_iter_ctx_queue_t;

/** Iterates through the specified `queue` and gets the sum of all payloads
 * available in it. */
size_t protolayer_queue_count_payload(const protolayer_iter_ctx_queue_t *queue);

/** Checks if the specified `queue` has any payload data (i.e.
 * `protolayer_queue_count_payload` would be non-zero). This optimizes calls to
 * queue iterators, as it does not need to iterate through the whole queue. */
bool protolayer_queue_has_payload(const protolayer_iter_ctx_queue_t *queue);

/** Gets layer-specific session data for the specified protocol layer.
 * Returns NULL if the layer is not present in the session. */
void *protolayer_sess_data_get_proto(struct session2 *s, enum protolayer_type protocol);

/** Gets layer-specific session data for the last processed layer.
 * To be used after returning from its callback for async continuation but before calling protolayer_continue. */
void *protolayer_sess_data_get_current(struct protolayer_iter_ctx *ctx);

/** Gets layer-specific iteration data for the last processed layer.
 * To be used after returning from its callback for async continuation but before calling protolayer_continue. */
void *protolayer_iter_data_get_current(struct protolayer_iter_ctx *ctx);

/** Gets rough memory footprint estimate of session/iteration for use in defer.
 * Different, hopefully minor, allocations are not counted here;
 * tasks and subsessions are also not counted;
 * read the code before using elsewhere. */
size_t protolayer_sess_size_est(struct session2 *s);
size_t protolayer_iter_size_est(struct protolayer_iter_ctx *ctx, bool incl_payload);

/** Layer-specific data - the generic struct. To be added as the first member of
 * each specific struct. */
struct protolayer_data {
	struct session2 *session; /**< Pointer to the owner session. */\
};

/** Return value of `protolayer_iter_cb` callbacks. To be returned by *layer
 * sequence return functions* (see glossary) as a sanity check. Not to be used
 * directly by user code. */
enum protolayer_iter_cb_result {
	PROTOLAYER_ITER_CB_RESULT_MAGIC = 0x364F392E,
};

/** Function type for `struct protolayer_globals::wrap` and `struct
 * protolayer_globals::unwrap`. The function processes the provided
 * `ctx->payload` and decides the next action for the currently processed
 * sequence.
 *
 * The function (or another function, that the pointed-to function causes to be
 * called, directly or through an asynchronous operation), must call one of the
 * *layer sequence return functions* (see glossary) to advance (or end) the
 * layer sequence. The function must return the result of such a return
 * function. */
typedef enum protolayer_iter_cb_result (*protolayer_iter_cb)(
		void *sess_data,
		void *iter_data,
		struct protolayer_iter_ctx *ctx);

/** Return value of `protolayer_event_cb` callbacks. Controls the flow of
 * events. See `protolayer_event_cb` for details. */
enum protolayer_event_cb_result {
	PROTOLAYER_EVENT_CONSUME = 0,
	PROTOLAYER_EVENT_PROPAGATE = 1
};

/** Function type for `struct protolayer_globals::event_wrap` and `struct
 * protolayer_globals::event_unwrap` callbacks of layers. The `baton` parameter
 * points to the mutable, iteration-specific baton pointer, initialized by the
 * `baton` parameter of one of the `session2_event` functions. The pointed-to
 * value of `baton` may be modified to accommodate for the next layer in the
 * sequence.
 *
 * When `PROTOLAYER_EVENT_PROPAGATE` is returned, iteration over the sequence
 * of layers continues. When `PROTOLAYER_EVENT_CONSUME` is returned, iteration
 * stops.
 *
 * **IMPORTANT:** A well-behaved layer will **ALWAYS** propagate events it knows
 * nothing about. Only ever consume events you actually have good reason to
 * consume (like TLS consumes `CONNECT` from TCP, because it needs to perform
 * its own handshake first). */
typedef enum protolayer_event_cb_result (*protolayer_event_cb)(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data);

/** Function type for initialization callbacks of layer session data.
 *
 * The `param` value is the one associated with the currently initialized
 * layer, from the `layer_param` array of `session2_new()` - may be NULL if
 * none is provided for the current layer.
 *
 * `data` points to the layer-specific data struct.
 *
 * Returning 0 means success, other return values mean error and halt the
 * initialization. */
typedef int (*protolayer_data_sess_init_cb)(struct session2 *session,
                                            void *data, void *param);

/** Function type for determining the size of a layer's wire buffer overhead. */
typedef size_t (*protolayer_wire_buf_overhead_cb)(bool outgoing);

/** Function type for (de)initialization callback of layer iteration data.
 *
 * `ctx` points to the iteration context that `data` belongs to.
 *
 * `data` points to the layer-specific data struct.
 *
 * Returning 0 means success, other return values mean error and halt the
 * initialization. */
typedef int (*protolayer_iter_data_cb)(struct protolayer_iter_ctx *ctx,
                                       void *data);

/** Function type for (de)initialization callbacks of layers.
 *
 * `data` points to the layer-specific data struct.
 *
 * Returning 0 means success, other return values mean error and halt the
 * initialization. */
typedef int (*protolayer_data_cb)(struct session2 *session, void *data);

/** Function type for (de)initialization callbacks of DNS requests.
 *
 * `req` points to the request for initialization.
 * `sess_data` points to layer-specific session data struct. */
typedef void (*protolayer_request_cb)(struct session2 *session,
                                      struct kr_request *req,
                                      void *sess_data);

/** Initialization parameters for protocol layer session data. */
struct protolayer_data_param {
	enum protolayer_type protocol; /**< Which protocol these parameters
	                                    * are meant for. */
	void *param; /**< Pointer to protolayer-related initialization
	              * parameters. Only needs to be valid during session
	              * initialization. */
};

/** Global data for a specific layered protocol. This is to be initialized in
 * the `protolayer_globals` global array (below) during the the resolver's
 * startup. It contains pointers to functions implementing a particular
 * protocol, as well as other important data.
 *
 * Every member of this struct is allowed to be zero/NULL if a particular
 * protocol has no use for it. */
struct protolayer_globals {
	/** Size of the layer-specific data struct, valid per-session.
	 *
	 * The struct MUST begin with a `struct protolayer_data` member. If
	 * no session struct is used by the layer, the value may be zero. */
	size_t sess_size;

	/** Size of the layer-specific data struct, valid per-iteration. It
	 * gets created and destroyed together with a `struct
	 * protolayer_iter_ctx`.
	 *
	 * The struct MUST begin with a `struct protolayer_data` member. If
	 * no iteration struct is used by the layer, the value may be zero. */
	size_t iter_size;

	/** Number of bytes that this layer adds onto the session's wire buffer
	 * by default. All overheads in a group are summed together to form the
	 * resulting default wire buffer length.
	 *
	 * Ignored when `wire_buf_overhead_cb` is non-NULL. */
	size_t wire_buf_overhead;

	/** Called during session initialization to determine the number of
	 * bytes that this layer adds onto the session's wire buffer.
	 *
	 * It is the dynamic version of `wire_buf_overhead`, which is ignored
	 * when this is non-NULL. */
	protolayer_wire_buf_overhead_cb wire_buf_overhead_cb;

	/** Number of bytes that this layer adds onto the session's wire buffer
	 * at most. All overheads in a group are summed together to form the
	 * resulting default wire buffer length.
	 *
	 * If this is less than the default overhead, the default is used
	 * instead. */
	size_t wire_buf_max_overhead;

	/** Called during session creation to initialize
	 * layer-specific session data. The data is always provided
	 * zero-initialized to this function. */
	protolayer_data_sess_init_cb sess_init;

	/** Called during session destruction to deinitialize
	 * layer-specific session data. */
	protolayer_data_cb sess_deinit;

	/** Called at the beginning of a non-event layer sequence to initialize
	 * layer-specific iteration data. The data is always zero-initialized
	 * during iteration context initialization. */
	protolayer_iter_data_cb iter_init;

	/** Called at the end of a non-event layer sequence to deinitialize
	 * layer-specific iteration data. */
	protolayer_iter_data_cb iter_deinit;

	/** Strips the buffer of protocol-specific data. E.g. a HTTP layer
	 * removes HTTP status and headers. Optional - iteration continues
	 * automatically if this is NULL. */
	protolayer_iter_cb unwrap;

	/** Wraps the buffer into protocol-specific data. E.g. a HTTP layer
	 * adds HTTP status and headers. Optional - iteration continues
	 * automatically if this is NULL. */
	protolayer_iter_cb wrap;

	/** Processes events in the unwrap order (sent from the outside).
	 * Optional - iteration continues automatically if this is NULL. */
	protolayer_event_cb event_unwrap;

	/** Processes events in the wrap order (bounced back by the session).
	 * Optional - iteration continues automatically if this is NULL. */
	protolayer_event_cb event_wrap;

	/** Modifies the provided request for use with the layer. Mostly for
	 * setting `struct kr_request::qsource.comm_flags`. */
	protolayer_request_cb request_init;
};

/** Global data about layered protocols. Mapped by `enum protolayer_type`.
 * Individual protocols are to be initialized during resolver startup. */
extern struct protolayer_globals protolayer_globals[PROTOLAYER_TYPE_COUNT];


/** *Layer sequence return function* (see glossary) - signalizes the protolayer
 * manager to continue processing the next layer. */
enum protolayer_iter_cb_result protolayer_continue(struct protolayer_iter_ctx *ctx);

/** *Layer sequence return function* (see glossary) - signalizes that the layer
 * wants to stop processing of the buffer and clean up, possibly due to an error
 * (indicated by a non-zero `status`). */
enum protolayer_iter_cb_result protolayer_break(struct protolayer_iter_ctx *ctx, int status);

/** *Layer sequence return function* (see glossary) - signalizes that the
 * current sequence will continue in an asynchronous manner. The layer should
 * store the context and call another sequence return function at another point.
 * This may be used in layers that work through libraries whose operation is
 * asynchronous, like GnuTLS.
 *
 * Note that this one is basically just a readability hint - another return
 * function may be actually called before it (generally during a call to an
 * external library function, e.g. GnuTLS or nghttp2). This is completely legal
 * and the sequence will continue correctly. */
static inline enum protolayer_iter_cb_result protolayer_async(void)
{
	return PROTOLAYER_ITER_CB_RESULT_MAGIC;
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
 * protocols used by the session - see `enum kr_proto` and
 * `protolayer_`-prefixed types and functions for more information.
 *
 * A session processes data in two directions:
 *
 *  - `_UNWRAP` deals with raw data received from the session's transport. It
 *  strips the ceremony of individual protocols from the buffers, retaining any
 *  required metadata in an iteration context (`struct protolayer_iter_ctx`).
 *  The last layer (as defined by a `protolayer_grp_*` array in `session2.c`) in
 *  a sequence is generally responsible for submitting the unwrapped data to be
 *  processed by an internal system, e.g. to be resolved as a DNS query.
 *
 *  - `_WRAP` deals with data generated by an internal system. It adds the
 *  required protocol ceremony to it (e.g. encryption). The first layer (as
 *  defined by a `protolayer_grp_*` array in `session2.c`) is responsible for
 *  preparing the data to be sent through the session's transport. */
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

	uv_timer_t timer; /**< For session-wide timeout events. */
	enum protolayer_event_type timer_event; /**< The event fired on timeout. */
	trie_t *tasks; /**< List of tasks associated with given session. */
	queue_t(struct qr_task *) waiting; /**< List of tasks waiting for
	                                    * sending to upstream. */
	struct wire_buf wire_buf;
	uint32_t log_id; /**< Session ID for logging. */

	int ref_count; /**< Number of unclosed libUV handles owned by this
	               * session + iteration contexts referencing the session. */

	/** Communication information. Typically written into by one of the
	 * first layers facilitating transport protocol processing.
	 * Zero-initialized by default. */
	struct comm_info comm_storage;

	/** Time of last IO activity (if any occurs). Otherwise session
	 * creation time. */
	uint64_t last_activity;

	/** If true, the session's transport is towards an upstream server.
	 * Otherwise, it is towards a client. */
	bool outgoing : 1;

	/** If true, the session is at the end of its lifecycle and is about
	 * to close. */
	bool closing : 1;

	/** If true, the session has done something useful,
	 * e.g. it has produced a packet. */
	bool was_useful : 1;

	/** If true, encryption takes place in this session. Layers may use
	 * this to determine whether padding should be applied. A layer that
	 * provides security shall set this to `true` during session
	 * initialization. */
	bool secure : 1;

	/** If true, the session contains a stream-based protocol layer.
	 * Set during protocol layer initialization by the stream-based layer. */
	bool stream : 1;

	/** If true, the session contains a protocol layer with custom handling
	 * of malformed queries. This is used e.g. by the HTTP layer, which will
	 * return a Bad Request status on a malformed query. */
	bool custom_emalf_handling : 1;

	/** If true, session is being rate-limited. One of the protocol layers
	 * is going to be the writer for this flag. */
	bool throttled : 1;

	/* Protocol layers */

	/** The set of protocol layers used by this session. */
	enum kr_proto proto;
	/** The size of a single iteration context
	 * (`struct protolayer_iter_ctx`), including layer-specific data. */
	size_t iter_ctx_size;

	/** The size of this session struct. */
	size_t session_size;

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
	 * `sess_data` is a sequence of variably-sized CPU-aligned
	 * layer-specific structs.
	 *
	 * `sess_offsets` determines data offsets in `sess_data` for pointer
	 * retrieval.
	 *
	 * `iter_offsets` determines data offsets in `struct
	 * protolayer_iter_ctx::data` for pointer retrieval. */
	alignas(CPU_STRUCT_ALIGN) char layer_data[];
};

/** Allocates and initializes a new session with the specified protocol layer
 * group, and the provided transport context.
 *
 * `layer_param` is a pointer to an array of size `layer_param_count`. The
 * parameters are passed to the layer session initializers. The parameter array
 * is only required to be valid before this function returns. It is up to the
 * individual layer implementations to determine the lifetime of the data
 * pointed to by the parameters. */
struct session2 *session2_new(enum session2_transport_type transport_type,
                              enum kr_proto proto,
                              struct protolayer_data_param *layer_param,
                              size_t layer_param_count,
                              bool outgoing);

/** Allocates and initializes a new session with the specified protocol layer
 * group, using a *libuv handle* as its transport. */
static inline struct session2 *session2_new_io(uv_handle_t *handle,
                                               enum kr_proto layer_grp,
                                               struct protolayer_data_param *layer_param,
                                               size_t layer_param_count,
                                               bool outgoing)
{
	struct session2 *s = session2_new(SESSION2_TRANSPORT_IO, layer_grp,
			layer_param, layer_param_count, outgoing);
	s->transport.io.handle = handle;
	handle->data = s;
	s->ref_count++; /* Session owns the handle */
	return s;
}

/** Allocates and initializes a new session with the specified protocol layer
 * group, using a *parent session* as its transport. */
static inline struct session2 *session2_new_child(struct session2 *parent,
                                                  enum kr_proto layer_grp,
                                                  struct protolayer_data_param *layer_param,
                                                  size_t layer_param_count,
                                                  bool outgoing)
{
	struct session2 *s = session2_new(SESSION2_TRANSPORT_PARENT, layer_grp,
			layer_param, layer_param_count, outgoing);
	s->transport.parent = parent;
	return s;
}

/** Used when a libUV handle owned by the session is closed. Once all owned
 * handles are closed, the session is freed. */
void session2_unhandle(struct session2 *s);

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

/** Start the session timer. On timeout, the specified `event` is sent in the
 * `_UNWRAP` direction. Only a single timeout can be active at a time. */
int session2_timer_start(struct session2 *s, enum protolayer_event_type event,
                         uint64_t timeout, uint64_t repeat);

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

/** Penalizes the server the specified `session` is connected to, if the session
 * has not been useful (see `struct session2::was_useful`). Only applies to
 * `outgoing` sessions, and the session should not be connection-less. */
void session2_penalize(struct session2 *session);

/** Sends the specified `payload` to be processed in the `_UNWRAP` direction by
 * the session's protocol layers.
 *
 * The `comm` parameter may contain a pointer to comm data, e.g. for UDP, that
 * comm data shall contain a pointer to the sender's `struct sockaddr_*`. If
 * `comm` is `NULL`, session-wide data shall be used.
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
                    const struct comm_info *comm, protolayer_finished_cb cb,
                    void *baton);

/** Same as `session2_unwrap`, but looks up the specified `protocol` in the
 * session's assigned protocol group and sends the `payload` to the layer that
 * is next in the sequence in the `_UNWRAP` direction.
 *
 * Layers may use this to generate their own data to send in the sequence, e.g.
 * for protocol-specific ceremony. */
int session2_unwrap_after(struct session2 *s, enum protolayer_type protocol,
                          struct protolayer_payload payload,
                          const struct comm_info *comm,
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
                  const struct comm_info *comm, protolayer_finished_cb cb,
                  void *baton);

/** Same as `session2_wrap`, but looks up the specified `protocol` in the
 * session's assigned protocol group and sends the `payload` to the layer that
 * is next in the sequence in the `_WRAP` direction.
 *
 * Layers may use this to generate their own data to send in the sequence, e.g.
 * for protocol-specific ceremony. */
int session2_wrap_after(struct session2 *s, enum protolayer_type protocol,
                        struct protolayer_payload payload,
                        const struct comm_info *comm,
                        protolayer_finished_cb cb, void *baton);

/** Sends an event to be synchronously processed by the protocol layers of the
 * specified session. The layers are first iterated through in the `_UNWRAP`
 * direction, then bounced back in the `_WRAP` direction. */
void session2_event(struct session2 *s, enum protolayer_event_type event, void *baton);

/** Sends an event to be synchronously processed by the protocol layers of the
 * specified session, starting from the specified `protocol` in the `_UNWRAP`
 * direction. The layers are first iterated through in the `_UNWRAP` direction,
 * then bounced back in the `_WRAP` direction.
 *
 * NOTE: The bounced iteration does not exclude any layers - the layer
 * specified by `protocol` and those before it are only skipped in the
 * `_UNWRAP` direction! */
void session2_event_after(struct session2 *s, enum protolayer_type protocol,
                          enum protolayer_event_type event, void *baton);

/** Sends a `PROTOLAYER_EVENT_CLOSE` event to be processed by the protocol
 * layers of the specified session. This function exists for readability
 * reasons, to signal the intent that sending this event is used to actually
 * close the session. */
static inline void session2_close(struct session2 *s)
{
	session2_event(s, PROTOLAYER_EVENT_CLOSE, NULL);
}

/** Sends a `PROTOLAYER_EVENT_FORCE_CLOSE` event to be processed by the
 * protocol layers of the specified session. This function exists for
 * readability reasons, to signal the intent that sending this event is used to
 * actually close the session. */
static inline void session2_force_close(struct session2 *s)
{
	session2_event(s, PROTOLAYER_EVENT_FORCE_CLOSE, NULL);
}

/** Performs initial setup of the specified `req`, using the session's protocol
 * layers. Layers are processed in the `_UNWRAP` direction. */
void session2_init_request(struct session2 *s, struct kr_request *req);

/** Removes the specified request task from the session's tasklist. The session
 * must be outgoing. If the session is UDP, a signal to close is also sent to it. */
void session2_kill_ioreq(struct session2 *session, struct qr_task *task);

/** Update `last_activity` to the current timestamp. */
static inline void session2_touch(struct session2 *session)
{
	session->last_activity = kr_now();
}
