/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/defer.h"
#include "daemon/session2.h"
#include "daemon/udp_queue.h"
#include "lib/kru.h"
#include "lib/mmapped.h"
#include "lib/utils.h"

#define V4_PREFIXES  (uint8_t[])       {  18,  20, 24, 32 }
#define V4_RATE_MULT (kru_price_t[])   { 768, 256, 32,  1 }

#define V6_PREFIXES  (uint8_t[])       { 32, 48, 56, 64, 128 }
#define V6_RATE_MULT (kru_price_t[])   { 64,  4,  3,  2,   1 }

#define V4_PREFIXES_CNT (sizeof(V4_PREFIXES) / sizeof(*V4_PREFIXES))
#define V6_PREFIXES_CNT (sizeof(V6_PREFIXES) / sizeof(*V6_PREFIXES))
#define MAX_PREFIXES_CNT ((V4_PREFIXES_CNT > V6_PREFIXES_CNT) ? V4_PREFIXES_CNT : V6_PREFIXES_CNT)

#define LOADS_THRESHOLDS        (uint16_t[])  {1<<4, 1<<8, 1<<11, -1}    // the last one should be UINT16_MAX
#define QUEUES_CNT              (sizeof(LOADS_THRESHOLDS) / sizeof(*LOADS_THRESHOLDS) + 1)  // +1 for unverified
#define PRIORITY_SYNC           (-1)              // no queue
#define PRIORITY_UDP            (QUEUES_CNT - 1)  // last queue

#define KRU_CAPACITY            (1<<19)
	// same as ratelimiting default
#define MAX_DECAY               (KRU_LIMIT * 0.0006929)
	// halving counters in 1s
	//   5s from max  to 2^11   (priority 3)    // TODO change 2^11 to 2^12 to make the times equal?
	//   3s from 2^11 to 2^8    (priority 2)
	//   4s from 2^8  to 2^4    (priority 1)
	//   4s from 2^4  to zero   (priority 0)
#define BASE_PRICE(nsec, cpus)  ((uint64_t)MAX_DECAY * 10 * nsec / 1000000ll / cpus)
	// max value when the single host uses 1/10 of all cpus' time;
	// needed cpu utilization (rate limit) for other thresholds and prefixes:
	//           single      v6/48      v4/24      v6/32      v4/20      v4/18
	//   max:    10.000 %    40.00 %        -          -          -          -
	//   2^11:    0.312 %     1.25 %    10.00 %    20.00 %    80.00 %        -     (priority 3)
	//   2^8:     0.039 %     0.16 %     1.25 %     2.50 %    10.00 %    30.00 %   (priority 2)
	//   2^4:     0.002 %     0.01 %     0.08 %     0.16 %     0.63 %     1.87 %   (priority 1)
	// instant limit for single host and 1 cpu: (greater for larger networks and for more cpus)
	//   35 us for 2^4,  0.56 ms for 2^8,  4.5 ms for 2^11,  144 ms max value
	//   TODO adjust somehow
	//     simple DoT query may cost 1 ms, DoH 2.5 ms; it gets priority 2 during handshake (on laptop);
	//     the instant limits can be doubled by:
	//       doubling half-life (approx.),
	//       doubling percents in the previous table, or
	//       doubling number of cpus
	//     possible solution:
	//       half-life 5s, BASE_PRICE /= 2.5 -> for 4 cpus 1.75 ms fits below 2^4;
	//       still not enough for home routers -> TODO make something configurable, maybe the BASE_PRICE multiplier

#define REQ_TIMEOUT           5000000 // ns (THREAD_CPUTIME), older deferred queries are dropped
#define IDLE_TIMEOUT          1000000 // ns (THREAD_CPUTIME); if exceeded, continue processing after next poll phase
#define PHASE_UDP_TIMEOUT      400000 // ns (THREAD_CPUTIME); switch between udp, non-udp phases
#define PHASE_NON_UDP_TIMEOUT  400000 // ns (THREAD_CPUTIME);    after timeout or emptying queue
#define MAX_WAITING_REQS_SIZE (64 * 1024 * 1024)  // bytes; if exceeded, some deferred requests are processed in poll phase
	// single TCP allocates more than 64KiB wire buffer
	// TODO check whether all important allocations are counted;
	//   different things are not counted: tasks and subsessions (not deferred after created), uv handles, queues overhead, ...;
	//   payload is counted either as part of session wire buffer (for stream) or as part of iter ctx (for datagrams)

#define VERBOSE_LOG(...) kr_log_debug(DEFER, " | " __VA_ARGS__)

struct defer {
	size_t capacity;
	kru_price_t max_decay;
	int cpus;
	bool using_avx2;
	_Alignas(64) uint8_t kru[];
};
struct defer *defer = NULL;
bool defer_initialized = false;
struct mmapped defer_mmapped = {0};

defer_sample_state_t defer_sample_state = {
	.is_accounting = 0,
};

uv_idle_t idle_handle;
static void defer_queues_idle(uv_idle_t *handle);

protolayer_iter_ctx_queue_t queues[QUEUES_CNT];
int waiting_requests = 0;
ptrdiff_t waiting_requests_size = 0;  // signed for non-negativeness asserts
int queue_ix = QUEUES_CNT;  // MIN( last popped queue, first non-empty queue )

enum phase {
	PHASE_UDP      = 1,
	PHASE_NON_UDP  = 2,
	PHASE_ANY      = PHASE_UDP | PHASE_NON_UDP
} phase = PHASE_ANY;
uint64_t phase_elapsed = 0;    // ns
bool phase_accounting = false; // add accounted time to phase_elapsed on next call of defer_account

static inline void phase_set(enum phase p)
{
	if (phase != p) {
		phase_elapsed = 0;
		phase = p;
	}
}
static inline void phase_charge(uint64_t nsec)
{
	kr_assert(phase != PHASE_ANY);
	phase_elapsed += nsec;
	if ((phase == PHASE_UDP) && (phase_elapsed > PHASE_UDP_TIMEOUT)) {
		phase_set(PHASE_NON_UDP);
	} else if ((phase == PHASE_NON_UDP) && (phase_elapsed > PHASE_NON_UDP_TIMEOUT)) {
		phase_set(PHASE_UDP);
	}
}

struct pl_defer_sess_data {
	struct protolayer_data h;
	protolayer_iter_ctx_queue_t queue;  // properly ordered sequence of deferred packets, for stream only
		// the first ctx in the queue is also in a defer queue
	size_t size;
};

struct pl_defer_iter_data {
	struct protolayer_data h;
	uint64_t req_stamp;   // time when request was received, uses get_stamp()
	size_t size;
};

/// Return whether we're using optimized variant right now.
static bool using_avx2(void)
{
	bool result = (KRU.initialize == KRU_AVX2.initialize);
	kr_require(result || KRU.initialize == KRU_GENERIC.initialize);
	return result;
}

/// Increment KRU counters by given time.
void defer_charge(uint64_t nsec, union kr_sockaddr *addr, bool stream)
{
	if (phase_accounting) {
		phase_charge(nsec);
		phase_accounting = false;
	}

	if (!stream) return;  // UDP is not accounted in KRU

	_Alignas(16) uint8_t key[16] = {0, };
	uint16_t max_load = 0;
	uint8_t prefix = 0;
	kru_price_t base_price = BASE_PRICE(nsec, defer->cpus);

	if (addr->ip.sa_family == AF_INET6) {
		memcpy(key, &addr->ip6.sin6_addr, 16);

		kru_price_t prices[V6_PREFIXES_CNT];
		for (size_t i = 0; i < V6_PREFIXES_CNT; i++) {
			prices[i] = base_price / V6_RATE_MULT[i];
		}

		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, kr_now(),
				1, key, V6_PREFIXES, prices, V6_PREFIXES_CNT, &prefix);
	} else if (addr->ip.sa_family == AF_INET) {
		memcpy(key, &addr->ip4.sin_addr, 4);

		kru_price_t prices[V4_PREFIXES_CNT];
		for (size_t i = 0; i < V4_PREFIXES_CNT; i++) {
			prices[i] = base_price / V4_RATE_MULT[i];
		}

		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, kr_now(),
				0, key, V4_PREFIXES, prices, V4_PREFIXES_CNT, &prefix);
	} else {
		return;
	}

	VERBOSE_LOG("  %s ADD %4.3f ms -> load: %d on /%d\n",
			kr_straddr(&addr->ip), nsec / 1000000.0, max_load, prefix);
}

/// Determine priority of the request in [-1, QUEUES_CNT - 1].
/// Lower value has higher priority, -1 should be synchronous.
/// Both UDP and non-UDP may end up with synchronous priority
/// if the phase is active and no requests can be scheduled before them.
static inline int classify(const union kr_sockaddr *addr, bool stream)
{
	if (!stream) { // UDP
		VERBOSE_LOG("    unverified address\n");
		if ((phase & PHASE_UDP) && (queue_len(queues[PRIORITY_UDP]) == 0)) {
			phase_set(PHASE_UDP);
			return PRIORITY_SYNC;
		}
		return PRIORITY_UDP;
	}

	_Alignas(16) uint8_t key[16] = {0, };
	uint16_t max_load = 0;
	uint8_t prefix = 0;
	if (addr->ip.sa_family == AF_INET6) {
		memcpy(key, &addr->ip6.sin6_addr, 16);
		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, kr_now(),
				1, key, V6_PREFIXES, NULL, V6_PREFIXES_CNT, &prefix);
	} else if (addr->ip.sa_family == AF_INET) {
		memcpy(key, &addr->ip4.sin_addr, 4);
		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, kr_now(),
				0, key, V4_PREFIXES, NULL, V4_PREFIXES_CNT, &prefix);
	}

	int priority = 0;
	for (; LOADS_THRESHOLDS[priority] < max_load; priority++);

	VERBOSE_LOG("    load %d on /%d\n", max_load, prefix);

	if ((phase & PHASE_NON_UDP) && (priority == 0) && (queue_len(queues[0]) == 0)) {
		phase_set(PHASE_NON_UDP);
		return PRIORITY_SYNC;
	}
	return priority;
}



/// Push query to a queue according to its priority and activate idle.
static inline void push_query(struct protolayer_iter_ctx *ctx, int priority, bool to_head_end)
{
	if (to_head_end) {
		queue_push_head(queues[priority], ctx);
	} else {
		queue_push(queues[priority], ctx);
	}
	queue_ix = MIN(queue_ix, priority);
	if (waiting_requests++ <= 0) {
		kr_assert(waiting_requests == 1);
		uv_idle_start(&idle_handle, defer_queues_idle);
		VERBOSE_LOG("  activating idle\n");
	}
}

/// Pop and return query from the specified queue, deactivate idle if not needed.
static inline struct protolayer_iter_ctx *pop_query_queue(int priority)
{
	kr_assert(queue_len(queues[priority]) > 0);
	struct protolayer_iter_ctx *ctx = queue_head(queues[priority]);
	queue_pop(queues[priority]);
	if (--waiting_requests <= 0) {
		kr_assert(waiting_requests == 0);
		uv_idle_stop(&idle_handle);
		VERBOSE_LOG("  deactivating idle\n");
	}
	return ctx;
}


/// Pop and return the query with the highest priority, UDP or non-UDP based on current phase,
/// deactivate idle if not needed.
static inline struct protolayer_iter_ctx *pop_query(void)
{
	const int waiting_udp = queue_len(queues[PRIORITY_UDP]);
	const int waiting_non_udp = waiting_requests - waiting_udp;

	enum phase new_phase;
	if ((phase & PHASE_NON_UDP) && (waiting_non_udp > 0)) {
		new_phase = PHASE_NON_UDP;  // maybe changing from PHASE_ANY
	} else if ((phase & PHASE_UDP) && (waiting_udp > 0)) {
		new_phase = PHASE_UDP;      // maybe changing from PHASE_ANY
	} else if (waiting_non_udp > 0) {
		new_phase = PHASE_NON_UDP;  // change from PHASE_UDP, no UDP queries
	} else {
		new_phase = PHASE_UDP;      // change from PHASE_NON_UDP, no non-UDP queries
	}
	phase_set(new_phase);

	int i;
	if (phase == PHASE_NON_UDP) {
		for (; queue_ix < QUEUES_CNT && queue_len(queues[queue_ix]) == 0; queue_ix++);
		if (queue_ix >= PRIORITY_UDP) kr_assert(false);
		i = queue_ix;
	} else {
		i = PRIORITY_UDP;
	}

	return pop_query_queue(i);
}


// Break the given query; for streams break also all follow-up queries and force-close the stream.
static inline void break_query(struct protolayer_iter_ctx *ctx, int err)
{
	if (ctx->session->stream) {
		struct session2 *s = ctx->session;
		struct pl_defer_sess_data *sdata = protolayer_sess_data_get_current(ctx);
		s->ref_count++; // keep session and sdata alive for a while
		waiting_requests_size -= sdata->size;
		if (!ctx->session->closing) {
			session2_force_close(ctx->session);
		}
		kr_assert(ctx == queue_head(sdata->queue));
		while (true) {
			queue_pop(sdata->queue);
			if (ctx) {
				struct pl_defer_iter_data *idata = protolayer_iter_data_get_current(ctx);
				waiting_requests_size -= idata->size;
				protolayer_break(ctx, kr_error(err));
			}
			if (queue_len(sdata->queue) == 0) break;
			ctx = queue_head(sdata->queue);
		}
		session2_unhandle(s); // decrease ref_count
	} else {
		struct pl_defer_iter_data *idata = protolayer_iter_data_get_current(ctx);
		waiting_requests_size -= idata->size;
		protolayer_break(ctx, kr_error(err));
	}
	kr_assert(waiting_requests ? waiting_requests_size > 0 : waiting_requests_size == 0);
}

/// Process a single deferred query (or defer again) if there is any.
/// Time accounting should have been just started, the stamp is used, accounted address is set.
static inline void process_single_deferred(void)
{
	struct protolayer_iter_ctx *ctx = pop_query();
	if (kr_fails_assert(ctx)) return;

	defer_sample_addr((const union kr_sockaddr *)ctx->comm->src_addr, ctx->session->stream);
	phase_accounting = true;  // TODO check there are no suspensions of sampling

	struct pl_defer_iter_data *idata = protolayer_iter_data_get_current(ctx);
	struct pl_defer_sess_data *sdata = protolayer_sess_data_get_current(ctx);
	struct session2 *session = ctx->session;
	uint64_t age_ns = defer_sample_state.stamp - idata->req_stamp;

	VERBOSE_LOG("  %s POP from %d after %4.3f ms\n",
			kr_straddr(ctx->comm->src_addr),
			queue_ix,
			age_ns / 1000000.0);

	if (ctx->session->closing) {
		VERBOSE_LOG("    BREAK (session is closing)\n");
		break_query(ctx, ECANCELED);
		return;
	}

	if (age_ns >= REQ_TIMEOUT) {
		VERBOSE_LOG("    BREAK (timeout)\n");
		break_query(ctx, ETIME);
		return;
	}

	int priority = classify((const union kr_sockaddr *)ctx->comm->src_addr, ctx->session->stream);
	if (priority > queue_ix) {  // priority dropped (got higher value)
		VERBOSE_LOG("    PUSH to %d\n", priority);
		push_query(ctx, priority, false);
		return;
	}

	bool eof = false;
	if (ctx->session->stream) {
		kr_assert(queue_head(sdata->queue) == ctx);
		queue_pop(sdata->queue);
		while ((queue_len(sdata->queue) > 0) && (queue_head(sdata->queue) == NULL)) { // EOF event
			eof = true;
			queue_pop(sdata->queue);
		}
		if (queue_len(sdata->queue) > 0) {
			VERBOSE_LOG("    PUSH follow-up to head of %d\n", priority);
			push_query(queue_head(sdata->queue), priority, true);
		} else {
			waiting_requests_size -= sdata->size;
		}
	}

	waiting_requests_size -= idata->size;
	kr_assert(waiting_requests ? waiting_requests_size > 0 : waiting_requests_size == 0);

	if (eof) {
		// Keep session alive even if it is somehow force-closed during continuation.
		// TODO Is it possible?
		session->ref_count++;
	}

	VERBOSE_LOG("    CONTINUE\n");
	protolayer_continue(ctx);

	if (eof) {
		VERBOSE_LOG("    CONTINUE EOF event\n");
		session2_event_after(session, PROTOLAYER_TYPE_DEFER, PROTOLAYER_EVENT_EOF, NULL);
		session2_unhandle(session); // decrease ref_count
	}
}

/// Break expired requests at the beginning of queues, uses current stamp.
static inline void cleanup_queues(void)
{
	for (int i = 0; i < QUEUES_CNT; i++) {
		int cnt = 0;
		while (queue_len(queues[i]) > 0) {
			struct protolayer_iter_ctx *ctx = queue_head(queues[i]);
			struct pl_defer_iter_data *idata = protolayer_iter_data_get_current(ctx);
			uint64_t age_ns = defer_sample_state.stamp - idata->req_stamp;
			if (age_ns < REQ_TIMEOUT) break;
			pop_query_queue(i);
			break_query(ctx, ETIME);
			cnt++;
		}
		if (cnt > 0) {
			VERBOSE_LOG("  BREAK %d queries from %d\n", cnt, i);
		}
	}
}

/// Unwrap: defer or process the query synchronously.
/// Time accounting should have been started, the stamp is used, accounted address is set.
static enum protolayer_iter_cb_result pl_defer_unwrap(
		void *sess_data, void *iter_data,
		struct protolayer_iter_ctx *ctx)
{
	if (!defer || ctx->session->outgoing)
		return protolayer_continue(ctx);

	defer_sample_addr((const union kr_sockaddr *)ctx->comm->src_addr, ctx->session->stream);
	struct pl_defer_iter_data *data = iter_data;
	struct pl_defer_sess_data *sdata = sess_data;
	data->req_stamp = defer_sample_state.stamp;

	VERBOSE_LOG("  %s UNWRAP\n",
			kr_straddr(ctx->comm->src_addr));

	if (queue_len(sdata->queue) > 0) {  // stream with preceding packet already deferred
		queue_push(sdata->queue, ctx);
		waiting_requests_size += data->size = protolayer_iter_size_est(ctx, false);
			// payload counted in session wire buffer
		VERBOSE_LOG("    PUSH as follow-up\n");
		return protolayer_async();
	}

	int priority = classify((const union kr_sockaddr *)ctx->comm->src_addr, ctx->session->stream);

	if (priority == -1) {
		VERBOSE_LOG("    CONTINUE\n");
		phase_accounting = true;
		return protolayer_continue(ctx);
	}

	VERBOSE_LOG("    PUSH to %d\n", priority);
	if (ctx->session->stream) {
		queue_push(sdata->queue, ctx);
		waiting_requests_size += sdata->size = protolayer_sess_size_est(ctx->session);
	}
	push_query(ctx, priority, false);
	waiting_requests_size += data->size = protolayer_iter_size_est(ctx, !ctx->session->stream);
		// for stream, payload is counted in session wire buffer

	if (waiting_requests_size > MAX_WAITING_REQS_SIZE) {
		defer_sample_state_t prev_sample_state;
		defer_sample_start(&prev_sample_state);
		do {
			process_single_deferred();  // possibly defers again without decreasing waiting_requests_size
			defer_sample_restart();
		} while (waiting_requests_size > MAX_WAITING_REQS_SIZE);
		defer_sample_stop(&prev_sample_state, true);
	}

	return protolayer_async();
}

/// Unwrap event: EOF event may be deferred here, other events pass synchronously.
static enum protolayer_event_cb_result pl_defer_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if (!defer || session->outgoing)
		return PROTOLAYER_EVENT_PROPAGATE;

	struct pl_defer_sess_data *sdata = sess_data;
	if ((event == PROTOLAYER_EVENT_EOF) && (queue_len(sdata->queue) > 0)) {
		// defer EOF event if unprocessed data remain, baton is dropped if any
		queue_push(sdata->queue, NULL);
		VERBOSE_LOG("  %s event %s deferred\n",
				session->comm_storage.src_addr ? kr_straddr(session->comm_storage.src_addr) : "(null)",
				protolayer_event_name(event));
		return PROTOLAYER_EVENT_CONSUME;
	}

	VERBOSE_LOG("  %s event %s passes through synchronously%s%s\n",
			session->comm_storage.src_addr ? kr_straddr(session->comm_storage.src_addr) : "(null)",
			protolayer_event_name(event),
			queue_len(sdata->queue) > 0 ? " ahead of deferred data" : "",
			*baton ? " (with baton)" : "");
	return PROTOLAYER_EVENT_PROPAGATE;
}

/// Idle: continue processing deferred requests.
static void defer_queues_idle(uv_idle_t *handle)
{
	kr_assert(waiting_requests > 0);
	VERBOSE_LOG("IDLE\n");
	VERBOSE_LOG("  %d waiting\n", waiting_requests);
	defer_sample_start(NULL);
	uint64_t idle_stamp = defer_sample_state.stamp;
	do {
		process_single_deferred();
		defer_sample_restart();
	} while ((waiting_requests > 0) && (defer_sample_state.stamp < idle_stamp + IDLE_TIMEOUT));
	defer_sample_stop(NULL, true);
	cleanup_queues();
	udp_queue_send_all();

	if (waiting_requests > 0) {
		VERBOSE_LOG("  %d waiting\n", waiting_requests);
	} else {
		phase_set(PHASE_ANY);
	}
	VERBOSE_LOG("POLL\n");
}


/// Initialize shared memory, queues. To be called from Lua.
int defer_init(const char *mmap_file, int cpus)
{
	defer_initialized = true;
	if (mmap_file == NULL) {
		// defer explicitly disabled
		return 0;
	}

	int ret = 0;
	if (cpus < 1) {
		ret = EINVAL;
		goto fail;
	}

	struct defer header = {
		.capacity = KRU_CAPACITY,
		.max_decay = MAX_DECAY,
		.cpus = cpus,
		.using_avx2 = using_avx2(),
	};

	size_t capacity_log = 0;
	for (size_t c = header.capacity - 1; c > 0; c >>= 1) capacity_log++;

	size_t size = offsetof(struct defer, kru) + KRU.get_size(capacity_log);
	size_t header_size = offsetof(struct defer, using_avx2) + sizeof(header.using_avx2);
	static_assert(  // no padding up to .using_avx2
		offsetof(struct defer, using_avx2) ==
			sizeof(header.capacity) +
			sizeof(header.max_decay) +
			sizeof(header.cpus),
		"detected padding with undefined data inside mmapped header");

	ret = mmapped_init(&defer_mmapped, mmap_file, size, &header, header_size);
	if (ret == MMAPPED_WAS_FIRST) {
		kr_log_info(SYSTEM, "Initializing prioritization...\n");

		defer = defer_mmapped.mem;

		bool succ = KRU.initialize((struct kru *)defer->kru, capacity_log, header.max_decay);
		if (!succ) {
			defer = NULL;
			ret = kr_error(EINVAL);
			goto fail;
		}

		ret = mmapped_init_continue(&defer_mmapped);
		if (ret != 0) goto fail;

		kr_log_info(SYSTEM, "Prioritization initialized (%s).\n", (defer->using_avx2 ? "AVX2" : "generic"));
	} else if (ret == 0) {
		defer = defer_mmapped.mem;
		kr_log_info(SYSTEM, "Using existing prioritization data (%s).\n", (defer->using_avx2 ? "AVX2" : "generic"));
	} else goto fail;

	for (size_t i = 0; i < QUEUES_CNT; i++)
		queue_init(queues[i]);

	return 0;

fail:

	kr_log_crit(SYSTEM, "Initialization of shared prioritization data failed.\n");
	return ret;
}

/// Initialize idle.
int defer_init_idle(uv_loop_t *loop)
{
	return uv_idle_init(loop, &idle_handle);
}

/// Initialize session queue
int pl_defer_sess_init(struct session2 *session, void *data, void *param)
{
	struct pl_defer_sess_data *sdata = data;
	queue_init(sdata->queue);
	return 0;
}

/// Deinitialize shared memory.
void defer_deinit(void)
{
	mmapped_deinit(&defer_mmapped);
	defer = NULL;
}

/// Initialize protolayer.
__attribute__((constructor))
static void defer_protolayers_init(void)
{
	protolayer_globals[PROTOLAYER_TYPE_DEFER] = (struct protolayer_globals){
		.iter_size = sizeof(struct pl_defer_iter_data),
		.sess_size = sizeof(struct pl_defer_sess_data),
		.sess_init = pl_defer_sess_init,
		.unwrap = pl_defer_unwrap,
		.event_unwrap = pl_defer_event_unwrap,
	};
}
