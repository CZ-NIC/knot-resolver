/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <math.h>
#include <stdatomic.h>
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

#define LOADS_THRESHOLDS        (uint16_t[])  {1<<4, 1<<8, 1<<12, -1}    // the last one should be UINT16_MAX
#define QUEUES_CNT              (sizeof(LOADS_THRESHOLDS) / sizeof(*LOADS_THRESHOLDS) + 1)  // +1 for unverified
#define PRIORITY_SYNC           (-1)              // no queue
#define PRIORITY_UDP            (QUEUES_CNT - 1)  // last queue

#define KRU_CAPACITY            (1<<19)  // same as ratelimiting default
#define MAX_DECAY               (KRU_LIMIT * 0.00013862)  // half-life: 5s
#define BASE_PRICE(nsec, cpus)  ((uint64_t)MAX_DECAY * 4 * nsec / 1000000ll / cpus)
	// max value reached when the single host uses 1/4 of all cpus' time;
	// instant limits in us are multiplied by cpus while rate limits in % of all cpus' time are not;
	//   see log written by defer_str_conf for details
	// TODO check that configuration makes sense (public resolvers vs home routers)
	//   laptop measurements:
	//     simple cached queries:
	//       TCP  0.5 ms
	//       DoT: 1.0 ms
	//       DoH: 2.5 ms
	//     uncached resolving: ~10 ms or more

#define REQ_TIMEOUT        1000000000 // ns (THREAD_CPUTIME), older deferred queries are dropped
#define IDLE_TIMEOUT          1000000 // ns (THREAD_CPUTIME); if exceeded, continue processing after next poll phase
#define PHASE_UDP_TIMEOUT      400000 // ns (THREAD_CPUTIME); switch between udp, non-udp phases
#define PHASE_NON_UDP_TIMEOUT  400000 // ns (THREAD_CPUTIME);    after timeout or emptying queue
#define MAX_WAITING_REQS_SIZE (64 * 1024 * 1024)  // bytes; if exceeded, some deferred requests are processed in poll phase
	// single TCP allocates more than 64KiB wire buffer
	// TODO check whether all important allocations are counted;
	//   different things are not counted: tasks and subsessions (not deferred after creation), uv handles, queues overhead, ...;
	//   payload is counted either as part of session wire buffer (for stream) or as part of iter ctx (for datagrams)

#define VERBOSE_LOG(...) kr_log_debug(DEFER, " | " __VA_ARGS__)

struct defer {
	size_t capacity;
	kru_price_t max_decay;
	uint32_t log_period;
	int cpus;
	bool using_avx2;
	_Atomic uint32_t log_time;
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

/// Print configuration into desc array.
void defer_str_conf(char *desc, int desc_len) {
	int len = 0;
#define append(...) len += snprintf(desc + len, desc_len > len ? desc_len - len : 0, __VA_ARGS__)
#define append_time(prefix, ms, suffix) { \
		if (ms < 1) append(prefix "%7.1f us" suffix, ms * 1000); \
		else if (ms < 1000) append(prefix "%7.1f ms" suffix, ms); \
		else append(prefix "%7.1f s " suffix, ms / 1000); }
	append(     "  Expected cpus/procs: %5d\n", defer->cpus);

	append(     "  Max waiting requests:%7.1f MiB\n", MAX_WAITING_REQS_SIZE / 1024.0 / 1024.0);
	append_time("  Request timeout:     ", REQ_TIMEOUT           / 1000000.0, "\n");
	append_time("  Idle:                ", IDLE_TIMEOUT          / 1000000.0, "\n");
	append_time("  UDP phase:           ", PHASE_UDP_TIMEOUT     / 1000000.0, "\n");
	append_time("  Non-UDP phase:       ", PHASE_NON_UDP_TIMEOUT / 1000000.0, "\n");
	append(     "  Priority levels:     %5ld + UDP\n", QUEUES_CNT - 1);

	append(     "  KRU capacity:        %7.1f k\n", KRU_CAPACITY / 1000.0);

	bool uniform_thresholds = true;
	for (int i = 1; i < QUEUES_CNT - 2; i++)
		uniform_thresholds &= (LOADS_THRESHOLDS[i] == LOADS_THRESHOLDS[i-1] * LOADS_THRESHOLDS[0]);
	uniform_thresholds &= ((1<<16) == (int)LOADS_THRESHOLDS[QUEUES_CNT - 3] * LOADS_THRESHOLDS[0]);

	append(     "  Max decay:             %7.3f %% per ms (32-bit: %d)\n",
			100.0 * MAX_DECAY / KRU_LIMIT, (kru_price_t)MAX_DECAY);
	float half_life = -1.0 / log2f(1.0 - MAX_DECAY / KRU_LIMIT);
	append_time("    Half-life:         ", half_life, "\n");
	if (uniform_thresholds)
		append_time("    Priority rise in:  ", half_life * 16 / (QUEUES_CNT - 1), "\n");
	append_time("    Counter reset in:  ", half_life * 16, "\n");

	append("  Rate limits for crossing priority levels as CPU utilization out of %d cores:\n",
			defer->cpus);

	uint8_t *const prefixes[] = {V4_PREFIXES, V6_PREFIXES};
	kru_price_t *const rate_mult[] = {V4_RATE_MULT, V6_RATE_MULT};
	const size_t prefixes_cnt[] = {V4_PREFIXES_CNT, V6_PREFIXES_CNT};
	const int version[] = {4, 6};

	append("%15s", "");
	for (int j = 0; j < 3; j++)
		append("%10d", j+1);
	append("%10s\n", "max");

	for (int v = 0; v < 2; v++) {
		for (int i = prefixes_cnt[v] - 1; i >= 0; i--) {
			append("%9sv%d/%-3d: ", "", version[v], prefixes[v][i]);
			for (int j = 0; j < QUEUES_CNT - 1; j++) {
				float needed_util = MAX_DECAY / (1<<16) * LOADS_THRESHOLDS[j] / BASE_PRICE(1000000, 1) * rate_mult[v][i];
				if (needed_util <= 1) {
					append("%8.3f %%", needed_util * 100);
				} else {
					append("%8s  ", "-");
				}
			}
			append("\n");
		}
	}

	append("  Instant limits for crossing priority levels as CPU time (depends on cpu count):\n");

	append("%15s", "");
	for (int j = 0; j < 3; j++)
		append("%10d", j+1);
	append("%10s\n", "max");

	for (int v = 0; v < 2; v++) {
		for (int i = prefixes_cnt[v] - 1; i >= 0; i--) {
			append("%9sv%d/%-3d:  ", "", version[v], prefixes[v][i]);
			for (int j = 0; j < QUEUES_CNT - 1; j++) {
				float needed_time = (float)KRU_LIMIT / (1<<16) * LOADS_THRESHOLDS[j] / BASE_PRICE(1000000, defer->cpus) * rate_mult[v][i];
				if (needed_time < 1) {
					append("%7.1f us", needed_time * 1000);
				} else if (needed_time < 1000) {
					append("%7.1f ms", needed_time);
				} else {
					append("%7.1f s ", needed_time / 1000);
				}
			}
			append("\n");
		}
	}
	append("    (values above max are indistinguishable)\n");

#undef append_time
#undef append
}


/// Increment KRU counters by given time.
void defer_charge(uint64_t nsec, union kr_sockaddr *addr, bool stream)
{
	if (phase_accounting) {
		phase_charge(nsec);
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

		// notice logging according to log-period
		const uint32_t time_now = kr_now();
		uint32_t log_time_orig = atomic_load_explicit(&defer->log_time, memory_order_relaxed);
		if (defer->log_period) {
			while (time_now - log_time_orig + 1024 >= defer->log_period + 1024) {
				if (atomic_compare_exchange_weak_explicit(&defer->log_time, &log_time_orig, time_now,
						memory_order_relaxed, memory_order_relaxed)) {
					kr_log_notice(DEFER, "Data from %s too long in queue, dropping.\n",
							kr_straddr(ctx->comm->src_addr));
					break;
				}
			}
		}

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
	phase_accounting = false;
	if (!defer || ctx->session->outgoing)
		return protolayer_continue(ctx);

	defer_sample_addr((const union kr_sockaddr *)ctx->comm->src_addr, ctx->session->stream);
	struct pl_defer_iter_data *idata = iter_data;
	struct pl_defer_sess_data *sdata = sess_data;
	idata->req_stamp = defer_sample_state.stamp;

	VERBOSE_LOG("  %s UNWRAP\n",
			kr_straddr(ctx->comm->src_addr));

	if (queue_len(sdata->queue) > 0) {  // stream with preceding packet already deferred
		queue_push(sdata->queue, ctx);
		waiting_requests_size += idata->size = protolayer_iter_size_est(ctx, false);
			// payload counted in session wire buffer
		VERBOSE_LOG("    PUSH as follow-up\n");
		return protolayer_async();
	}

	int priority = classify((const union kr_sockaddr *)ctx->comm->src_addr, ctx->session->stream);

	if (priority == PRIORITY_SYNC) {
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
	waiting_requests_size += idata->size = protolayer_iter_size_est(ctx, !ctx->session->stream);
		// for stream, payload is counted in session wire buffer

	if (waiting_requests_size > MAX_WAITING_REQS_SIZE) {
		defer_sample_state_t prev_sample_state;
		defer_sample_start(&prev_sample_state);
		phase_accounting = true;
		do {
			process_single_deferred();  // possibly defers again without decreasing waiting_requests_size
				// If the unwrapped query is to be processed here,
				// it is the last iteration and the query is processed after returning.
			defer_sample_restart();
		} while (waiting_requests_size > MAX_WAITING_REQS_SIZE);
		phase_accounting = false;
		defer_sample_stop(&prev_sample_state, true);
	}

	return protolayer_async();
}

/// Unwrap event: EOF event may be deferred here, other events pass synchronously.
static enum protolayer_event_cb_result pl_defer_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
	if ((event == PROTOLAYER_EVENT_EOF) || (event == PROTOLAYER_EVENT_GENERAL_TIMEOUT)) {
		// disable accounting only for events that cannot occur during incoming data processing
		phase_accounting = false;
	}
	if (!defer || !session->stream || session->outgoing)
		return PROTOLAYER_EVENT_PROPAGATE;

	defer_sample_addr((const union kr_sockaddr *)session->comm_storage.src_addr, session->stream);

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
	phase_accounting = true;
	do {
		process_single_deferred();
		defer_sample_restart();
	} while ((waiting_requests > 0) && (defer_sample_state.stamp < idle_stamp + IDLE_TIMEOUT));
	phase_accounting = false;
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
int defer_init(const char *mmap_file, uint32_t log_period, int cpus)
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
		.log_period = log_period,
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
			sizeof(header.log_period) +
			sizeof(header.cpus),
		"detected padding with undefined data inside mmapped header");

	ret = mmapped_init(&defer_mmapped, mmap_file, size, &header, header_size);
	if (ret == MMAPPED_WAS_FIRST) {
		kr_log_info(DEFER, "Initializing defer...\n");

		defer = defer_mmapped.mem;

		bool succ = KRU.initialize((struct kru *)defer->kru, capacity_log, header.max_decay);
		if (!succ) {
			defer = NULL;
			ret = kr_error(EINVAL);
			goto fail;
		}

		defer->log_time = kr_now() - log_period;

		ret = mmapped_init_continue(&defer_mmapped);
		if (ret != 0) goto fail;

		kr_log_info(DEFER, "Defer initialized (%s).\n", (defer->using_avx2 ? "AVX2" : "generic"));

		// log current configuration
		if (KR_LOG_LEVEL_IS(LOG_INFO) || kr_log_group_is_set(LOG_GRP_DEFER)) {
			char desc[8000];
			defer_str_conf(desc, sizeof(desc));
			kr_log_info(DEFER, "Defer configuration:\n%s", desc);
		}
	} else if (ret == 0) {
		defer = defer_mmapped.mem;
		kr_log_info(DEFER, "Using existing defer data (%s).\n", (defer->using_avx2 ? "AVX2" : "generic"));
	} else goto fail;

	for (size_t i = 0; i < QUEUES_CNT; i++)
		queue_init(queues[i]);

	return 0;

fail:

	kr_log_crit(DEFER, "Initialization of shared defer data failed.\n");
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
