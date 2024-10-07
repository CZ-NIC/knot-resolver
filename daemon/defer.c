#include <stdatomic.h>
#include "daemon/defer.h"
#include "daemon/mmapped.h"
#include "daemon/session2.h"
#include "daemon/udp_queue.h"
#include "lib/kru.h"
#include "lib/utils.h"

#define V4_PREFIXES  (uint8_t[])       {  18,  20, 24, 32 }
#define V4_RATE_MULT (kru_price_t[])   { 768, 256, 32,  1 }

#define V6_PREFIXES  (uint8_t[])       { 32, 48, 56, 64, 128 }
#define V6_RATE_MULT (kru_price_t[])   { 64,  4,  3,  2,   1 }

#define V4_PREFIXES_CNT (sizeof(V4_PREFIXES) / sizeof(*V4_PREFIXES))
#define V6_PREFIXES_CNT (sizeof(V6_PREFIXES) / sizeof(*V6_PREFIXES))
#define MAX_PREFIXES_CNT ((V4_PREFIXES_CNT > V6_PREFIXES_CNT) ? V4_PREFIXES_CNT : V6_PREFIXES_CNT)

#define LOADS_THRESHOLDS     (uint16_t[])  {1<<4, 1<<8, 1<<11, -1}    // the last one should be UINT16_MAX
#define QUEUES_CNT           (sizeof(LOADS_THRESHOLDS) / sizeof(*LOADS_THRESHOLDS) + 1)  // +1 for unverified
#define PRIORITY_SYNC        (-1)              // no queue
#define PRIORITY_UDP         (QUEUES_CNT - 1)  // last queue

#define KRU_CAPACITY         (1<<10)
#define MAX_DECAY            (KRU_LIMIT * 0.0006929)  // -> halving counters in 1s of accounted time
#define BASE_PRICE(nsec)     ((uint64_t)MAX_DECAY * nsec / 1000000ll)
// TODO reconsider time flow speed in KRU (currently sum of all-processes accounted time)

#define REQ_TIMEOUT           5000000 // ns (THREAD_CPUTIME), older deferred queries are dropped
#define IDLE_TIMEOUT          1000000 // ns (THREAD_CPUTIME); if exceeded, continue processing after next poll phase
#define PHASE_UDP_TIMEOUT      400000 // ns (THREAD_CPUTIME); switch between udp, non-udp phases
#define PHASE_NON_UDP_TIMEOUT  400000 // ns (THREAD_CPUTIME);    after timeout or emptying queue
#define MAX_WAITING_REQS        10000 // if exceeded, process single deferred request immediatelly in poll phase

#define VERBOSE_LOG(...) kr_log_debug(DEFER, " | " __VA_ARGS__)

struct defer {
	size_t capacity;
	kru_price_t max_decay;
	bool using_avx2;
	_Atomic uint32_t time_now;  // shared counter incremented each msec by each process, used for kru decay only
	_Alignas(64) uint8_t kru[];
};
struct defer *defer = NULL;
struct mmapped defer_mmapped = {0};
uint64_t kru_time_now_nsec = 0;  // total time contribution of the current process

defer_sample_state_t defer_sample_state = {
	.is_accounting = 0,
};

uv_idle_t idle_handle;
static void defer_queues_idle(uv_idle_t *handle);

protolayer_iter_ctx_queue_t queues[QUEUES_CNT];
int waiting_requests = 0;
int queue_ix = QUEUES_CNT;  // MIN( last popped queue, first non-empty queue )

enum phase {
	PHASE_UDP      = 1,
	PHASE_NON_UDP  = 2,
	PHASE_ANY      = PHASE_UDP | PHASE_NON_UDP
} phase = PHASE_ANY;
uint64_t phase_elapsed = 0;    // ns
bool phase_accounting = false; // add accounted time to phase_elapsed on next call of defer_account

static inline void phase_set(enum phase p) {
	if (phase != p) {
		phase_elapsed = 0;
		phase = p;
	}
}
static inline void phase_account(uint64_t nsec) {
	kr_assert(phase != PHASE_ANY);
	phase_elapsed += nsec;
	if ((phase == PHASE_UDP) && (phase_elapsed > PHASE_UDP_TIMEOUT)) {
		phase_set(PHASE_NON_UDP);
	} else if ((phase == PHASE_NON_UDP) && (phase_elapsed > PHASE_NON_UDP_TIMEOUT)) {
		phase_set(PHASE_UDP);
	}
}

struct pl_defer_iter_data {
	struct protolayer_data h;
	uint64_t req_stamp;   // time when request was received, uses get_stamp()
		// TODO use different clock than CLOCK_THREAD_CPUTIME_ID?
};

/// Return whether we're using optimized variant right now.
static bool using_avx2(void)
{
	bool result = (KRU.initialize == KRU_AVX2.initialize);
	kr_require(result || KRU.initialize == KRU_GENERIC.initialize);
	return result;
}

/// Increment KRU counters by given time.
void defer_account(uint64_t nsec, union kr_sockaddr *addr, bool stream) {
	if (phase_accounting) {
		phase_account(nsec);
		phase_accounting = false;
	}

	if (!stream) return;  // UDP is not accounted in KRU

	_Alignas(16) uint8_t key[16] = {0, };
	uint16_t max_load = 0;
	uint8_t prefix = 0;
	kru_price_t base_price = BASE_PRICE(nsec);

	uint32_t time_now;
	uint32_t time_now_incr = (kru_time_now_nsec + nsec) / 1000000 - kru_time_now_nsec / 1000000;
	if (time_now_incr > 0) {
		time_now = atomic_fetch_add_explicit(&defer->time_now, time_now_incr, memory_order_relaxed) + time_now_incr;
	} else {
		time_now = atomic_load_explicit(&defer->time_now, memory_order_relaxed);
	}
	kru_time_now_nsec += nsec;

	if (addr->ip.sa_family == AF_INET6) {
		memcpy(key, &addr->ip6.sin6_addr, 16);

		kru_price_t prices[V6_PREFIXES_CNT];
		for (size_t i = 0; i < V6_PREFIXES_CNT; i++) {
			prices[i] = base_price / V6_RATE_MULT[i];
		}

		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, time_now,
				1, key, V6_PREFIXES, prices, V6_PREFIXES_CNT, &prefix);
	} else if (addr->ip.sa_family == AF_INET) {
		memcpy(key, &addr->ip4.sin_addr, 4);

		kru_price_t prices[V4_PREFIXES_CNT];
		for (size_t i = 0; i < V4_PREFIXES_CNT; i++) {
			prices[i] = base_price / V4_RATE_MULT[i];
		}

		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, time_now,
				0, key, V4_PREFIXES, prices, V4_PREFIXES_CNT, &prefix);
	} else {
		return;
	}

	VERBOSE_LOG("  %s ADD %4.3f ms -> load: %d on /%d  (kru time: %d)\n",
			kr_straddr(&defer_sample_state.addr.ip), nsec / 1000000.0, max_load, prefix, time_now);
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

	uint32_t time_now = atomic_load_explicit(&defer->time_now, memory_order_relaxed);
	_Alignas(16) uint8_t key[16] = {0, };
	uint16_t max_load = 0;
	uint8_t prefix = 0;
	if (addr->ip.sa_family == AF_INET6) {
		memcpy(key, &addr->ip6.sin6_addr, 16);
		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, time_now,
				1, key, V6_PREFIXES, NULL, V6_PREFIXES_CNT, &prefix);
	} else if (addr->ip.sa_family == AF_INET) {
		memcpy(key, &addr->ip4.sin_addr, 4);
		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, time_now,
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
static inline void push_query(struct protolayer_iter_ctx *ctx, int priority)
{
	queue_push(queues[priority], ctx);
	queue_ix = MIN(queue_ix, priority);
	if (waiting_requests++ <= 0) {
		kr_assert(waiting_requests == 1);
		uv_idle_start(&idle_handle, defer_queues_idle);
		VERBOSE_LOG("  activating idle\n");
	}
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

	struct protolayer_iter_ctx *ctx = queue_head(queues[i]);
	queue_pop(queues[i]);
	if (--waiting_requests <= 0) {
		kr_assert(waiting_requests == 0);
		uv_idle_stop(&idle_handle);
		VERBOSE_LOG("  deactivating idle\n");
	}
	return ctx;
}


/// Process a single deferred query (or defer again) if there is any.
/// Time accounting should have been just started, the stamp is used, accounted address is set.
static inline void process_single_deferred(void) {
	struct protolayer_iter_ctx *ctx = pop_query();
	if (ctx == NULL) return;

	defer_sample_addr((const union kr_sockaddr *)ctx->comm->comm_addr, ctx->session->stream);
	phase_accounting = true;

	struct pl_defer_iter_data *iter_data = protolayer_iter_data_get_current(ctx);
	uint64_t age_ns = defer_sample_state.stamp - iter_data->req_stamp;

	VERBOSE_LOG("  %s POP from %d after %4.3f ms\n",
			kr_straddr(ctx->comm->comm_addr),
			queue_ix,
			age_ns / 1000000.0);

	if (ctx->session->closing) {
		VERBOSE_LOG("    BREAK (session is closing)\n");
		protolayer_break(ctx, kr_error(ECANCELED));
		return;
	}
	if (age_ns >= REQ_TIMEOUT) {
		VERBOSE_LOG("    BREAK (timeout)\n");
		protolayer_break(ctx, kr_error(ETIME));
		return;
	}

	int priority = classify((const union kr_sockaddr *)ctx->comm->comm_addr, ctx->session->stream);
	if (priority > queue_ix) {  // priority dropped (got higher value)
		VERBOSE_LOG("    PUSH to %d\n", priority);
		push_query(ctx, priority);
		return;
	}

	VERBOSE_LOG("    CONTINUE\n");
	protolayer_continue(ctx);
}

/// Unwrap: defer or process the query synchronously.
/// Time accounting should have been started, the stamp is used, accounted address is set.
static enum protolayer_iter_cb_result pl_defer_unwrap(
		void *sess_data, void *iter_data,
		struct protolayer_iter_ctx *ctx)
{
	if (ctx->session->outgoing)
		return protolayer_continue(ctx);

	defer_sample_addr((const union kr_sockaddr *)ctx->comm->comm_addr, ctx->session->stream);
	struct pl_defer_iter_data *data = iter_data;
	data->req_stamp = defer_sample_state.stamp;

	VERBOSE_LOG("  %s UNWRAP\n",
			kr_straddr(ctx->comm->comm_addr));
	int priority = classify((const union kr_sockaddr *)ctx->comm->comm_addr, ctx->session->stream);

	if (priority == -1) {
		VERBOSE_LOG("    CONTINUE\n");
		phase_accounting = true;
		return protolayer_continue(ctx);
	}

	VERBOSE_LOG("    PUSH to %d\n", priority);
	push_query(ctx, priority);
	while (waiting_requests > MAX_WAITING_REQS) {
		defer_sample_restart();
		process_single_deferred();  // possibly defers again without decreasing waiting_requests
		// defer_sample_stop should be called soon outside
	}

	return protolayer_async();
}

/// Idle: continue processing deferred requests.
static void defer_queues_idle(uv_idle_t *handle) {
	kr_assert(waiting_requests > 0);
	VERBOSE_LOG("IDLE\n");
	VERBOSE_LOG("  %d waiting\n", waiting_requests);
	defer_sample_start();
	uint64_t idle_stamp = defer_sample_state.stamp;
	while ((waiting_requests > 0) && (defer_sample_state.stamp < idle_stamp + IDLE_TIMEOUT)) {
		process_single_deferred();
		defer_sample_restart();
	}
	defer_sample_stop();  // TODO skip calling and use just restart elsewhere?
	udp_queue_send_all();

	if (waiting_requests > 0) {
		VERBOSE_LOG("  %d waiting\n", waiting_requests);
	} else {
		phase_set(PHASE_ANY);
	}
	VERBOSE_LOG("POLL\n");
}


/// Initialize shared memory, queues, idle.
int defer_init(uv_loop_t *loop)
{
	struct defer header = {
		.capacity = KRU_CAPACITY,
		.max_decay = MAX_DECAY,
		.using_avx2 = using_avx2(),
	};

	size_t capacity_log = 0;
	for (size_t c = header.capacity - 1; c > 0; c >>= 1) capacity_log++;

	size_t size = offsetof(struct defer, kru) + KRU.get_size(capacity_log);
	size_t header_size = offsetof(struct defer, using_avx2) + sizeof(header.using_avx2);
	kr_assert(header_size ==
		sizeof(header.capacity) +
		sizeof(header.max_decay) +
		sizeof(header.using_avx2));  // no undefined padding inside

	int ret = mmapped_init(&defer_mmapped, "defer", size, &header, header_size);
	if (ret == MMAPPED_WAS_FIRST) {
		kr_log_info(SYSTEM, "Initializing prioritization...\n");

		defer = defer_mmapped.mem;
		defer->time_now = 0;

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

	uv_idle_init(loop, &idle_handle);
	return 0;

fail:

	kr_log_crit(SYSTEM, "Initialization of shared prioritization data failed.\n");
	return ret;
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
		.unwrap = pl_defer_unwrap,
	};
}
