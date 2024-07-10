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

#define LOADS_THRESHOLDS  (uint16_t[])  {1<<4, 1<<8, 1<<11, -1}    // the last one should be UINT16_MAX
#define QUEUES_CNT        (sizeof(LOADS_THRESHOLDS) / sizeof(*LOADS_THRESHOLDS) - 1)

#define KRU_CAPACITY  (1<<10)
#define MAX_DECAY     (KRU_LIMIT * 0.0006929)  // -> halving counters in 1s
#define TIME_MULT     1/1   // max fraction of rate limit filled by one cpu (multiplies large int)
	// TODO divide by #cpus?

#define REQ_TIMEOUT        5000000 // ns (THREAD_CPUTIME), older deferred queries are dropped
#define IDLE_TIMEOUT       1000000 // ns (THREAD_CPUTIME); if exceeded, continue processing after next poll phase
#define MAX_WAITING_REQS     10000 // if exceeded, process single deferred request immediatelly in poll phase

#define VERBOSE_LOG(...) kr_log_notice(DEVEL, "defer |  " __VA_ARGS__)
// #define VERBOSE_LOG(...)

struct defer {
	size_t capacity;
	kru_price_t max_decay;
	bool using_avx2;
	_Alignas(64) uint8_t kru[];
};
struct defer *defer = NULL;
struct mmapped defer_mmapped = {0};

defer_sample_state_t defer_sample_state = {
	.is_accounting = 0,
};

uv_idle_t idle_handle;
static void defer_queues_idle(uv_idle_t *handle);

protolayer_iter_ctx_queue_t queues[QUEUES_CNT];
int waiting_requests = 0;
int queue_ix = QUEUES_CNT;  // MIN( last popped queue, first non-empty queue )

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
void defer_account(uint64_t nsec, union kr_sockaddr *addr) {
	_Alignas(16) uint8_t key[16] = {0, };
	uint16_t max_load = 0;
	uint8_t prefix = 0;
	kru_price_t base_price = (uint64_t)MAX_DECAY * nsec * TIME_MULT / 1000000ll;  // TODO adjust

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
	}

	VERBOSE_LOG("  %s ADD %4.3f ms -> load: %d on /%d\n",
			kr_straddr(&defer_sample_state.addr.ip), nsec / 1000000.0, max_load, prefix);
}

/// Determine priority of the request in [-1, QUEUES_CNT - 1].
/// Lower value has higher priority, -1 should be synchronous.
static inline int classify(const union kr_sockaddr *addr)
{
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

	int threshold_index = 0;  // 0: synchronous
	for (; LOADS_THRESHOLDS[threshold_index] < max_load; threshold_index++);

	VERBOSE_LOG("    load %d on /%d\n", max_load, prefix);

	return threshold_index - 1;
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

/// Pop and return the query with the highest priority, deactivate idle if not needed.
static inline struct protolayer_iter_ctx *pop_query(void)
{
	for (; queue_ix < QUEUES_CNT && queue_len(queues[queue_ix]) == 0; queue_ix++);
	if (queue_ix >= QUEUES_CNT) return NULL;

	struct protolayer_iter_ctx *ctx = queue_head(queues[queue_ix]);
	queue_pop(queues[queue_ix]);
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

	defer_sample_addr((const union kr_sockaddr *)ctx->comm->comm_addr);

	struct pl_defer_iter_data *iter_data = protolayer_iter_data_get_current(ctx);
	uint64_t age_ns = defer_sample_state.stamp - iter_data->req_stamp;

	VERBOSE_LOG("  %s POP from %d after %4.3f ms\n",
			kr_straddr(ctx->comm->comm_addr),
			queue_ix,
			age_ns / 1000000.0);

	if (age_ns >= REQ_TIMEOUT) {
		VERBOSE_LOG("    BREAK\n");
		protolayer_break(ctx, kr_error(ETIME));
		return;
	}

	int priority = classify((const union kr_sockaddr *)ctx->comm->comm_addr);
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

	defer_sample_addr((const union kr_sockaddr *)ctx->comm->comm_addr);
	struct pl_defer_iter_data *data = iter_data;
	data->req_stamp = defer_sample_state.stamp;

	VERBOSE_LOG("  %s UNWRAP\n",
			kr_straddr(ctx->comm->comm_addr));
	int priority = classify((const union kr_sockaddr *)ctx->comm->comm_addr);

	if (priority == -1) {
		VERBOSE_LOG("    CONTINUE\n");
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
	size_t header_size = offsetof(struct defer, kru);

	int ret = mmapped_init(&defer_mmapped, "defer", size, &header, header_size);
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
