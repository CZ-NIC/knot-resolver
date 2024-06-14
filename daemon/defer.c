#include "daemon/defer.h"
#include "daemon/mmapped.h"
#include "daemon/session2.h"
#include "lib/kru.h"
#include "lib/utils.h"

#define V4_PREFIXES  (uint8_t[])       {  18,  20, 24, 32 }
#define V4_RATE_MULT (kru_price_t[])   { 768, 256, 32,  1 }

#define V6_PREFIXES  (uint8_t[])       { 32, 48, 56, 64, 128 }
#define V6_RATE_MULT (kru_price_t[])   { 64,  4,  3,  2,   1 }

#define V4_PREFIXES_CNT (sizeof(V4_PREFIXES) / sizeof(*V4_PREFIXES))
#define V6_PREFIXES_CNT (sizeof(V6_PREFIXES) / sizeof(*V6_PREFIXES))
#define MAX_PREFIXES_CNT ((V4_PREFIXES_CNT > V6_PREFIXES_CNT) ? V4_PREFIXES_CNT : V6_PREFIXES_CNT)

#define LOADS_THRESHOLDS  (uint16_t[])  {1<<4, 1<<8, 1<<11, -1}
#define QUEUES_CNT        (sizeof(LOADS_THRESHOLDS) / sizeof(*LOADS_THRESHOLDS) - 1)

#define MAX_DECAY  (KRU_LIMIT * 0.0006929)  // -> halving counters in 1s
#define TIME_MULT  1/1   // max fraction of rate limit filled by one cpu (multiplies large int)  // TODO divide by #cpus?

struct defer {
	size_t capacity;
	kru_price_t max_decay;
	bool using_avx2;
	_Alignas(64) uint8_t kru[];
};
struct defer *defer = NULL;
struct mmapped defer_mmapped = {0};

uv_check_t check_handle;
protolayer_iter_ctx_queue_t queues[QUEUES_CNT];

defer_sample_state_t defer_sample_state = {
	.is_accounting = 0,
};

/// Return whether we're using optimized variant right now.
static bool using_avx2(void)
{
	bool result = (KRU.initialize == KRU_AVX2.initialize);
	kr_require(result || KRU.initialize == KRU_GENERIC.initialize);
	return result;
}

/// Increment KRU counters by given time.
void defer_account(uint64_t nsec, union kr_sockaddr addr) {
	_Alignas(16) uint8_t key[16] = {0, };
	uint16_t max_load = 0;
	if (defer_sample_state.addr.ip.sa_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&defer_sample_state.addr.ip;
		memcpy(key, &ipv6->sin6_addr, 16);

		kru_price_t prices[V6_PREFIXES_CNT];
		for (size_t i = 0; i < V6_PREFIXES_CNT; i++) {
			prices[i] = (uint64_t)MAX_DECAY * nsec * TIME_MULT / 1000000ll / V6_RATE_MULT[i];  // TODO adjust
		}

		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, kr_now(),
				1, key, V6_PREFIXES, prices, V6_PREFIXES_CNT);
	} else if (defer_sample_state.addr.ip.sa_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)&defer_sample_state.addr.ip;
		memcpy(key, &ipv4->sin_addr, 4);  // TODO append port?

		kru_price_t prices[V4_PREFIXES_CNT];
		for (size_t i = 0; i < V4_PREFIXES_CNT; i++) {
			prices[i] = (uint64_t)MAX_DECAY * nsec * TIME_MULT / 1000000ll / V4_RATE_MULT[i];   // TODO adjust
		}

		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, kr_now(),
				0, key, V4_PREFIXES, prices, V4_PREFIXES_CNT);
	}

	kr_log_notice(DEVEL, "%8.3f ms for %s, load: %d\n", nsec / 1000000.0,
			kr_straddr(&defer_sample_state.addr.ip), max_load);
}

/// Determine whether the request should be deferred during unwrapping.
static enum protolayer_iter_cb_result pl_defer_unwrap(
		void *sess_data, void *iter_data,
		struct protolayer_iter_ctx *ctx)
{
	if (ctx->session->outgoing)
		return protolayer_continue(ctx);

	defer_sample_addr((const union kr_sockaddr *)ctx->comm->comm_addr);

	_Alignas(16) uint8_t key[16] = {0, };
	uint16_t max_load = 0;
	if (ctx->comm->comm_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)ctx->comm->comm_addr;
		memcpy(key, &ipv6->sin6_addr, 16);

		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, kr_now(),
				1, key, V6_PREFIXES, NULL, V6_PREFIXES_CNT);
	} else if (ctx->comm->comm_addr->sa_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)ctx->comm->comm_addr;
		memcpy(key, &ipv4->sin_addr, 4);  // TODO append port?

		max_load = KRU.load_multi_prefix_max((struct kru *)defer->kru, kr_now(),
				0, key, V4_PREFIXES, NULL, V4_PREFIXES_CNT);
	}

	int threshold_index = 0;  // 0: synchronous
	for (; LOADS_THRESHOLDS[threshold_index] < max_load; threshold_index++);

	kr_log_notice(DEVEL, "DEFER | addr: %s, load: %d, queue: %d\n",
			kr_straddr(ctx->comm->src_addr),
			max_load, threshold_index);

	if (threshold_index == 0)
		return protolayer_continue(ctx);

	queue_push(queues[threshold_index - 1], ctx);

	return protolayer_async();
}

/// Continue processing deferred requests in libuv check phase.
static void defer_queues_check(uv_check_t *handle) {
	// TODO drop too old requests and/or break processing if it lasts too long (keeping some work to another check phase)
	for (size_t i = 0; i < QUEUES_CNT; i++) {
		while (queue_len(queues[i]) > 0) {
			defer_sample_start();
			struct protolayer_iter_ctx *ctx = queue_head(queues[i]);
			queue_pop(queues[i]);
			defer_sample_addr((const union kr_sockaddr *)ctx->comm->comm_addr);
			kr_log_notice(DEVEL, "DEFER continue: %s\n",
					kr_straddr(ctx->comm->comm_addr));
			protolayer_continue(ctx);
			defer_sample_stop();
		}
	}
}

/// Initialize defer, incl. shared memory with KRU.
int defer_init(uv_loop_t *loop) {
	struct defer header = {  // TODO adjust hardcoded values
		.capacity = 1 << 10,
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

	protolayer_globals[PROTOLAYER_TYPE_DEFER].unwrap = pl_defer_unwrap;
	uv_check_init(loop, &check_handle);
	uv_check_start(&check_handle, defer_queues_check);
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
