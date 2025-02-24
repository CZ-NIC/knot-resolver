/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <math.h>
#include <stdatomic.h>
#include <unistd.h>
#include "daemon/defer.h"
#include "daemon/session2.h"
#include "daemon/udp_queue.h"
#include "lib/kru.h"
#include "lib/mmapped.h"
#include "lib/resolve.h"
#include "lib/utils.h"

#define V4_PREFIXES  (uint8_t[])       {  18,  20, 24, 32 }
#define V4_RATE_MULT (kru_price_t[])   { 768, 256, 32,  1 }
#define V4_SUBPRIO   (uint8_t[])       {   0,   1,  3,  7 }

#define V6_PREFIXES  (uint8_t[])       { 32, 48, 56, 64, 128 }
#define V6_RATE_MULT (kru_price_t[])   { 64,  4,  3,  2,   1 }
#define V6_SUBPRIO   (uint8_t[])       {  2,  4,  5,  6,   7 }

#define SUBPRIO_CNT 8
#define V4_PREFIXES_CNT (sizeof(V4_PREFIXES) / sizeof(*V4_PREFIXES))
#define V6_PREFIXES_CNT (sizeof(V6_PREFIXES) / sizeof(*V6_PREFIXES))
#define MAX_PREFIXES_CNT ((V4_PREFIXES_CNT > V6_PREFIXES_CNT) ? V4_PREFIXES_CNT : V6_PREFIXES_CNT)

struct kru_conf {
	uint8_t namespace;
	size_t prefixes_cnt;
	uint8_t *prefixes;
	const kru_price_t *rate_mult;
	const uint8_t *subprio;
} const
V4_CONF = {0, V4_PREFIXES_CNT, V4_PREFIXES, V4_RATE_MULT, V4_SUBPRIO},
V6_CONF = {1, V6_PREFIXES_CNT, V6_PREFIXES, V6_RATE_MULT, V6_SUBPRIO};

#define LOADS_THRESHOLDS      (uint16_t[])  {1<<4, 1<<8, 1<<12, -1}    // the last one should be UINT16_MAX
#define QUEUES_CNT            ((sizeof(LOADS_THRESHOLDS) / sizeof(*LOADS_THRESHOLDS) - 1) * SUBPRIO_CNT + 2)
	// priority 0 has no subpriorities, +1 for unverified
#define PRIORITY_UDP          (QUEUES_CNT - 1)  // last queue

#define Q0_INSTANT_LIMIT      1000000 // ns
#define KRU_CAPACITY          (1<<19) // same as ratelimiting default
#define BASE_PRICE(nsec)      ((uint64_t)KRU_LIMIT * LOADS_THRESHOLDS[0] / (1<<16) * (nsec) / Q0_INSTANT_LIMIT)
#define MAX_DECAY             (BASE_PRICE(1000000) / 2)  // max value at 50% utilization of single cpu
	//   see log written by defer_str_conf for details

#define REQ_TIMEOUT        1000000000 // ns (THREAD_CPUTIME), older deferred queries are dropped
#define IDLE_TIMEOUT          1000000 // ns (THREAD_CPUTIME); if exceeded, continue processing after next poll phase
#define PHASE_UDP_TIMEOUT      400000 // ns (THREAD_CPUTIME); switch between udp, non-udp phases
#define PHASE_NON_UDP_TIMEOUT  400000 // ns (THREAD_CPUTIME);    after timeout or emptying queue
#define MAX_WAITING_REQS_SIZE (64l * 1024 * 1024)  // bytes; if exceeded, some deferred requests are processed in poll phase
	// single TCP allocates more than 64KiB wire buffer
	// TODO check whether all important allocations are counted;
	//   different things are not counted: tasks and subsessions (not deferred after creation), uv handles, queues overhead, ...;
	//   payload is counted either as part of session wire buffer (for stream) or as part of iter ctx (for datagrams)


/// Async-signal-safe snprintf-like formatting function, it supports:
///   * %s takes (char *);
///   * %u takes unsigned, %NUMu allowed for padding with spaces or zeroes;
///   * %x takes unsigned, %NUMx allowed;
///   * %f takes double, behaves like %.3f;
///   * %r takes (struct sockaddr *).
int sigsafe_format(char *str, size_t size, const char *fmt, ...) {
	char *strp = str;        // ptr just after last written char
	char *stre = str + size; // ptr just after str buffer
	const char digits[] ="0123456789abcdef";
	va_list ap;
	va_start(ap, fmt);  // NOLINT, should be safe in GCC
	while (*fmt && (stre-strp > 1)) {
		const char *append_str = NULL;
		int append_len = -1;
		bool mod_zero = false;
		int  mod_int = 0;
		int  base = 10;
		char tmpstr[50];

		if (*fmt != '%') {
			char *perc = strchr(fmt, '%');
			append_str = fmt;
			append_len = perc ? perc - fmt : strlen(fmt);
			fmt += append_len;
		} else while(fmt++, !append_str) {
			switch(*fmt) {
				case '%':   // %%
					append_str = "%";
					break;
				case 's':   // just %s
					append_str = va_arg(ap, char *);  // NOLINT, should be safe in GCC
					break;
				case 'x':   // %x, %#x, %0#x
					base = 16; // passthrough
				case 'u': { // %u, %#u, %0#u
					unsigned num = va_arg(ap, unsigned);  // NOLINT, should be safe in GCC
					char *sp = tmpstr + sizeof(tmpstr);
					*--sp = '\0';
					while ((num > 0) || !*sp) {
						*--sp = digits[num % base];
						num /= base;
						mod_int--;
					}
					while (mod_int-- > 0) {
						*--sp = mod_zero ? '0' : ' ';
					}
					append_str = sp;
					} break;
				case 'f': { // just %f, behaves like %.3f
					double valf = va_arg(ap, double);  // NOLINT, should be safe in GCC
					const char *sign = "";
					if (valf < 0) { sign = "-"; valf *= -1; }
					uint64_t vali = valf * 1000 + 0.5;  // NOLINT(bugprone-incorrect-roundings), just minor imprecisions
						// larger numbers, NaNs, ... are not handled
					strp += sigsafe_format(strp, stre-strp, "%s%u.%03u", sign, (unsigned)(vali / 1000), (unsigned)(vali % 1000));
					append_str = "";
					} break;
				case 'r': { // just %r, takes (struct sockaddr *)
					struct sockaddr *addr = va_arg(ap, void *);  // NOLINT, should be safe in GCC
					if (!addr) {
						append_str = "(null)";
						break;
					}
					switch (addr->sa_family) {
						case AF_UNIX:
							append_str = ((struct sockaddr_un *)addr)->sun_path;
							break;
						case AF_INET: {
							struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
							uint8_t *ipv4 = (uint8_t *)&(addr4->sin_addr);
							uint8_t *port = (uint8_t *)&(addr4->sin_port);
							strp += sigsafe_format(strp, stre-strp, "%u.%u.%u.%u#%u", ipv4[0], ipv4[1], ipv4[2], ipv4[3], (port[0] << 8) | port[1]);
							append_str = "";
							} break;
						case AF_INET6: {
							struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
							uint8_t *ipv6 = (uint8_t *)&(addr6->sin6_addr);
							uint8_t *port = (uint8_t *)&(addr6->sin6_port);
							int mzb = -2, mze = 0;  // maximal zero-filled gap begin (incl.) and end (excl.)
							{ // find longest gap
								int zb = 0, ze = 0;
								for (size_t i = 0; i < 16; i += 2) {
									if (!ipv6[i] && !ipv6[i+1]) {
										if (i == ze) {
											ze += 2;
										} else {
											if (ze - zb > mze - mzb) {
												mzb = zb; mze = ze;
											}
											zb = i; ze = i + 2;
										}
									}
								}
								if (ze - zb > mze - mzb) {
									mzb = zb; mze = ze;
								}
							}
							for (int i = -!mzb; i < 15; i++) {
								if (i == mzb) i = mze - 1;  // after ':' (possibly for i=-1), skip sth. and continue with ':' (possibly for i=15)
								if (i%2) {
									if (strp < stre) *strp++ = ':';
								} else {
									strp += sigsafe_format(strp, stre-strp, "%x", (ipv6[i] << 8) | ipv6[i+1]);
								}
							}
							strp += sigsafe_format(strp, stre-strp, "#%u", (port[0] << 8) | port[1]);
							append_str = "";
							} break;
						case AF_UNSPEC:
							append_str = "(unspec)";
							break;
						default:
							append_str = "(unknown)";
							break;
					}
					} break;
				default:
					if (('0' <= *fmt) && (*fmt <= '9')) {
						if ((mod_int == 0) && (*fmt == '0')) {
							mod_zero = true;
						} else {
							mod_int = mod_int * 10 + *fmt - '0';
						}
					} else {
						append_str = "[ERR]";
					}
					break;
			}
		}

		// append to str (without \0)
		append_len = MIN(append_len >= 0 ? append_len : strlen(append_str), stre-strp-1);
		memcpy(strp, append_str, append_len);
		strp += append_len;
	}
	*strp = '\0';
	va_end(ap);  // NOLINT, should be safe in GCC
	return strp-str;
}

#define VERBOSE_LOG(...) kr_log_debug(DEFER, " | " __VA_ARGS__)

// Uses NON-STANDARD format string, see sigsafe_format above.
#define SIGSAFE_LOG(max_size, ...) { \
	char msg[max_size]; \
	int len = sigsafe_format(msg, sizeof(msg), "[defer ] "__VA_ARGS__); \
	write(kr_log_target == LOG_TARGET_STDOUT ? 1 : 2, msg, len); \
}
#define SIGSAFE_VERBOSE_LOG(max_size, ...) { \
	if (kr_log_is_debug(DEFER, NULL)) /* NOLINT */\
	{ SIGSAFE_LOG(max_size, " | " __VA_ARGS__)}}


struct defer {
	size_t capacity;
	kru_price_t max_decay;
	uint32_t log_period;
	uint32_t hard_timeout;
	int cpus;
	bool using_avx2;
	_Atomic uint32_t log_time;
	_Alignas(64) uint8_t kru[];
};
struct defer *defer = NULL;
bool defer_initialized = false;
uint64_t defer_uvtime_stamp = 0;
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
	PHASE_NONE,
	PHASE_UDP,
	PHASE_NON_UDP
} phase = PHASE_NONE;
uint64_t phase_elapsed[3] = { 0 };  // ns; [PHASE_NONE] value is being incremented but never used
const uint64_t phase_limits[3] = {0, PHASE_UDP_TIMEOUT, PHASE_NON_UDP_TIMEOUT};
uint64_t phase_stamp = 0;

static inline bool phase_over_limit(enum phase p)
{
	return phase_elapsed[p] >= phase_limits[p];
}

/// Reset elapsed times of phases and set phase to UDP, NON_UDP, or NONE.
static inline void phase_reset(enum phase p)
{
	phase_elapsed[PHASE_UDP] = 0;
	phase_elapsed[PHASE_NON_UDP] = 0;
	phase_stamp = defer_sample_state.stamp;
	phase = p;
}

/// Set phase to UDP or NON_UDP if it is not over limit or both are over limit (reset them).
static inline bool phase_try_set(enum phase p)
{
	phase_elapsed[phase] += defer_sample_state.stamp - phase_stamp;
	phase_stamp = defer_sample_state.stamp;

	if (!phase_over_limit(p)) {
		phase = p;
		return true;
	} else if (phase_over_limit(PHASE_UDP) && phase_over_limit(PHASE_NON_UDP)) {
		phase_reset(p);
		return true;
	}

	return false;
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
void defer_str_conf(char *desc, int desc_len)
{
	int len = 0;
#define append(...) len += snprintf(desc + len, desc_len > len ? desc_len - len : 0, __VA_ARGS__)
#define append_time(prefix, ms, suffix) { \
		if ((ms) < 1) append(prefix "%7.1f us" suffix, (ms) * 1000); \
		else if ((ms) < 1000) append(prefix "%7.1f ms" suffix, (ms)); \
		else append(prefix "%7.1f s " suffix, (ms) / 1000); }
	append(     "  Expected cpus/procs: %5d\n", defer->cpus);

	const size_t thresholds = sizeof(LOADS_THRESHOLDS) / sizeof(*LOADS_THRESHOLDS);
	append(     "  Max waiting requests:%7.1f MiB\n", MAX_WAITING_REQS_SIZE / 1024.0 / 1024.0);
	append_time("  Request timeout:     ", REQ_TIMEOUT           / 1000000.0, "\n");
	append_time("  Idle:                ", IDLE_TIMEOUT          / 1000000.0, "\n");
	append_time("  UDP phase:           ", PHASE_UDP_TIMEOUT     / 1000000.0, "\n");
	append_time("  Non-UDP phase:       ", PHASE_NON_UDP_TIMEOUT / 1000000.0, "\n");
	append(     "  Priority levels:     %5ld (%ld main levels, %d sublevels) + UDP\n", QUEUES_CNT - 1, thresholds, SUBPRIO_CNT);

	size_t capacity_log = 0;
	for (size_t c = defer->capacity - 1; c > 0; c >>= 1) capacity_log++;
	size_t size = offsetof(struct defer, kru) + KRU.get_size(capacity_log);

	append(     "  KRU capacity:        %7.1f k (%0.1f MiB)\n", (1 << capacity_log) / 1000.0, size / 1000000.0);

	bool uniform_thresholds = true;
	for (int i = 1; i < thresholds - 1; i++)
		uniform_thresholds &= (LOADS_THRESHOLDS[i] == LOADS_THRESHOLDS[i - 1] * LOADS_THRESHOLDS[0]);
	uniform_thresholds &= ((1<<16) == (int)LOADS_THRESHOLDS[thresholds - 2] * LOADS_THRESHOLDS[0]);

	append(     "  Decay:                 %7.3f %% per ms (32-bit max: %d)\n",
			100.0 * defer->max_decay / KRU_LIMIT, defer->max_decay);
	float half_life = -1.0 / log2f(1.0 - (float)defer->max_decay / KRU_LIMIT);
	append_time("    Half-life:         ", half_life, "\n");
	if (uniform_thresholds)
		append_time("    Priority rise in:  ", half_life * 16 / thresholds, "\n");
	append_time("    Counter reset in:  ", half_life * 16, "\n");

	append("  Rate limits for crossing priority levels as single CPU utilization:\n");

	const struct kru_conf *kru_confs[] = {&V4_CONF, &V6_CONF};
	const int version[] = {4, 6};
	const kru_price_t base_price_ms = BASE_PRICE(1000000);

	append("%15s", "");
	for (int j = 0; j < 3; j++)
		append("%14d", j+1);
	append("%14s\n", "max");

	for (int v = 0; v < 2; v++) {
		for (int i = kru_confs[v]->prefixes_cnt - 1; i >= 0; i--) {
			append("%9sv%d/%-3d: ", "", version[v], kru_confs[v]->prefixes[i]);
			for (int j = 0; j < thresholds; j++) {
				float needed_util = (float)defer->max_decay / (1<<16) * LOADS_THRESHOLDS[j] / base_price_ms * kru_confs[v]->rate_mult[i];
				append("%12.3f %%", needed_util * 100);
			}
			append("\n");
		}
	}

	append("  Instant limits for crossing priority levels as CPU time:\n");

	append("%15s", "");
	for (int j = 0; j < 3; j++)
		append("%14d", j+1);
	append("%14s\n", "max");

	for (int v = 0; v < 2; v++) {
		for (int i = kru_confs[v]->prefixes_cnt - 1; i >= 0; i--) {
			append("%9sv%d/%-3d:  ", "", version[v], kru_confs[v]->prefixes[i]);
			for (int j = 0; j < thresholds; j++) {
				float needed_time = (float)KRU_LIMIT / (1<<16) * LOADS_THRESHOLDS[j] / base_price_ms * kru_confs[v]->rate_mult[i];
				if (needed_time < 1) {
					append("%11.1f us", needed_time * 1000);
				} else if (needed_time < 1000) {
					append("%11.1f ms", needed_time);
				} else {
					append("%11.1f s ", needed_time / 1000);
				}
			}
			append("\n");
		}
	}
	append("    (values above max are indistinguishable)\n");

#undef append_time
#undef append
}

void defer_set_price_factor16(struct kr_request *req, uint32_t price_factor16)
{
	req->qsource.price_factor16 = defer_sample_state.price_factor16 = price_factor16;
}

/// Call KRU, return priority and as params load and prefix.
static inline int kru_charge_classify(const struct kru_conf *kru_conf, uint8_t *key, kru_price_t *prices,
		uint16_t *out_load, uint8_t *out_prefix)
{
	uint16_t loads[kru_conf->prefixes_cnt];
	const uint64_t now = kr_now(); // NOLINT, async-signal-safe, uv_now only reads uint64_t
	KRU.load_multi_prefix((struct kru *)defer->kru, now,
			kru_conf->namespace, key, kru_conf->prefixes, prices, kru_conf->prefixes_cnt, loads);

	int priority = 0;
	int prefix_index = kru_conf->prefixes_cnt - 1;
	for (int i = kru_conf->prefixes_cnt - 1, j = 0; i >= 0; i--) {
		for (; LOADS_THRESHOLDS[j] < loads[i]; j++) {
			prefix_index = i;
			priority = 1 + j * SUBPRIO_CNT + kru_conf->subprio[i];
		}
	}
	*out_load = loads[prefix_index];
	*out_prefix = kru_conf->prefixes[prefix_index];
	return priority;
}

/// Increment KRU counters by given time.
void defer_charge(uint64_t nsec, union kr_sockaddr *addr, bool stream)
{
	if (!stream) return;  // UDP is not accounted in KRU; TODO remove !stream invocations?
	
	// compute time adjusted by the price factor
	uint64_t nsec_adj;
	const uint32_t pf16 = defer_sample_state.price_factor16;
	if (pf16 == 0) return;  // whitelisted
	if (nsec < (1ul<<32)) {  // simple way with standard rounding
		nsec_adj = (nsec * pf16 + (1<<15)) >> 16;
	} else {  // afraid of overflow, so we swap the order of the math
		nsec_adj = ((nsec + (1<<15)) >> 16) * pf16;
	}

	_Alignas(16) uint8_t key[16] = {0, };
	const struct kru_conf *kru_conf;
	if (addr->ip.sa_family == AF_INET6) {
		memcpy(key, &addr->ip6.sin6_addr, 16);
		kru_conf = &V6_CONF;
	} else if (addr->ip.sa_family == AF_INET) {
		memcpy(key, &addr->ip4.sin_addr, 4);
		kru_conf = &V4_CONF;
	} else {
		return;
	}

	uint64_t base_price = BASE_PRICE(nsec_adj);
	kru_price_t prices[kru_conf->prefixes_cnt];
	for (size_t i = 0; i < kru_conf->prefixes_cnt; i++) {
		uint64_t price = base_price / kru_conf->rate_mult[i];
		prices[i] = price > (kru_price_t)-1 ? -1 : price;
	}

	uint16_t load;
	uint8_t prefix;
	kru_charge_classify(kru_conf, key, prices, &load, &prefix);

	SIGSAFE_VERBOSE_LOG(KR_STRADDR_MAXLEN + 100,
			"  %r ADD %f ms * %f -> load: %u on /%u\n",
			&addr->ip, nsec / 1000000.0, pf16 / (float)(1<<16), load, prefix);
}

/// Determine priority of the request in [0, QUEUES_CNT - 1];
/// lower value has higher priority; plain UDP always gets PRIORITY_UDP.
static inline int classify(const union kr_sockaddr *addr, bool stream)
{
	if (!stream) { // UDP
		VERBOSE_LOG("    unverified address\n");
		return PRIORITY_UDP;
	}

	_Alignas(16) uint8_t key[16] = {0, };
	const struct kru_conf *kru_conf = NULL;
	if (addr->ip.sa_family == AF_INET6) {
		memcpy(key, &addr->ip6.sin6_addr, 16);
		kru_conf = &V6_CONF;
	} else if (addr->ip.sa_family == AF_INET) {
		memcpy(key, &addr->ip4.sin_addr, 4);
		kru_conf = &V4_CONF;
	} else {
		kr_assert(false);
		return 0; // shouldn't happen anyway
	}

	uint16_t load;
	uint8_t prefix;
	int priority = kru_charge_classify(kru_conf, key, NULL, &load, &prefix);

	VERBOSE_LOG("    load %d on /%d\n", load, prefix);

	return priority;
}


/// Push query to a queue according to its priority.
static inline void push_query(struct protolayer_iter_ctx *ctx, int priority, bool to_head_end)
{
	if (to_head_end) {
		queue_push_head(queues[priority], ctx);
	} else {
		queue_push(queues[priority], ctx);
	}
	queue_ix = MIN(queue_ix, priority);
	waiting_requests++;
}

/// Pop and return query from the specified queue..
static inline struct protolayer_iter_ctx *pop_query_queue(int priority)
{
	kr_assert(queue_len(queues[priority]) > 0);
	struct protolayer_iter_ctx *ctx = queue_head(queues[priority]);
	queue_pop(queues[priority]);
	waiting_requests--;
	kr_assert(waiting_requests >= 0);
	return ctx;
}


/// Pop and return the query with the highest priority, UDP or non-UDP based on the current phase.
static inline struct protolayer_iter_ctx *pop_query(void)
{
	const int waiting_udp = queue_len(queues[PRIORITY_UDP]);
	const int waiting_non_udp = waiting_requests - waiting_udp;

	if (!((waiting_non_udp > 0) && phase_try_set(PHASE_NON_UDP)) &&
		  !((waiting_udp     > 0) && phase_try_set(PHASE_UDP)))
		phase_reset(waiting_non_udp > 0 ? PHASE_NON_UDP : PHASE_UDP);

	int i;
	if (phase == PHASE_NON_UDP) {
		for (; queue_ix < QUEUES_CNT && queue_len(queues[queue_ix]) == 0; queue_ix++);
		if (kr_fails_assert(queue_ix < PRIORITY_UDP))
			return NULL;
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
					kr_log_notice(DEFER, "Data from %s too long in queue, dropping. (%0.3f MiB in queues)\n",
							kr_straddr(ctx->comm->src_addr), waiting_requests_size / 1024.0 / 1024.0);
					break;
				}
			}
		}

		break_query(ctx, ETIME);
		return;
	}

	bool eof = false;
	if (ctx->session->stream) {
		int priority = classify((const union kr_sockaddr *)ctx->comm->src_addr, ctx->session->stream);
		if (priority > queue_ix) {  // priority dropped (got higher value)
			VERBOSE_LOG("    PUSH to %d\n", priority);
			push_query(ctx, priority, false);
			return;
		}

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

/// Process as many deferred requests as needed to get memory consumption under limit.
static inline void process_deferred_over_size_limit(void) {
	if (waiting_requests_size > MAX_WAITING_REQS_SIZE) {
		defer_sample_state_t prev_sample_state;
		defer_sample_start(&prev_sample_state);
		do {
			process_single_deferred();  // possibly defers again without decreasing waiting_requests_size
				// If the unwrapped query is to be processed here,
				// it is the last iteration and the query is processed after returning.
			defer_sample_restart();
		} while (waiting_requests_size > MAX_WAITING_REQS_SIZE);
		defer_sample_stop(&prev_sample_state, true);
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
	struct pl_defer_iter_data *idata = iter_data;
	struct pl_defer_sess_data *sdata = sess_data;
	idata->req_stamp = defer_sample_state.stamp;

	VERBOSE_LOG("  %s UNWRAP\n",
			kr_straddr(ctx->comm->src_addr));

	uv_idle_start(&idle_handle, defer_queues_idle);

	if (queue_len(sdata->queue) > 0) {  // stream with preceding packet already deferred
		queue_push(sdata->queue, ctx);
		waiting_requests_size += idata->size = protolayer_iter_size_est(ctx, false);
			// payload counted in session wire buffer
		VERBOSE_LOG("    PUSH as follow-up\n");
		process_deferred_over_size_limit();
		return protolayer_async();
	}

	int priority = classify((const union kr_sockaddr *)ctx->comm->src_addr, ctx->session->stream);

	// Process synchronously unless there may exist requests that has to be processed first
	if (((priority == 0) || (priority == PRIORITY_UDP)) && (queue_len(queues[priority]) == 0) &&
			phase_try_set(priority == PRIORITY_UDP ? PHASE_UDP : PHASE_NON_UDP)) {
		VERBOSE_LOG("    CONTINUE\n");
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

	process_deferred_over_size_limit();
	return protolayer_async();
}

/// Unwrap event: EOF event may be deferred here, other events pass synchronously.
static enum protolayer_event_cb_result pl_defer_event_unwrap(
		enum protolayer_event_type event, void **baton,
		struct session2 *session, void *sess_data)
{
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
	VERBOSE_LOG("IDLE\n");
	if (waiting_requests > 0) {
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
	}

	if (waiting_requests > 0) {
		VERBOSE_LOG("  %d waiting\n", waiting_requests);
	} else {
		phase_reset(PHASE_NONE);
		VERBOSE_LOG("  deactivate idle\n");
		uv_idle_stop(&idle_handle);
	}
	VERBOSE_LOG("POLL\n");
}

static void defer_alarm(int signum)
{
	if (!defer || (defer->hard_timeout == 0)) return;

	uint64_t elapsed = 0;
	if (defer_sample_state.is_accounting) {
		elapsed = defer_get_stamp() - defer_sample_state.stamp;
		SIGSAFE_VERBOSE_LOG(KR_STRADDR_MAXLEN + 100,
				"SIGALRM %s, host %r used %f s of cpu time on ongoing operation.\n",
				signum ? "received" : "initialized",
				&defer_sample_state.addr.ip, elapsed / 1000000000.0);
	} else {
		SIGSAFE_VERBOSE_LOG(KR_STRADDR_MAXLEN + 100,
				"SIGALRM %s, no measuring in progress.\n",
				signum ? "received" : "initialized");
	}
	int64_t rest_to_timeout_ms = defer->hard_timeout - elapsed / 1000000; // ms - ns

	if (rest_to_timeout_ms <= 0) {
		defer_charge(elapsed, &defer_sample_state.addr, defer_sample_state.stream);
		SIGSAFE_LOG(KR_STRADDR_MAXLEN + 100,
			"Host %r used %f s of cpu time continuously, interrupting kresd.\n",
			&defer_sample_state.addr.ip, elapsed / 1000000000.0);
		abort();
	}
	alarm((rest_to_timeout_ms + 999) / 1000);
}

/// Initialize shared memory, queues. To be called from Lua.
int defer_init(const char *mmap_file, uint32_t log_period, uint32_t hard_timeout, int cpus)
	// TODO possibly remove cpus; not needed
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
		.hard_timeout = hard_timeout,
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
			sizeof(header.hard_timeout) +
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

	if (signal(SIGALRM, defer_alarm) == SIG_ERR) {
		kr_log_error(DEFER, "Cannot set SIGALRM handler, interrupting of too long work on a single request will not work: %s\n",
			strerror(errno));
	}
	defer_alarm(0);

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
