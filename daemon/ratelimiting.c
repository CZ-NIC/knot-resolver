/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdatomic.h>
#include "daemon/ratelimiting.h"
#include "lib/kru.h"
#include "lib/mmapped.h"
#include "lib/utils.h"
#include "lib/resolve.h"

#define V4_PREFIXES  (uint8_t[])       {  18,  20, 24, 32 }
#define V4_RATE_MULT (kru_price_t[])   { 768, 256, 32,  1 }

#define V6_PREFIXES  (uint8_t[])       { 32, 48, 56, 64, 128 }
#define V6_RATE_MULT (kru_price_t[])   { 64,  4,  3,  2,   1 }

#define V4_PREFIXES_CNT (sizeof(V4_PREFIXES) / sizeof(*V4_PREFIXES))
#define V6_PREFIXES_CNT (sizeof(V6_PREFIXES) / sizeof(*V6_PREFIXES))
#define MAX_PREFIXES_CNT ((V4_PREFIXES_CNT > V6_PREFIXES_CNT) ? V4_PREFIXES_CNT : V6_PREFIXES_CNT)

struct ratelimiting {
	size_t capacity;
	uint32_t instant_limit;
	uint32_t rate_limit;
	uint32_t log_period;
	uint16_t slip;
	bool dry_run;
	bool using_avx2;
	_Atomic uint32_t log_time;
	kru_price_t v4_prices[V4_PREFIXES_CNT];
	kru_price_t v6_prices[V6_PREFIXES_CNT];
	_Alignas(64) uint8_t kru[];
};
struct ratelimiting *ratelimiting = NULL;
struct mmapped ratelimiting_mmapped = {0};

/// return whether we're using optimized variant right now
static bool using_avx2(void)
{
	bool result = (KRU.initialize == KRU_AVX2.initialize);
	kr_require(result || KRU.initialize == KRU_GENERIC.initialize);
	return result;
}

int ratelimiting_init(const char *mmap_file, size_t capacity, uint32_t instant_limit,
		uint32_t rate_limit, uint16_t slip, uint32_t log_period, bool dry_run)
{

	size_t capacity_log = 0;
	for (size_t c = capacity - 1; c > 0; c >>= 1) capacity_log++;

	size_t size = offsetof(struct ratelimiting, kru) + KRU.get_size(capacity_log);

	struct ratelimiting header = {
		.capacity = capacity,
		.instant_limit = instant_limit,
		.rate_limit = rate_limit,
		.log_period = log_period,
		.slip = slip,
		.dry_run = dry_run,
		.using_avx2 = using_avx2()
	};

	size_t header_size = offsetof(struct ratelimiting, using_avx2) + sizeof(header.using_avx2);
	static_assert(  // no padding up to .using_avx2
		offsetof(struct ratelimiting, using_avx2) ==
			sizeof(header.capacity) +
			sizeof(header.instant_limit) +
			sizeof(header.rate_limit) +
			sizeof(header.log_period) +
			sizeof(header.slip) +
			sizeof(header.dry_run),
		"detected padding with undefined data inside mmapped header");

	int ret = mmapped_init(&ratelimiting_mmapped, mmap_file, size, &header, header_size);
	if (ret == MMAPPED_WAS_FIRST) {
		kr_log_info(SYSTEM, "Initializing rate-limiting...\n");

		ratelimiting = ratelimiting_mmapped.mem;

		const kru_price_t base_price = KRU_LIMIT / instant_limit;
		const kru_price_t max_decay = rate_limit > 1000ll * instant_limit ? base_price :
			(uint64_t) base_price * rate_limit / 1000;

		bool succ = KRU.initialize((struct kru *)ratelimiting->kru, capacity_log, max_decay);
		if (!succ) {
			ratelimiting = NULL;
			ret = kr_error(EINVAL);
			goto fail;
		}

		ratelimiting->log_time = kr_log_period_init(log_period);

		for (size_t i = 0; i < V4_PREFIXES_CNT; i++) {
			ratelimiting->v4_prices[i] = base_price / V4_RATE_MULT[i];
		}

		for (size_t i = 0; i < V6_PREFIXES_CNT; i++) {
			ratelimiting->v6_prices[i] = base_price / V6_RATE_MULT[i];
		}

		ret = mmapped_init_continue(&ratelimiting_mmapped);
		if (ret != 0) goto fail;

		kr_log_info(SYSTEM, "Rate-limiting initialized (%s).\n", (ratelimiting->using_avx2 ? "AVX2" : "generic"));
		return 0;
	} else if (ret == 0) {
		ratelimiting = ratelimiting_mmapped.mem;
		kr_log_info(SYSTEM, "Using existing rate-limiting data (%s).\n", (ratelimiting->using_avx2 ? "AVX2" : "generic"));
		return 0;
	} // else fail

fail:

	kr_log_crit(SYSTEM, "Initialization of shared rate-limiting data failed.\n");
	return ret;
}

void ratelimiting_deinit(void)
{
	mmapped_deinit(&ratelimiting_mmapped);
	ratelimiting = NULL;
}


bool ratelimiting_request_begin(struct kr_request *req)
{
	if (!ratelimiting) return false;
	if (!req->qsource.addr)
		return false;  // don't consider internal requests
	if (req->qsource.price_factor16 == 0)
		return false;  // whitelisted

	// We only do this on pure UDP.  (also TODO if cookies get implemented)
	const bool ip_validated = req->qsource.flags.tcp || req->qsource.flags.tls;
	if (ip_validated) return false;

	const uint32_t time_now = kr_now();

	// classify
	_Alignas(16) uint8_t key[16] = {0, };
	uint8_t limited_prefix;
	if (req->qsource.addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)req->qsource.addr;
		memcpy(key, &ipv6->sin6_addr, 16);

		// compute adjusted prices, using standard rounding
		kru_price_t prices[V6_PREFIXES_CNT];
		for (int i = 0; i < V6_PREFIXES_CNT; ++i) {
			prices[i] = (req->qsource.price_factor16
					* (uint64_t)ratelimiting->v6_prices[i] + (1<<15)) >> 16;
		}
		limited_prefix = KRU.limited_multi_prefix_or((struct kru *)ratelimiting->kru, time_now,
				1, key, V6_PREFIXES, prices, V6_PREFIXES_CNT, NULL);
	} else {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)req->qsource.addr;
		memcpy(key, &ipv4->sin_addr, 4);  // TODO append port?

		// compute adjusted prices, using standard rounding
		kru_price_t prices[V4_PREFIXES_CNT];
		for (int i = 0; i < V4_PREFIXES_CNT; ++i) {
			prices[i] = (req->qsource.price_factor16
					* (uint64_t)ratelimiting->v4_prices[i] + (1<<15)) >> 16;
		}
		limited_prefix = KRU.limited_multi_prefix_or((struct kru *)ratelimiting->kru, time_now,
				0, key, V4_PREFIXES, prices, V4_PREFIXES_CNT, NULL);
	}
	if (!limited_prefix) return false;  // not limited

	// slip: truncating vs dropping
	bool tc =
		(ratelimiting->slip > 1) ?
			((kr_rand_bytes(1) % ratelimiting->slip == 0) ? true : false) :
			((ratelimiting->slip == 1) ? true : false);

	// logging
	if (kr_log_period(ratelimiting->log_period, &ratelimiting->log_time)) {
		kr_log_notice(SYSTEM, "address %s rate-limited on /%d (%s%s)\n",
				kr_straddr(req->qsource.addr), limited_prefix,
				ratelimiting->dry_run ? "dry-run, " : "",
				tc ? "truncated" : "dropped");
	}

	req->ratelimited = true; // we set this even on dry_run
	if (ratelimiting->dry_run) return false;

	// perform limiting
	if (tc) { // TC=1: return truncated reply to force source IP validation
		knot_pkt_t *answer = kr_request_ensure_answer(req);
		if (!answer) { // something bad; TODO: perhaps improve recovery from this
			kr_assert(false);
			return true;
		}
		// at this point the packet should be pretty clear

		// The TC=1 answer is not perfect, as the right RCODE might differ
		// in some cases, but @vcunat thinks that NOERROR isn't really risky here.
		knot_wire_set_tc(answer->wire);
		knot_wire_clear_ad(answer->wire);
		req->state = KR_STATE_DONE;
	} else {
		// no answer
		req->options.NO_ANSWER = true;
		req->state = KR_STATE_FAIL;
	}

	return true;
}
