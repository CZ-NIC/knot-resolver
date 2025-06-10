/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "categories.h"

#include <libknot/libknot.h>
#include "lib/utils.h"
#include "lib/cache/top.h"
#include "utils/cache_gc/db.h"

static bool rrtype_is_infrastructure(uint16_t r)  // currently unused
{
	switch (r) {
	case KNOT_RRTYPE_NS:
	case KNOT_RRTYPE_DS:
	case KNOT_RRTYPE_DNSKEY:
	case KNOT_RRTYPE_A:
	case KNOT_RRTYPE_AAAA:
		return true;
	default:
		return false;
	}
}

static unsigned int get_random(int to)  // currently unused
{
	// We don't need these to be really unpredictable,
	// but this should be cheap enough not to be noticeable.
	return kr_rand_bytes(1) % to;
}

static inline int load2cat(uint16_t load) { // 0..64, reversed
	const uint32_t load32 = ((uint32_t)load << 16) | 0xFFFF;
	const int leading_zeroes = __builtin_clz(load32);  // 0..16
	const int logss2 =  //  0, 4, 6, 8..64; approx of log with base 2^{1/4}
		4 * (16 - leading_zeroes) +             // 4 * floor(log2(load32 >> 15))
		(load32 >> (29 - leading_zeroes)) - 7;  // partition rounded ranges linearly
	const int lin_log = load <= logss2 ? load : logss2;  // 0..64; linear from the beginning then logarithmic
	return 64 - lin_log;  // lowest load -> highest cat
}

category_t kr_gc_categorize(struct kr_cache_top *top, gc_record_info_t * info, void *key, size_t key_len)
{
	category_t res; // 0..(CATEGORIES - 1), highest will be dropped first

	if (!info->valid)
		return CATEGORIES - 1;

	uint16_t load = kr_cache_top_load(top, key, key_len);
	res = load2cat(load);  // 0..64

	// TODO check/reconsider penalties
	if (info->rrtype == KNOT_CACHE_RTT) {
		// TODO same priority, or prioritize this
	} else {
		if (info->entry_size > 300) {
			// penalty for big answers
			res += 4;  // ~1 half-life
		}
		if (info->expires_in <= 0) {
			// penalty for expired
			res += 28;  // ~7 half-lifes
		}
	}
	static_assert(CATEGORIES - 1 > 64 + 4 + 28);

	return res;
}
