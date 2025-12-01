/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "categories.h"

#include <libknot/libknot.h>
#include "lib/utils.h"
#include "lib/cache/top.h"
#include "lib/kru.h"
#include "utils/cache_gc/db.h"

static inline int load2cat(uint16_t load)  // -> 0..64, reversed
{
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

	if (!info->valid) {
		// invalid entries will be evicted first
		return CATEGORIES - 1;
	}

	uint16_t load = kr_cache_top_load(top, key, key_len);
	res = load2cat(load);  // 0..64

	if ((info->rrtype != KNOT_CACHE_RTT) && (info->expires_in <= 0)) {
		// evict all expired before any non-expired (incl. RTT)
		res = res / 2 + 65;  // 65..97
	}
	static_assert(CATEGORIES - 1 > 97, "inssuficient CATEGORIES number");

	if (!kr_log_is_debug(CACHE, NULL)) // skip these computations if not needed
		goto finish;

	const kru_price_t price = kr_cache_top_entry_price(top, info->entry_size);
	const double accesses = (double)((kru_price_t)load << (KRU_PRICE_BITS - 16)) / price;
	kr_log_debug(CACHE, "cat %02d %6d l %8.1f acc %6ld B %8ld s  %s\n",
		res, load, accesses, info->entry_size, info->expires_in,
		kr_cache_top_strkey(key, key_len)
	);

finish:
	return res;
}
