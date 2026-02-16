/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "categories.h"

#include <libknot/libknot.h>
#include "lib/utils.h"
#include "lib/cache/impl.h"
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

category_t categorize(struct kr_cache_top *top, struct kr_gc_cat_record_info *info, bool P_eligible_out[static 1])
{
	category_t res; // 0..(CATEGORIES - 1), highest will be dropped first

	if (!info->valid) {
		// invalid entries will be evicted first
		return CATEGORIES - 1;
	}

	if ((info->rrtype == KNOT_CACHE_PREFETCH) && (info->expires_in < 0)) {
		// cancel prefetch for all expired records; updates are performed only before expiration anyway
		res = CATEGORIES - 1;
		goto done;
	}

	const knot_db_val_t *ekey = (info->rrtype == KNOT_CACHE_PREFETCH ? &info->prefetch_ekey : &info->key);
	const uint16_t load = kr_cache_top_load(top, ekey->data, ekey->len);
	res = load2cat(load);  // 0..64

	*P_eligible_out = (info->rrtype == KNOT_CACHE_PREFETCH) && (load >= info->prefetch_min_load);

	if ((info->rrtype != KNOT_CACHE_RTT) && (info->expires_in < 0)) {
		// evict all expired before any non-expired (incl. RTT)
		res = res / 2 + 65;  // 65..97
	}
	static_assert(CATEGORIES - 1 > 97, "inssuficient CATEGORIES number");

	if (!kr_log_is_debug(CACHE, NULL)) // skip these computations if not needed
		return res;

done:
	if (info->rrtype != KNOT_CACHE_PREFETCH) {
		const kru_price_t price = kr_cache_top_entry_price(top, info->entry_size);
		const double accesses = (double)((kru_price_t)load << (KRU_PRICE_BITS - 16)) / price;
		if (info->rrtype != KNOT_CACHE_RTT) {
			kr_log_debug(CACHE, "cat %02d %6d l %8.1f acc %6ld B %8ld s  %s\n",
				res, load, accesses, info->entry_size, info->expires_in,
				kr_cache_top_strkey(info->key.data, info->key.len)
			);
		} else {
			kr_log_debug(CACHE, "cat %02d %6d l %8.1f acc %6ld B             %s\n",
				res, load, accesses, info->entry_size,
				kr_cache_top_strkey(info->key.data, info->key.len)
			);
		}
	} else {
		kr_log_debug(CACHE, "cat %02d                       %6ld B %8ld s  %s\n",
			res, info->entry_size, info->expires_in,
			kr_cache_top_strkey(info->key.data, info->key.len)
		);
	}

	return res;
}

void kr_gc_cat_analyze(struct kr_cache_top *top, struct kr_gc_cat_record_info *info, void *analysis_ctx)
{
	struct kr_gc_cat_analysis *analysis = analysis_ctx;
	bool P_eligible = false;

	category_t cat = categorize(top, info, &P_eligible);
	analysis->categories_sizes[cat] += info->entry_size;
	switch (info->rrtype) {
		case KNOT_CACHE_RTT:
			analysis->categories_sizes_S[cat]          += info->entry_size;
			break;
		case KNOT_CACHE_PREFETCH:
			analysis->categories_sizes_P[cat]          += info->entry_size;
			analysis->categories_sizes_P_ekeydata[cat] += info->prefetch_ekeydata_len;
			analysis->categories_sizes_P_ekeydata_eligible[cat] +=
				(P_eligible ? info->prefetch_ekeydata_len : 0);
			break;
		default:
			analysis->categories_sizes_other[cat]      += info->entry_size;
			break;
	}
	analysis->records++;
}

void kr_gc_cat_summarize(struct kr_gc_cat_analysis *analysis, struct kr_gc_cat_summary *summary,
		uint8_t remove_perc, uint8_t unsched_perc)
{
	//ssize_t amount_tofree = knot_db_lmdb_get_mapsize(db) * cfg->cache_to_be_freed / 100;
	// Mixing ^^ page usage and entry sizes (key+value lengths) didn't work
	// too well, probably due to internal fragmentation after some GC cycles.
	// Therefore let's scale this by the ratio of these two sums.
	size_t cats_sumsize = 0;
	for (int i = 0; i < CATEGORIES; ++i) {
		analysis->categories_sizes[i] =
			analysis->categories_sizes_S[i] +
			analysis->categories_sizes_P[i] +
			analysis->categories_sizes_other[i];
		cats_sumsize += analysis->categories_sizes[i];
	}
	/* use less precise variant to avoid 32-bit overflow */
	size_t amount_tofree = cats_sumsize / 100 * remove_perc;
	size_t amount_tounsched = MAX(cats_sumsize / 100 * unsched_perc, amount_tofree);

	kr_log_debug(CACHE, "tofree: %zd / %zd\n", amount_tofree, cats_sumsize);
	if (VERBOSE_STATUS) {
		for (int i = 0; i < CATEGORIES; i++) {
			if (analysis->categories_sizes[i] > 0) {
				printf("category %.2d size %zu\n", i,
				       analysis->categories_sizes[i]);
			}
		}
	}

	struct sizess { size_t
		// sizes of entries of given type
		P_keep, P_remove,
		S_keep, S_remove,
		E_keep_valid, E_keep_exp, E_remove_valid, E_remove_exp,  // incl. 1 and 3 entries
		remove_invalid, // unrecognized type; hopefully zero

		// sizes of E-entries corresponding to found P-entries based on both entries states
		// (for NS/CNAME/DNAME we count eh size + 1/3 of the key and other common data size)
		P_keep_ekeydata_valid_eligible,
		P_remove_ekeydata_valid_eligible_keep,
		P_remove_ekeydata_valid_eligible_remove,
		P_remove_ekeydata_exp,

		// sums
		P_total, S_total, E_total_valid, E_total_exp,
		P_total_ekeydata_valid_eligible,
		remove, total;
	} sizes = { 0 };

	category_t c = CATEGORIES - 1;
	size_t size = 0;

	// P-entries of all expired E-entries; unrecognized entries; (both to be removed)
		size                                 += analysis->categories_sizes[c];
		sizes.remove_invalid                 += analysis->categories_sizes_other[c];
		sizes.P_remove                       += analysis->categories_sizes_P[c];
		sizes.P_remove_ekeydata_exp          += analysis->categories_sizes_P_ekeydata[c];
		kr_assert(0 ==
			analysis->categories_sizes_S[c]);
		c--;

	// expired E-entries for removal; no (S,P)-entries here
	for (; (size <= amount_tofree) && (c > 64); c--) {
		size                                 += analysis->categories_sizes[c];
		sizes.E_remove_exp                   += analysis->categories_sizes_other[c];
		kr_assert(0 ==
			analysis->categories_sizes_S[c] +
			analysis->categories_sizes_P[c] +
			analysis->categories_sizes_P_ekeydata[c]);
	}

	// valid E-entries for removal with their P-entries; S-entries for removal
	for (; (size <= amount_tofree) && (c > 0); c--) {
		size                                 += analysis->categories_sizes[c];
		sizes.S_remove                       += analysis->categories_sizes_S[c];
		sizes.E_remove_valid                 += analysis->categories_sizes_other[c];
		sizes.P_remove                       += analysis->categories_sizes_P[c];
		sizes.P_remove_ekeydata_valid_eligible_remove +=
			analysis->categories_sizes_P_ekeydata_eligible[c];
	}

	summary->limit_category_remove = c + 1;

	// kept expired E-entries for unscheduling; kept S-entries; no P-entries as all expired are in 99
	for (; (size <= amount_tounsched) && (c > 64); c--) {
		size                                 += analysis->categories_sizes[c];
		sizes.S_keep                         += analysis->categories_sizes_S[c];
		sizes.E_keep_exp                     += analysis->categories_sizes_other[c];
		kr_assert(0 ==
			analysis->categories_sizes_P[c] +
			analysis->categories_sizes_P_ekeydata[c]);
	}

	// kept valid E-entries for unscheduling; corresponding P-entries; kept S-entries
	for (; (size <= amount_tounsched) && (c > 0); c--) {
		size                                 += analysis->categories_sizes[c];
		sizes.S_keep                         += analysis->categories_sizes_S[c];
		sizes.E_keep_valid                   += analysis->categories_sizes_other[c];
		sizes.P_remove                       += analysis->categories_sizes_P[c];
		sizes.P_remove_ekeydata_valid_eligible_keep +=
			analysis->categories_sizes_P_ekeydata_eligible[c];
	}

	summary->limit_category_unsched = c + 1;

	// kept expired E-entries; kept S-entries; no P-entries as all expired are in 99
	for (; c > 64; c--) {
		size                                 += analysis->categories_sizes[c];
		sizes.S_keep                         += analysis->categories_sizes_S[c];
		sizes.E_keep_exp                     += analysis->categories_sizes_other[c];
		kr_assert(0 ==
			analysis->categories_sizes_P[c] +
			analysis->categories_sizes_P_ekeydata[c]);
	}

	// kept valid E-entries; corresponding kept P-entries; kept S-entries
	for (; c > 0; c--) {
		size                                 += analysis->categories_sizes[c];
		sizes.S_keep                         += analysis->categories_sizes_S[c];
		sizes.E_keep_valid                   += analysis->categories_sizes_other[c];
		sizes.P_keep                         += analysis->categories_sizes_P[c];
		sizes.P_keep_ekeydata_valid_eligible += analysis->categories_sizes_P_ekeydata_eligible[c];
	}

	// sums
	sizes.P_total_ekeydata_valid_eligible =
		sizes.P_keep_ekeydata_valid_eligible +
		sizes.P_remove_ekeydata_valid_eligible_keep +
		sizes.P_remove_ekeydata_valid_eligible_remove;
	sizes.E_total_valid =
		sizes.E_keep_valid +
		sizes.E_remove_valid;
	sizes.E_total_exp =
		sizes.E_keep_exp +
		sizes.E_remove_exp;
	sizes.S_total =
		sizes.S_keep +
		sizes.S_remove;
	sizes.P_total =
		sizes.P_keep +
		sizes.P_remove;
	sizes.remove =
		sizes.E_remove_valid +
		sizes.E_remove_exp +
		sizes.P_remove +
		sizes.S_remove +
		sizes.remove_invalid;
	sizes.total =
		sizes.E_total_valid +
		sizes.E_total_exp +
		sizes.P_total +
		sizes.S_total +
		sizes.remove_invalid;
	kr_assert(size == sizes.total);

	const double MB = 1024.0 * 1024.0;
	printf("Canceling prefetch for\n"
			"  %8.2f MB of kept valid RRs eligible for prefetch (limit category %d),\n"
			"  %8.2f MB of expired RRs (not updated in time, incl. those for removal);\n"
			"removing (limit category %d)\n"
			"  %8.2f MB / %8.2f MB of valid RRs eligible for prefetch,\n"
			"  %8.2f MB / %8.2f MB of other valid RRs,\n"
			"  %8.2f MB / %8.2f MB of expired RRs,\n"
			"  %8.2f MB / %8.2f MB of RTT entries,\n"
			"  %8.2f MB / %8.2f MB of prefetch entries (incl. cancellation),\n"
			"  %8.2f MB / %8.2f MB (%zu records) in total.\n",
			sizes.P_remove_ekeydata_valid_eligible_keep / MB, summary->limit_category_unsched,
			sizes.P_remove_ekeydata_exp / MB,
			summary->limit_category_remove,
			sizes.P_remove_ekeydata_valid_eligible_remove / MB, sizes.P_total_ekeydata_valid_eligible / MB,
			(int64_t)(sizes.E_remove_valid - sizes.P_remove_ekeydata_valid_eligible_remove) / MB,   // may be a little negative due to some imprecisions
				(int64_t)(sizes.E_total_valid - sizes.P_total_ekeydata_valid_eligible) / MB,                   // here too
			sizes.E_remove_exp / MB, sizes.E_total_exp / MB,
			sizes.S_remove / MB, sizes.S_total / MB,
			sizes.P_remove / MB, sizes.P_total / MB,
			sizes.remove / MB, sizes.total / MB,
			analysis->records);
}

bool kr_gc_cat_decide(struct kr_cache_top *top, struct kr_gc_cat_record_info *info, struct kr_gc_cat_summary *summary)
{
	bool P_eligible;  // unused
	const category_t cat = categorize(top, info, &P_eligible);

	if (info->rrtype == KNOT_CACHE_PREFETCH) {
		return cat >= summary->limit_category_unsched;
	}

	return cat >= summary->limit_category_remove;
}
