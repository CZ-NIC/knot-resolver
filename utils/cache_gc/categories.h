/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "kr_cache_gc.h"
#include "lib/cache/top.h"

#include <libknot/libknot.h>

/* Eviction deciding process:
 *
 * The base concept is assigning numerical category to each cache entry according to its usefulness
 * and removing all from a determined limit category onwards.
 *
 * First _analyze is called to each cache entry accumulating sizes per category in _analysis context;
 * then _summarize is called once to determine limit categories for removal and prefetch cancellation;
 * finally _decide is called for each cache entry.
 * Both _analyze and _decide internally evaluate to which category the entry falls.
 */


typedef uint8_t category_t;
#define CATEGORIES 100           // number of categories

// Info about the current cache entry passed to _analyze and _decide.
struct kr_gc_cat_record_info {
	knot_db_val_t key;
	size_t entry_size;             // amount of bytes occupied in cache by this record
	bool valid;                    // fields further down are valid (ignore them if false)
	int64_t expires_in;            // < 0 => already expired
	uint32_t rrtype;               // RR type or KNOT_CACHE_RTT or KNOT_CACHE_PREFETCH
	uint8_t no_labels;             // 0 == ., 1 == root zone member, 2 == TLD member ...
	uint8_t rank;
	knot_db_val_t prefetch_ekey;   // key of the corresponding E-entry
	size_t prefetch_ekeydata_len;  // size of the E-entry (eh + 1/3 of common parts for NS)
	uint16_t prefetch_min_load;    // minimal load to stay prefetchable
};

// Data accumulated during calls to _analyze and used in _summarize;
// opaque but expected to be zero-initialized.
struct kr_gc_cat_analysis {
	size_t categories_sizes[CATEGORIES];             // sum of _P, _S, _other; computed later in _summary
	size_t categories_sizes_P[CATEGORIES];
	size_t categories_sizes_S[CATEGORIES];
	size_t categories_sizes_other[CATEGORIES];       // (E,1,3)-entries
	size_t categories_sizes_P_ekeydata[CATEGORIES];  // sum of sizes of E-entries corresponding to found P-entries
	size_t categories_sizes_P_ekeydata_eligible[CATEGORIES];  // as previous but only still eligible for prefetch considered
	size_t records;
};

// Result of the _summarize to be used in _decide, also opaque.
struct kr_gc_cat_summary {
	category_t limit_category_remove;   // remove all from this category to (CATEGORIES - 1)
	category_t limit_category_unsched;  // remove P-entries (cancel prefetch) from this category to (_remove - 1)
};


// Per entry analysis, accumulates data in analysis_ctx which should be zero-initialized struct kr_gc_cat_analysis.
void kr_gc_cat_analyze(struct kr_cache_top *top, struct kr_gc_cat_record_info *info, void *analysis_ctx);

// Summarize data accumulated in analysis, print many different statistics
// and compute limit categories to summary based on percents of the used space to be removed and to get prefetch unscheduled.
void kr_gc_cat_summarize(struct kr_gc_cat_analysis *analysis, struct kr_gc_cat_summary *summary,
		uint8_t remove_perc, uint8_t unsched_perc);

// Decide whether to remove the cache entry based on computed summary.
bool kr_gc_cat_decide(struct kr_cache_top *top, struct kr_gc_cat_record_info *info, struct kr_gc_cat_summary *summary);
