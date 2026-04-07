/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/cache/api.h"
#include <uv.h>

struct entry_h;

// Data of P-entry in cache.
struct entry_p {
	uint16_t ekeydata_len;
	uint16_t min_load;
	uint32_t exp_time;
} __attribute__ ((packed,aligned(1))); // needed by LMDB

// Data of P-entry incl. those encoded in its key.
struct kr_cache_prefetch_sched {
	knot_db_val_t ekey;   // RRSet record key (E type)
	uint32_t update_time;
	uint16_t rrtype;      // the original type (incl. DNAME/CNAME)
	uint8_t priority;     // accesses normalized to 1B for normal-size records
	struct entry_p *ep;
};


// Callback function invoking RR update.
typedef int (*kr_cache_prefetch_callback_t)(knot_dname_t *qname, uint16_t qtype);

// Initialize update callback and timer handle.
// To be called before initialization from Lua.
KR_EXPORT
void kr_cache_prefetch_callback_init(uv_loop_t *loop, kr_cache_prefetch_callback_t callback);

// Initialize the rest and activate prefetch, to be called from Lua.
KR_EXPORT
void kr_cache_prefetch_init(uint32_t max_access_period_sec, float min_accesses_per_update, int update_before_exp_perc);


// Try scheduling prefetching.
// To be called during LMDB write operation of (key, eh);
// eh may be modified inside and P-record is inserted into cache afterwards, closing previous LMDB write.
KR_EXPORT
void kr_cache_prefetch_schedule(knot_db_val_t key, struct entry_h *eh, size_t eh_len, size_t whole_entry_len, uint16_t rrtype);

// Cancel scheduled prefetching if set. Void if eh is NULL.
// It reads eh and then removes P-record from cache.
KR_EXPORT
void kr_cache_prefetch_unschedule(knot_db_val_t key, const struct entry_h *eh, uint16_t rrtype);


// Pause prefetching if defer is busy.
// To be called from defer to announce its state.
KR_EXPORT
void kr_cache_prefetch_defer_busy(bool busy);


// Encode sched to P-entry key and data.
KR_EXPORT
void kr_cache_prefetch_encode_entry(struct kr_cache_prefetch_sched *sched, knot_db_val_t *pkey, knot_db_val_t *pdata);

// Decode P-entry key and data,
// returns kr_ok() on success.
KR_EXPORT
int kr_cache_prefetch_decode_entry(knot_db_val_t pkey, knot_db_val_t pdata, struct kr_cache_prefetch_sched *sched);
