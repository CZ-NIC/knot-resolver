/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/cache/api.h"
#include <uv.h>

typedef int (*kr_cache_prefetch_callback_t)(knot_dname_t *qname, uint16_t qtype);

KR_EXPORT
void kr_cache_prefetch_init(uv_loop_t *loop, kr_cache_prefetch_callback_t callback);

struct entry_h;

struct entry_p {
	uint16_t ekeydata_len;
} __attribute__ ((packed,aligned(1))); // needed by LMDB

// Try scheduling prefetching.
// To be called during write transaction of (key, eh); eh may be modified inside.
KR_EXPORT
void kr_cache_prefetch_sched(knot_db_val_t key, struct entry_h *eh, size_t eh_len, size_t whole_entry_len, uint16_t rrtype);
	// XXX call either directly or from top_access to compute hash just once

// Cancel scheduled prefetching if set. Void if eh is NULL.
KR_EXPORT
void kr_cache_prefetch_unsched(knot_db_val_t key, struct entry_h *eh, uint16_t rrtype);


// Pauses prefetching if defer is busy.
// To be called from defer to announce its state.
KR_EXPORT
void kr_cache_prefetch_defer_busy(bool busy);

KR_EXPORT
void kr_cache_prefetch_parse_pkey(knot_db_val_t pkey, knot_db_val_t *ekey, uint32_t *exp_time);
