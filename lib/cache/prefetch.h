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

KR_EXPORT
uint16_t kr_cache_prefetch_sched(struct kr_request *req, knot_db_val_t key, struct entry_h *eh);
	// XXX call either directly or from top_access to compute hash just once

// Pauses prefetching if deferred packets exist.
// To be called from defer to announce its state.
void kr_cache_prefetch_defer_state(bool waiting_packets); // TODO
