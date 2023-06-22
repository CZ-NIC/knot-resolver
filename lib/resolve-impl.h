/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include "lib/resolve.h"

#define VERBOSE_MSG(qry, ...) kr_log_q((qry), RESOLVER,  __VA_ARGS__)

/** @internal Macro for iterating module layers. */
#define RESUME_LAYERS(from, r, qry, func, ...) \
    (r)->current_query = (qry); \
	for (size_t i = (from); i < (r)->ctx->modules->len; ++i) { \
		struct kr_module *mod = (r)->ctx->modules->at[i]; \
		if (mod->layer) { \
			struct kr_layer layer = {.state = (r)->state, .api = mod->layer, .req = (r)}; \
			if (layer.api && layer.api->func) { \
				(r)->state = layer.api->func(&layer, ##__VA_ARGS__); \
				/* It's an easy mistake to return error code, for example. */ \
				/* (though we could allow such an overload later) */ \
				if (kr_fails_assert(kr_state_consistent((r)->state))) { \
					(r)->state = KR_STATE_FAIL; \
				} else \
				if ((r)->state == KR_STATE_YIELD) { \
					func ## _yield(&layer, ##__VA_ARGS__); \
					break; \
				} \
			} \
		} \
	} /* Invalidate current query. */ \
	(r)->current_query = NULL

/** @internal Macro for starting module iteration. */
#define ITERATE_LAYERS(req, qry, func, ...) RESUME_LAYERS(0, req, qry, func, ##__VA_ARGS__)

/** Randomize QNAME letter case.
 *
 * This adds 32 bits of randomness at maximum, but that's more than an average domain name length.
 * https://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00
 */
void randomized_qname_case(knot_dname_t * restrict qname, uint32_t secret);

void set_yield(ranked_rr_array_t *array, const uint32_t qry_uid, const bool yielded);
int consume_yield(kr_layer_t *ctx, knot_pkt_t *pkt);

static inline int begin_yield(kr_layer_t *ctx) { return kr_ok(); }
static inline int reset_yield(kr_layer_t *ctx) { return kr_ok(); }
static inline int finish_yield(kr_layer_t *ctx) { return kr_ok(); }
static inline int produce_yield(kr_layer_t *ctx, knot_pkt_t *pkt) { return kr_ok(); }
static inline int checkout_yield(kr_layer_t *ctx, knot_pkt_t *packet, struct sockaddr *dst, int type) { return kr_ok(); }
static inline int answer_finalize_yield(kr_layer_t *ctx) { return kr_ok(); }

