/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/defines.h"
#include "lib/generic/map.h"
#include <libknot/rrset.h>

/**
 * Find TA RRSet by name.
 * @param  trust_anchors trust store
 * @param  name          name of the TA
 * @return non-empty RRSet or NULL
 */
KR_EXPORT
knot_rrset_t *kr_ta_get(map_t *trust_anchors, const knot_dname_t *name);

/**
 * Add TA to trust store. DS or DNSKEY types are supported.
 * @param  trust_anchors trust store
 * @param  name          name of the TA
 * @param  type          RR type of the TA (DS or DNSKEY)
 * @param  ttl           
 * @param  rdata         
 * @param  rdlen         
 * @return 0 or an error
 */
KR_EXPORT
int kr_ta_add(map_t *trust_anchors, const knot_dname_t *name, uint16_t type,
               uint32_t ttl, const uint8_t *rdata, uint16_t rdlen);

struct kr_context;

/**
 * Return pointer to the name of the closest positive trust anchor or NULL.
 *
 * "Closest" means on path towards root.  Closer negative anchor results into NULL.
 * @param type serves as a shorthand because DS needs to start one level higher.
 */
KR_EXPORT KR_PURE
const knot_dname_t * kr_ta_closest(const struct kr_context *ctx, const knot_dname_t *name,
				   const uint16_t type);

/**
 * Remove TA from trust store.
 * @param  trust_anchors trust store
 * @param  name          name of the TA
 * @return 0 or an error
 */
KR_EXPORT
int kr_ta_del(map_t *trust_anchors, const knot_dname_t *name);

/**
 * Clear trust store.
 * @param trust_anchors trust store
 */
KR_EXPORT
void kr_ta_clear(map_t *trust_anchors);

