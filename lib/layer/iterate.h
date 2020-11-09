/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/layer.h"
#include "lib/rplan.h"

/* Packet classification. */
enum {
	PKT_NOERROR   = 1 << 0, /* Positive response */
	PKT_NODATA    = 1 << 1, /* No data response */
	PKT_NXDOMAIN  = 1 << 2, /* Negative response */
	PKT_REFUSED   = 1 << 3, /* Refused response */
	PKT_ERROR     = 1 << 4  /* Bad message */
};

/** Classify response by type. */
KR_EXPORT
int kr_response_classify(const knot_pkt_t *pkt);

/** Make next iterative query. */
KR_EXPORT
int kr_make_query(struct kr_query *query, knot_pkt_t *pkt);
