/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/selection.h"

/**
 * If one of the errors set to true is encountered, there is no point in asking this server again.
 */
static const bool UNRECOVERABLE_ERRORS[] = {
	[KR_SELECTION_QUERY_TIMEOUT] = false,
	[KR_SELECTION_TLS_HANDSHAKE_FAILED] = false,
	[KR_SELECTION_TCP_CONNECT_FAILED] = false,
	[KR_SELECTION_TCP_CONNECT_TIMEOUT] = false,
	[KR_SELECTION_REFUSED] = true,
	[KR_SELECTION_SERVFAIL] = true,
	[KR_SELECTION_FORMERROR] = false,
	[KR_SELECTION_NOTIMPL] = true,
	[KR_SELECTION_OTHER_RCODE] = true,
	[KR_SELECTION_TRUNCATED] = false,
	[KR_SELECTION_DNSSEC_ERROR] = true,
	[KR_SELECTION_LAME_DELEGATION] = true,
	[KR_SELECTION_INVALID_DATA] = true,
	[KR_SELECTION_BAD_CNAME] = true,
};

void iter_local_state_alloc(struct knot_mm *mm, void **local_state);
void iter_choose_transport(struct kr_query *qry,
			   struct kr_transport **transport);
void iter_error(struct kr_query *qry, const struct kr_transport *transport,
		enum kr_selection_error sel_error);
void iter_update_rtt(struct kr_query *qry, const struct kr_transport *transport,
		     unsigned rtt);