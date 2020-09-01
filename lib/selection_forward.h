/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/selection.h"
#include "lib/resolve.h"

void forward_local_state_alloc(struct knot_mm *mm, void **local_state, struct kr_request *req);
void forward_choose_transport(struct kr_query *qry, struct kr_transport **transport);
void forward_success(struct kr_query *qry, const struct kr_transport *transport);
void forward_error(struct kr_query *qry, const struct kr_transport *transport, enum kr_selection_error sel_error);
void forward_update_rtt(struct kr_query *qry, const struct kr_transport *transport, unsigned rtt);