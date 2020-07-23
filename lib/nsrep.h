/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <netinet/in.h>
#include "lib/utils.h"

#define DEFAULT_LOCAL_STATE_SIZE 10

enum kr_selection_error {
    KR_SELECTION_TIMEOUT,
    KR_SELECTION_REFUSED,
    KR_SELECTION_DNSSEC_ERROR,
    KR_SELECTION_FORMERROR,
};

enum kr_transport_protocol {
    KR_TRANSPORT_UDP,
    KR_TRANSPORT_TCP,
    KR_TRANSPORT_TLS,
    KR_TRANSPORT_NOADDR,
};

struct kr_transport {
    knot_dname_t *name;
    union inaddr address;
    enum kr_transport_protocol protocol;
    unsigned timeout;
};

struct kr_server_selection
{
    void (*choose_transport)(struct kr_query *qry);
    void (*success)(struct kr_query *qry, struct kr_transport transport);
    void (*update_rtt)(struct kr_query *qry, struct kr_transport transport, unsigned rtt);
    void (*error)(struct kr_query *qry, struct kr_transport transport, enum kr_selection_error error);

    void *local_state;
};

// Initialize server selection structure inside qry.
KR_EXPORT
void kr_server_selection_init(struct kr_query *qry);
