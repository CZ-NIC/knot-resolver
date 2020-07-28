/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/utils.h"

enum kr_selection_error {
    KR_SELECTION_TIMEOUT,
    KR_SELECTION_TLS_HANDSHAKE_FAILED,
    KR_SELECTION_TCP_CONNECT_FAILED,
    KR_SELECTION_TCP_CONNECT_TIMEOUT,

    KR_SELECTION_REFUSED,
    KR_SELECTION_SERVFAIL,
    KR_SELECTION_FORMERROR,
    KR_SELECTION_NOTIMPL,
    KR_SELECTION_OTHER_RCODE,
    KR_SELECTION_TRUNCATED,

    KR_SELECTION_DNSSEC_ERROR,

};

enum kr_transport_protocol {
    KR_TRANSPORT_NOADDR = 0,
    KR_TRANSPORT_UDP,
    KR_TRANSPORT_TCP,
    KR_TRANSPORT_TLS,
};

struct kr_transport {
    knot_dname_t *name;
    union inaddr address;
    enum kr_transport_protocol protocol;
    unsigned timeout;
};

struct kr_server_selection
{
    void (*choose_transport)(struct kr_query *qry, struct kr_transport **transport);
    void (*success)(struct kr_query *qry, const struct kr_transport *transport);
    void (*update_rtt)(struct kr_query *qry, const struct kr_transport *transport, unsigned rtt);
    void (*error)(struct kr_query *qry, const struct kr_transport *transport, enum kr_selection_error error);

    void *local_state;
};

// Initialize server selection structure inside qry.
KR_EXPORT
void kr_server_selection_init(struct kr_query *qry);
