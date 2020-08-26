/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/utils.h"

enum kr_selection_error {
    // Network errors
    KR_SELECTION_TIMEOUT,
    KR_SELECTION_TLS_HANDSHAKE_FAILED,
    KR_SELECTION_TCP_CONNECT_FAILED,
    KR_SELECTION_TCP_CONNECT_TIMEOUT,

    // RCODEs
    KR_SELECTION_REFUSED,
    KR_SELECTION_SERVFAIL,
    KR_SELECTION_FORMERROR,
    KR_SELECTION_NOTIMPL,
    KR_SELECTION_OTHER_RCODE,
    KR_SELECTION_TRUNCATED,

    // DNS errors
    KR_SELECTION_DNSSEC_ERROR,
    KR_SELECTION_LAME_DELEGATION,

    KR_SELECTION_NUMBER_OF_ERRORS // Leave this last as it is used as array size.
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
    size_t address_len;
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

KR_EXPORT
int kr_forward_init_target(struct kr_query *qry, size_t number);

KR_EXPORT
int kr_forward_add_target(struct kr_request *req, size_t index, const struct sockaddr *sock);