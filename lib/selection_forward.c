/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/selection_forward.h"
#include "lib/resolve.h"

#define VERBOSE_MSG(qry, ...) QRVERBOSE((qry), "nsrep",  __VA_ARGS__)

struct forward_local_state {
    union inaddr *targets;
    size_t target_num;
    struct address_state *addr_states;
    size_t last_choice_index;
};

void forward_local_state_init(struct knot_mm *mm, void **local_state, struct kr_request *req) {
    assert(req->selection_context.forwarding_targets);
    *local_state = mm_alloc(mm, sizeof(struct forward_local_state));
    memset(*local_state, 0, sizeof(struct forward_local_state));

    struct forward_local_state *forward_state = (struct forward_local_state *)*local_state;
    forward_state->targets = req->selection_context.forwarding_targets;
    forward_state->target_num = req->selection_context.forward_targets_num;

    forward_state->addr_states = mm_alloc(mm, sizeof(struct address_state) * forward_state->target_num);
    memset(forward_state->addr_states, 0, sizeof(struct address_state) * forward_state->target_num);
}

void forward_choose_transport(struct kr_query *qry, struct kr_transport **transport) {
    struct forward_local_state *local_state = qry->server_selection.local_state;
    struct choice choices[local_state->target_num];
    int valid = 0;

    for (int i = 0; i < local_state->target_num; i++) {
        union inaddr *address = &local_state->targets[i];
        size_t addr_len;
        switch (address->ip.sa_family) {
            case AF_INET:
                addr_len = sizeof(struct in_addr);
                break;
            case AF_INET6:
                addr_len = sizeof(struct in6_addr);
                break;
            default:
                assert(0);
        }

        struct address_state *addr_state = &local_state->addr_states[i];
        addr_state->name = (knot_dname_t *)"";
        check_tls_capable(addr_state, qry->request, &address->ip);
        check_tcp_connections(addr_state, qry->request, &address->ip);
        check_network_settings(addr_state, addr_len, qry->flags.NO_IPV4, qry->flags.NO_IPV6);

        if(addr_state->generation == -1) {
            continue;
        }
        addr_state->forward_index = i;

        addr_state->rtt_state = get_rtt_state(ip_to_bytes(address, addr_len), addr_len, &qry->request->ctx->cache);
        const char *ns_str = kr_straddr(&address->ip);
        if (VERBOSE_STATUS) {
            printf("[nsrep] rtt of %s is %d, variance is %d\n", ns_str, addr_state->rtt_state.srtt, addr_state->rtt_state.variance);
        }

        choices[valid++] = (struct choice){
            .address = ip_to_bytes(address, addr_len),
            .address_len = addr_len,
            .address_state = addr_state,
        };
    }

    *transport = choose_transport(choices, valid, NULL, 0, &qry->request->pool, qry->flags.TCP, &local_state->last_choice_index);
}

void forward_success(struct kr_query *qry, const struct kr_transport *transport) {
    return;
}

void forward_error(struct kr_query *qry, const struct kr_transport *transport, enum kr_selection_error sel_error) {
    struct forward_local_state *local_state = qry->server_selection.local_state;
	struct address_state *addr_state = &local_state->addr_states[local_state->last_choice_index];
}

void forward_update_rtt(struct kr_query *qry, const struct kr_transport *transport, unsigned rtt) {
    if (!transport) {
        return;
    }

	struct forward_local_state *local_state = qry->server_selection.local_state;
	struct address_state *addr_state = &local_state->addr_states[local_state->last_choice_index];

    update_rtt(qry, addr_state, transport, rtt);
}