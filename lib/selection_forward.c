/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/selection_forward.h"
#include "lib/resolve.h"

#define VERBOSE_MSG(qry, ...) QRVERBOSE((qry), "slct",  __VA_ARGS__)

#define FORWARDING_TIMEOUT 2000

struct forward_local_state {
	union inaddr *targets;
	size_t targets_count;
	struct address_state *addr_states;
	size_t last_choice_index; /**< Index of last choice in the targets array, used for error reporting. */
};

void forward_local_state_alloc(struct knot_mm *mm, void **local_state, struct kr_request *req) {
	assert(req->selection_context.forwarding_targets);
	*local_state = mm_alloc(mm, sizeof(struct forward_local_state));
	memset(*local_state, 0, sizeof(struct forward_local_state));

	struct forward_local_state *forward_state = (struct forward_local_state *)*local_state;
	forward_state->targets = req->selection_context.forwarding_targets;
	forward_state->targets_count = req->selection_context.forward_targets_count;

	forward_state->addr_states = mm_alloc(mm, sizeof(struct address_state) * forward_state->targets_count);
	memset(forward_state->addr_states, 0, sizeof(struct address_state) * forward_state->targets_count);
}

void forward_choose_transport(struct kr_query *qry, struct kr_transport **transport) {
	struct forward_local_state *local_state = qry->server_selection.local_state->private;
	struct choice choices[local_state->targets_count];
	int valid = 0;

	for (int i = 0; i < local_state->targets_count; i++) {
		union inaddr *address = &local_state->targets[i];
		size_t addr_len;
		uint16_t port;
		switch (address->ip.sa_family) {
			case AF_INET:
				port = ntohs(address->ip4.sin_port);
				addr_len = sizeof(struct in_addr);
				break;
			case AF_INET6:
				port = ntohs(address->ip6.sin6_port);
				addr_len = sizeof(struct in6_addr);
				break;
			default:
				assert(0);
		}

		struct address_state *addr_state = &local_state->addr_states[i];
		addr_state->ns_name = (knot_dname_t *)"";
		check_tls_capable(addr_state, qry->request, &address->ip);
		/* TODO: uncomment this once we actually use the information it collects
		check_tcp_connections(addr_state, qry->request, &address->ip);
		*/
		check_network_settings(addr_state, addr_len, qry->flags.NO_IPV4, qry->flags.NO_IPV6);

		if(addr_state->generation == -1) {
			continue;
		}
		addr_state->choice_array_index = i;

		addr_state->rtt_state = get_rtt_state(ip_to_bytes(address, addr_len), addr_len, &qry->request->ctx->cache);
		const char *ns_str = kr_straddr(&address->ip);
		if (VERBOSE_STATUS) {
			printf("[nsrep] rtt of %s is %d, variance is %d\n", ns_str, addr_state->rtt_state.srtt, addr_state->rtt_state.variance);
		}

		choices[valid++] = (struct choice){
			.address = ip_to_bytes(address, addr_len),
			.address_len = addr_len,
			.address_state = addr_state,
			.port = port,
		};
	}

	bool tcp = qry->flags.TCP | qry->server_selection.local_state->truncated;
	*transport = select_transport(choices, valid, NULL, 0, qry->server_selection.local_state->timeouts, &qry->request->pool, tcp, &local_state->last_choice_index);
	if (*transport) {
		/* Set static timeout for forwarding; there is no point in this being dynamic since the RTT
		 * of a packet to forwarding target says nothing about the network RTT of said target, since
		 * it is doing resolution upstream. */
		(*transport)->timeout = FORWARDING_TIMEOUT;
		// We need to propagate this to flags since it's used in other parts of the resolver (e.g. logging and stats)
		qry->flags.TCP = tcp;
	}
}

void forward_error(struct kr_query *qry, const struct kr_transport *transport, enum kr_selection_error sel_error) {
	if (!qry->server_selection.initialized) {
		return;
	}
	struct forward_local_state *local_state = qry->server_selection.local_state->private;
	struct address_state *addr_state = &local_state->addr_states[local_state->last_choice_index];
	error(qry, addr_state, transport, sel_error);
}

void forward_update_rtt(struct kr_query *qry, const struct kr_transport *transport, unsigned rtt) {
	if (!qry->server_selection.initialized) {
		return;
	}

	if (!transport) {
		return;
	}

	struct forward_local_state *local_state = qry->server_selection.local_state->private;
	struct address_state *addr_state = &local_state->addr_states[local_state->last_choice_index];

	update_rtt(qry, addr_state, transport, rtt);
}