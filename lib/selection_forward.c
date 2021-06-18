/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/selection_forward.h"
#include "lib/resolve.h"

#define VERBOSE_MSG(qry, ...) QRVERBOSE((qry), SELECTION, __VA_ARGS__)

#define FORWARDING_TIMEOUT 2000

struct forward_local_state {
	inaddr_array_t *targets;
	struct address_state *addr_states;
	/** Index of last choice in the targets array, used for error reporting. */
	size_t last_choice_index;
};

void forward_local_state_alloc(struct knot_mm *mm, void **local_state,
			       struct kr_request *req)
{
	kr_require(req->selection_context.forwarding_targets.at);
	*local_state = mm_calloc(mm, 1, sizeof(struct forward_local_state));

	struct forward_local_state *forward_state = *local_state;
	forward_state->targets = &req->selection_context.forwarding_targets;

	forward_state->addr_states = mm_calloc(mm, forward_state->targets->len,
						sizeof(struct address_state));
}

void forward_choose_transport(struct kr_query *qry,
			      struct kr_transport **transport)
{
	struct forward_local_state *local_state =
		qry->server_selection.local_state->private;
	struct choice choices[local_state->targets->len];
	int valid = 0;

	for (int i = 0; i < local_state->targets->len; i++) {
		union inaddr *address = &local_state->targets->at[i];
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
			kr_assert(false);
			*transport = NULL;
			return;
		}

		struct address_state *addr_state = &local_state->addr_states[i];
		addr_state->ns_name = (knot_dname_t *)"";

		update_address_state(addr_state, address, addr_len, qry);

		if (addr_state->generation == -1) {
			continue;
		}
		addr_state->choice_array_index = i;

		choices[valid++] = (struct choice){
			.address = *address,
			.address_len = addr_len,
			.address_state = addr_state,
			.port = port,
		};
	}

	bool tcp = qry->flags.TCP || qry->server_selection.local_state->truncated;
	*transport =
		select_transport(choices, valid, NULL, 0,
				 qry->server_selection.local_state->timeouts,
				 &qry->request->pool, tcp,
				 &local_state->last_choice_index);
	if (*transport) {
		/* Set static timeout for forwarding; there is no point in this
		 * being dynamic since the RTT of a packet to forwarding target
		 * says nothing about the network RTT of said target, since
		 * it is doing resolution upstream. */
		(*transport)->timeout = FORWARDING_TIMEOUT;
		/* Try to avoid TCP in STUB case.  It seems better for common use cases. */
		if (qry->flags.STUB && !tcp && (*transport)->protocol == KR_TRANSPORT_TCP)
			(*transport)->protocol = KR_TRANSPORT_UDP;
		/* We need to propagate this to flags since it's used in other
		 * parts of the resolver (e.g. logging and stats). */
		qry->flags.TCP = (*transport)->protocol == KR_TRANSPORT_TCP
			      || (*transport)->protocol == KR_TRANSPORT_TLS;
	}
}

void forward_error(struct kr_query *qry, const struct kr_transport *transport,
		   enum kr_selection_error sel_error)
{
	if (!qry->server_selection.initialized) {
		return;
	}
	struct forward_local_state *local_state =
		qry->server_selection.local_state->private;
	struct address_state *addr_state =
		&local_state->addr_states[local_state->last_choice_index];
	error(qry, addr_state, transport, sel_error);
}

void forward_update_rtt(struct kr_query *qry,
			const struct kr_transport *transport, unsigned rtt)
{
	if (!qry->server_selection.initialized) {
		return;
	}

	if (!transport) {
		return;
	}

	struct forward_local_state *local_state =
		qry->server_selection.local_state->private;
	struct address_state *addr_state =
		&local_state->addr_states[local_state->last_choice_index];

	update_rtt(qry, addr_state, transport, rtt);
}
