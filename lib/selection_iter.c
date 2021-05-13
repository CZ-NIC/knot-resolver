/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/selection_iter.h"
#include "lib/selection.h"

#include "lib/generic/trie.h"
#include "lib/generic/pack.h"
#include "lib/zonecut.h"
#include "lib/resolve.h"

#define VERBOSE_MSG(qry, ...) QRVERBOSE((qry), "slct", __VA_ARGS__)

/// To be held per query and locally.  Allocations are in the kr_request's mempool.
struct iter_local_state {
	trie_t *names; /// knot_dname_t -> struct iter_name_state *
	trie_t *addresses; /// IP address -> struct address_state *
	knot_dname_t *zonecut;
	/** Used to distinguish old and valid records in tries. */
	unsigned int generation;
	enum kr_selection_error last_error;
	unsigned int no_ns_addr_count;
};

enum record_state { RECORD_UNKNOWN, RECORD_RESOLVED, RECORD_TRIED };

// To be held per NS name and locally
struct iter_name_state {
	unsigned int generation;
	enum record_state a_state;
	enum record_state aaaa_state;
};

void iter_local_state_alloc(struct knot_mm *mm, void **local_state)
{
	*local_state = mm_calloc(mm, 1, sizeof(struct iter_local_state));
}

static struct address_state *get_address_state(struct iter_local_state *local_state,
						const struct kr_transport *transport)
{
	if (!transport) {
		return NULL;
	}

	uint8_t *address = ip_to_bytes(&transport->address, transport->address_len);
	trie_val_t *address_state = trie_get_try(local_state->addresses, (char *)address,
						 transport->address_len);
	if (!address_state) {
		(void)!kr_assume(transport->deduplicated);
		/* Transport was chosen by a different query. */
		return NULL;
	}
	return *address_state;
}

static void unpack_state_from_zonecut(struct iter_local_state *local_state,
				      struct kr_query *qry)
{
	struct kr_zonecut *zonecut = &qry->zone_cut;
	struct knot_mm *mm = &qry->request->pool;

	bool zcut_changed = false;
	if (local_state->names == NULL || local_state->addresses == NULL) {
		/* Local state initialization. */
		memset(local_state, 0, sizeof(struct iter_local_state));
		local_state->names = trie_create(mm);
		local_state->addresses = trie_create(mm);
	} else {
		zcut_changed = !knot_dname_is_equal(zonecut->name, local_state->zonecut);
	}
	local_state->zonecut = zonecut->name;
	local_state->generation++;

	if (zcut_changed) {
		local_state->no_ns_addr_count = 0;
	}

	trie_it_t *it;
	const unsigned int current_generation = local_state->generation;

	for (it = trie_it_begin(zonecut->nsset); !trie_it_finished(it); trie_it_next(it)) {
		knot_dname_t *dname = (knot_dname_t *)trie_it_key(it, NULL);
		pack_t *addresses = *trie_it_val(it);

		trie_val_t *val = trie_get_ins(local_state->names, (char *)dname,
					       knot_dname_size(dname));
		if (!*val) {
			/* We encountered this name for the first time. */
			*val = mm_calloc(mm, 1, sizeof(struct iter_name_state));
		}
		struct iter_name_state *name_state = *val;
		name_state->generation = current_generation;

		if (zcut_changed) {
			/* Set name as unresolved as they might have fallen out
			 * of cache (TTL expired). */
			name_state->a_state = RECORD_UNKNOWN;
			name_state->aaaa_state = RECORD_UNKNOWN;
		}

		/* Iterate over all addresses of this NS (if any). */
		for (uint8_t *obj = pack_head(*addresses); obj != pack_tail(*addresses);
		     obj = pack_obj_next(obj)) {
			uint8_t *address = pack_obj_val(obj);
			size_t address_len = pack_obj_len(obj);
			trie_val_t *tval = trie_get_ins(local_state->addresses,
							(char *)address,
							address_len);
			if (!*tval) {
				/* We have have not seen this address before. */
				*tval = mm_calloc(mm, 1, sizeof(struct address_state));
			}
			struct address_state *address_state = *tval;
			address_state->generation = current_generation;
			address_state->ns_name = dname;

			if (address_len == sizeof(struct in_addr)) {
				name_state->a_state = RECORD_RESOLVED;
			} else if (address_len == sizeof(struct in6_addr)) {
				name_state->aaaa_state = RECORD_RESOLVED;
			}
			union inaddr tmp_address;
			bytes_to_ip(address, address_len, 0, &tmp_address);
			update_address_state(address_state, &tmp_address, address_len, qry);
		}
	}
	trie_it_free(it);
}

static int get_valid_addresses(struct iter_local_state *local_state,
				struct choice choices[])
{
	unsigned count = 0;
	trie_it_t *it;
	for (it = trie_it_begin(local_state->addresses); !trie_it_finished(it);
	     trie_it_next(it)) {
		size_t address_len;
		uint8_t *address = (uint8_t *)trie_it_key(it, &address_len);
		struct address_state *address_state = *trie_it_val(it);
		if (address_state->generation == local_state->generation &&
		    !address_state->broken) {
			choices[count] = (struct choice){
				.address_len = address_len,
				.address_state = address_state,
			};
			bytes_to_ip(address, address_len, 0, &choices[count].address);
			count++;
		}
	}
	trie_it_free(it);
	return count;
}

static int get_resolvable_names(struct iter_local_state *local_state,
				struct to_resolve resolvable[], struct kr_query *qry)
{
	/* Further resolution is not possible until we get `. DNSKEY` record;
	 * we have to choose one of the known addresses here. */
	if (qry->sname[0] == '\0' && qry->stype == KNOT_RRTYPE_DNSKEY) {
		return 0;
	}

	unsigned count = 0;
	trie_it_t *it;
	for (it = trie_it_begin(local_state->names); !trie_it_finished(it);
	     trie_it_next(it)) {
		struct iter_name_state *name_state = *trie_it_val(it);
		if (name_state->generation != local_state->generation)
			continue;

		knot_dname_t *name = (knot_dname_t *)trie_it_key(it, NULL);
		if (qry->stype == KNOT_RRTYPE_DNSKEY &&
		    knot_dname_in_bailiwick(name, qry->sname) > 0) {
			/* Resolving `domain. DNSKEY` can't trigger the
			 * resolution of `sub.domain. A/AAAA` since it
			 * will cause a cycle. */
			continue;
		}

		/* FIXME: kr_rplan_satisfies(qry,…) should have been here, but this leads to failures on
		 * iter_ns_badip.rpl, this is because the test requires the resolver to switch to parent
		 * side after a record in cache expires. Only way to do this in the current zonecut setup is
		 * to requery the same query twice in the row. So we have to allow that and only check the
		 * rplan from parent upwards.
		 */
		bool a_in_rplan = kr_rplan_satisfies(qry->parent, name,
						     KNOT_CLASS_IN, KNOT_RRTYPE_A);
		bool aaaa_in_rplan = kr_rplan_satisfies(qry->parent, name,
							KNOT_CLASS_IN, KNOT_RRTYPE_AAAA);

		if (name_state->a_state == RECORD_UNKNOWN &&
		    !qry->flags.NO_IPV4 && !a_in_rplan) {
			resolvable[count++] = (struct to_resolve){
				name, KR_TRANSPORT_RESOLVE_A
			};
		}

		if (name_state->aaaa_state == RECORD_UNKNOWN &&
		    !qry->flags.NO_IPV6 && !aaaa_in_rplan) {
			resolvable[count++] = (struct to_resolve){
				name, KR_TRANSPORT_RESOLVE_AAAA
			};
		}
	}
	trie_it_free(it);
	return count;
}

static void update_name_state(knot_dname_t *name, enum kr_transport_protocol type,
			      trie_t *names)
{
	size_t name_len = knot_dname_size(name);
	trie_val_t *val = trie_get_try(names, (char *)name, name_len);

	if (!val) {
		return;
	}

	struct iter_name_state *name_state = (struct iter_name_state *)*val;
	switch (type) {
	case KR_TRANSPORT_RESOLVE_A:
		name_state->a_state = RECORD_TRIED;
		break;
	case KR_TRANSPORT_RESOLVE_AAAA:
		name_state->aaaa_state = RECORD_TRIED;
		break;
	default:
		(void)!kr_assume(false);
	}
}

void iter_choose_transport(struct kr_query *qry, struct kr_transport **transport)
{
	struct knot_mm *mempool = &qry->request->pool;
	struct iter_local_state *local_state =
		(struct iter_local_state *)
			qry->server_selection.local_state->private;

	unpack_state_from_zonecut(local_state, qry);

	struct choice choices[trie_weight(local_state->addresses) + 1/*avoid 0*/];
	/* We may try to resolve A and AAAA record for each name, so therefore
	 * 2*trie_weight(…) is here. */
	struct to_resolve resolvable[2 * trie_weight(local_state->names)];

	// Filter valid addresses and names from the tries
	int choices_len = get_valid_addresses(local_state, choices);
	int resolvable_len = get_resolvable_names(local_state, resolvable, qry);

	if (qry->server_selection.local_state->force_resolve && resolvable_len) {
		choices_len = 0;
		qry->server_selection.local_state->force_resolve = false;
	}

	bool tcp = qry->flags.TCP || qry->server_selection.local_state->truncated;
	*transport = select_transport(choices, choices_len, resolvable, resolvable_len,
				      qry->server_selection.local_state->timeouts,
				      mempool, tcp, NULL);
	bool nxnsattack_mitigation = false;

	if (*transport) {
		switch ((*transport)->protocol) {
		case KR_TRANSPORT_RESOLVE_A:
		case KR_TRANSPORT_RESOLVE_AAAA:
			if (++local_state->no_ns_addr_count > KR_COUNT_NO_NSADDR_LIMIT) {
				*transport = NULL;
				nxnsattack_mitigation = true;
				break;
			}
			/* Note that we tried resolving this name to not try it again. */
			update_name_state((*transport)->ns_name, (*transport)->protocol, local_state->names);
			break;
		case KR_TRANSPORT_TLS:
		case KR_TRANSPORT_TCP:
			/* We need to propagate this to flags since it's used in
			 * other parts of the resolver. */
			qry->flags.TCP = true;
		case KR_TRANSPORT_UDP: /* fall through */
			local_state->no_ns_addr_count = 0;
			break;
		default:
			(void)!kr_assume(false);
			break;
		}

		if (*transport &&
		    (*transport)->protocol == KR_TRANSPORT_TCP &&
		    !qry->server_selection.local_state->truncated &&
		    qry->server_selection.local_state->force_udp) {
			// Last chance on broken TCP.
			(*transport)->protocol = KR_TRANSPORT_UDP;
			qry->flags.TCP = false;
		}
	}

	if (*transport == NULL && local_state->last_error == KR_SELECTION_DNSSEC_ERROR) {
		/* Last selected server had broken DNSSEC and now we have no more
		* servers to ask. We signal this to the rest of resolver by
		* setting DNSSEC_BOGUS flag. */
		qry->flags.DNSSEC_BOGUS = true;
	}

	WITH_VERBOSE(qry)
	{
	KR_DNAME_GET_STR(zonecut_str, qry->zone_cut.name);
	if (*transport) {
		KR_DNAME_GET_STR(ns_name, (*transport)->ns_name);
		const enum kr_transport_protocol proto = *transport ? (*transport)->protocol : -1;
		const char *ns_str = kr_straddr(&(*transport)->address.ip);
		const char *ip_version;
		switch (proto)
		{
		case KR_TRANSPORT_RESOLVE_A:
		case KR_TRANSPORT_RESOLVE_AAAA:
			ip_version = (proto == KR_TRANSPORT_RESOLVE_A) ? "A" : "AAAA";
			VERBOSE_MSG(qry, "=> id: '%05u' choosing to resolve %s: '%s' zone cut: '%s'\n",
				    qry->id, ip_version, ns_name, zonecut_str);
			break;
		default:
			VERBOSE_MSG(qry, "=> id: '%05u' choosing: '%s'@'%s'"
				    " with timeout %u ms zone cut: '%s'\n",
				    qry->id, ns_name, ns_str ? ns_str : "",
				    (*transport)->timeout, zonecut_str);
			break;
		}
	} else {
		const char *nxns_msg = nxnsattack_mitigation
			? " (stopped due to mitigation for NXNSAttack CVE-2020-12667)" : "";
		VERBOSE_MSG(qry, "=> id: '%05u' no suitable transport, zone cut: '%s'%s\n",
			    qry->id, zonecut_str, nxns_msg );
	}
	}
}

void iter_error(struct kr_query *qry, const struct kr_transport *transport,
		enum kr_selection_error sel_error)
{
	if (!qry->server_selection.initialized) {
		return;
	}
	struct iter_local_state *local_state = qry->server_selection.local_state->private;
	struct address_state *addr_state = get_address_state(local_state, transport);
	local_state->last_error = sel_error;
	error(qry, addr_state, transport, sel_error);
}

void iter_update_rtt(struct kr_query *qry, const struct kr_transport *transport,
		     unsigned rtt)
{
	if (!qry->server_selection.initialized) {
		return;
	}
	struct iter_local_state *local_state = qry->server_selection.local_state->private;
	struct address_state *addr_state = get_address_state(local_state, transport);
	update_rtt(qry, addr_state, transport, rtt);
}
