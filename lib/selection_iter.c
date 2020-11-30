/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/selection_iter.h"
#include "lib/selection.h"

#include "lib/generic/trie.h"
#include "lib/generic/pack.h"
#include "lib/zonecut.h"
#include "lib/resolve.h"

#define VERBOSE_MSG(qry, ...) QRVERBOSE((qry), "slct",  __VA_ARGS__)

// To be held per query and locally
struct iter_local_state {
	trie_t *names;
	trie_t *addresses;
	knot_dname_t *zonecut;
	unsigned int generation; /**<< Used to distinguish old and valid records in tries. */
	enum kr_selection_error last_error;
	unsigned int no_ns_addr_count;
};

enum record_state {
	RECORD_UNKNOWN,
	RECORD_RESOLVED,
	RECORD_TRIED
};

// To be held per NS name and locally
struct iter_name_state {
	unsigned int generation;
	enum record_state a_state;
	enum record_state aaaa_state;
};

void update_name_state(struct kr_transport *transport, trie_t *names) {
	if (!transport) {
		return;
	}

	size_t name_len = knot_dname_size(transport->ns_name);
	trie_val_t *val = trie_get_try(names, (char *)transport->ns_name, name_len);

	if (!val) {
		return;
	}

	struct iter_name_state *name_state = (struct iter_name_state *)*val;

	switch (transport->protocol)
	{
	case KR_TRANSPORT_RESOLVE_A:
		name_state->a_state = RECORD_TRIED;
		return;
	case KR_TRANSPORT_RESOLVE_AAAA:
		name_state->aaaa_state = RECORD_TRIED;
		return;
	default:
		return;
	}

}

void iter_local_state_alloc(struct knot_mm *mm, void **local_state) {
	*local_state = mm_alloc(mm, sizeof(struct iter_local_state));
	memset(*local_state, 0, sizeof(struct iter_local_state));
}

struct address_state *get_address_state(struct iter_local_state *local_state, const struct kr_transport *transport) {
	if (!transport) {
		return NULL;
	}

	trie_t *addresses = local_state->addresses;
	uint8_t *address = ip_to_bytes(&transport->address, transport->address_len);

	trie_val_t *address_state = trie_get_try(addresses, (char *)address, transport->address_len);

	if (!address_state) {
		if (transport->deduplicated) {
			// Transport was chosen by a different query
			return NULL;
		}

		assert(0);
	}
	return (struct address_state *)*address_state;
}

bool zonecut_changed(knot_dname_t *new, knot_dname_t *old) {
	return knot_dname_cmp(old, new);
}

void update_state_from_rtt_cache(struct iter_local_state *local_state, struct kr_cache *cache) {
	trie_it_t *it;
	for(it = trie_it_begin(local_state->addresses); !trie_it_finished(it); trie_it_next(it)) {
		size_t address_len;
		uint8_t *address = (uint8_t *)trie_it_key(it, &address_len);
		struct address_state *address_state = (struct address_state *)*trie_it_val(it);

		if (address_state->generation != local_state->generation) {
			// Only look at valid addresses.
			continue;
		}

		address_state->rtt_state = get_rtt_state(address, address_len, cache);
		union inaddr addr;
		bytes_to_ip(address, address_len, &addr);
		const char *ns_str = kr_straddr(&addr.ip);
		if (VERBOSE_STATUS) {
			printf("[slct] rtt of %s is %d, variance is %d\n", ns_str, address_state->rtt_state.srtt, address_state->rtt_state.variance);
		}
	}
	trie_it_free(it);
}


void update_state_from_zonecut(struct iter_local_state *local_state, struct kr_zonecut *zonecut, struct knot_mm *mm) {
	bool zcut_changed = false;
	if (local_state->names == NULL || local_state->addresses == NULL) {
		// Local state initialization
		memset(local_state, 0, sizeof(struct iter_local_state));
		local_state->names = trie_create(mm);
		local_state->addresses = trie_create(mm);
	} else {
		zcut_changed = zonecut_changed(zonecut->name, local_state->zonecut);
	}
	local_state->zonecut = zonecut->name;
	local_state->generation++;

	if (zcut_changed) {
		local_state->no_ns_addr_count = 0;
	}

	trie_it_t *it;
	unsigned int current_generation = local_state->generation;

	for(it = trie_it_begin(zonecut->nsset); !trie_it_finished(it); trie_it_next(it)) {
		knot_dname_t *dname = (knot_dname_t *)trie_it_key(it, NULL);
		pack_t *addresses = (pack_t *)*trie_it_val(it);

		trie_val_t *val = trie_get_ins(local_state->names, (char *)dname, knot_dname_size(dname));
		if (!*val) {
			// We encountered this name for the first time
			*val = mm_alloc(mm, sizeof(struct iter_name_state));
			memset(*val, 0, sizeof(struct iter_name_state));
		}
		struct iter_name_state *name_state = *(struct iter_name_state **)val;
		name_state->generation = current_generation;

		if (zcut_changed) {
			// Set name as unresolved as they might have fallen out of cache (TTL expired)
			name_state->a_state = RECORD_UNKNOWN;
			name_state->aaaa_state = RECORD_UNKNOWN;
		}

		if (addresses->len > 0) {
			// We have some addresses to work with, let's iterate over them
			for(uint8_t *obj = pack_head(*addresses); obj != pack_tail(*addresses); obj = pack_obj_next(obj)) {
				uint8_t *address = pack_obj_val(obj);
				size_t address_len = pack_obj_len(obj);
				trie_val_t *tval = trie_get_ins(local_state->addresses, (char *)address, address_len);
				if (!*tval) {
					// We have have not seen this address before.
					*tval = mm_alloc(mm, sizeof(struct address_state));
					memset(*tval, 0, sizeof(struct address_state));
				}
				struct address_state *address_state = (*(struct address_state **)tval);
				address_state->generation = current_generation;
				address_state->ns_name = dname;

				if (address_len == sizeof(struct in_addr)) {
					name_state->a_state = RECORD_RESOLVED;
				} else if (address_len == sizeof(struct in6_addr)) {
					name_state->aaaa_state = RECORD_RESOLVED;
				}
			}
		}
	}

	trie_it_free(it);
}

// Loop over trie of addresses and update per-address properties
void update_address_states(struct iter_local_state *local_state, struct kr_query *qry) {
	trie_it_t *it;
	for(it = trie_it_begin(local_state->addresses); !trie_it_finished(it); trie_it_next(it)) {
		size_t address_len;
		uint8_t* address = (uint8_t *)trie_it_key(it, &address_len);

		union inaddr tmp_address;
		bytes_to_ip(address, address_len, &tmp_address);

		struct address_state *address_state = (struct address_state *)*trie_it_val(it);
		if (address_state->generation != local_state->generation) {
			// Only look at valid addresses.
			continue;
		}
		check_tls_capable(address_state, qry->request, &tmp_address.ip);
		/* TODO: uncomment this once we actually use the information it collects
		check_tcp_connections(address_state, qry->request, &tmp_address.ip);
		*/
		check_network_settings(address_state, address_len, qry->flags.NO_IPV4, qry->flags.NO_IPV6);
	}
	trie_it_free(it);
}

int get_valid_addresses(struct iter_local_state *local_state, struct choice choices[]) {
	unsigned count = 0;
	trie_it_t *it;
	for(it = trie_it_begin(local_state->addresses); !trie_it_finished(it); trie_it_next(it)) {
		size_t address_len;
		uint8_t* address = (uint8_t *)trie_it_key(it, &address_len);
		struct address_state *address_state = (struct address_state *)*trie_it_val(it);
		if (address_state->generation == local_state->generation && !address_state->unrecoverable_errors) {
			choices[count] = (struct choice){
				.address = address,
				.address_len = address_len,
				.address_state = address_state,
			};
			count++;
		}
	}
	trie_it_free(it);
	return count;
}

int get_resolvable_names(struct iter_local_state *local_state, struct to_resolve resolvable[], struct kr_query *qry) {
	// . DNSKEY must be fetched from root hints, no A/AAAA resolution is possible.
	if (qry->sname[0] == '\0' && qry->stype == KNOT_RRTYPE_DNSKEY) {
		return 0;
	}

	unsigned count = 0;
	trie_it_t *it;
	for(it = trie_it_begin(local_state->names); !trie_it_finished(it); trie_it_next(it)) {
		struct iter_name_state *name_state = *(struct iter_name_state **)trie_it_val(it);
		if (name_state->generation == local_state->generation) {
			knot_dname_t *name = (knot_dname_t *)trie_it_key(it, NULL);
			/* FIXME: kr_rplan_satisfies(qry,…) should have been here, but this leads to failures on 
			 * iter_ns_badip.rpl, this is because the test requires the resolver to switch to parent
			 * side after a record in cache expires. Only way to do this in the current zonecut setup is
			 * to requery the same query twice in the row. So we have to allow that and only check the 
			 * rplan from parent upwards.
			 */
			bool a_in_rplan = kr_rplan_satisfies(qry->parent, name, KNOT_CLASS_IN, KNOT_RRTYPE_A);
			bool aaaa_in_rplan = kr_rplan_satisfies(qry->parent, name, KNOT_CLASS_IN, KNOT_RRTYPE_AAAA);
			if (name_state->a_state == RECORD_UNKNOWN && !qry->flags.NO_IPV4 && !a_in_rplan) {
				resolvable[count++] = (struct to_resolve){name, KR_TRANSPORT_RESOLVE_A};
			}
			if (name_state->aaaa_state == RECORD_UNKNOWN && !qry->flags.NO_IPV6 && !aaaa_in_rplan) {
				resolvable[count++] = (struct to_resolve){name, KR_TRANSPORT_RESOLVE_AAAA};
			}
		}
	}
	trie_it_free(it);
	return count;
}

void iter_choose_transport(struct kr_query *qry, struct kr_transport **transport) {
	struct knot_mm *mempool = qry->request->rplan.pool;
	struct iter_local_state *local_state = (struct iter_local_state *)qry->server_selection.local_state->private;

	update_state_from_zonecut(local_state, &qry->zone_cut, mempool);
	update_state_from_rtt_cache(local_state, &qry->request->ctx->cache);

	update_address_states(local_state, qry);

	struct choice choices[trie_weight(local_state->addresses)];
	struct to_resolve resolvable[2*trie_weight(local_state->names)];

	// Filter valid addresses and names from the tries
	int choices_len = get_valid_addresses(local_state, choices);
	int resolvable_len = get_resolvable_names(local_state, resolvable, qry);

	if (choices_len || resolvable_len) {
		bool tcp = qry->flags.TCP | qry->server_selection.local_state->truncated;
		*transport = choose_transport(choices, choices_len, resolvable, resolvable_len, qry->server_selection.local_state->timeouts, mempool, tcp, NULL);
	} else {
		*transport = NULL;
		// Last selected server had broken DNSSEC and now we have no more servers to ask
		// we signal this to the rest of resolver by setting DNSSEC_BOGUS flag
		if (local_state->last_error == KR_SELECTION_DNSSEC_ERROR) {
			qry->flags.DNSSEC_BOGUS = true;
		}
	}

	// Take a note if we tried resolving this name, so we don't try it again
	update_name_state(*transport, local_state->names);

	bool nxnsattack_mitigation = false;
	enum kr_transport_protocol proto = *transport ? (*transport)->protocol : -1;
	if (proto == KR_TRANSPORT_RESOLVE_A || proto == KR_TRANSPORT_RESOLVE_AAAA) {
		if (++local_state->no_ns_addr_count > KR_COUNT_NO_NSADDR_LIMIT) {
			*transport = NULL;
			nxnsattack_mitigation = true;
		}
	}

	WITH_VERBOSE(qry) {
		KR_DNAME_GET_STR(zonecut_str, qry->zone_cut.name);
		if (*transport) {
			KR_DNAME_GET_STR(ns_name, (*transport)->ns_name);
			const char *ns_str = kr_straddr(&(*transport)->address.ip);
			if (proto != KR_TRANSPORT_RESOLVE_A && proto != KR_TRANSPORT_RESOLVE_AAAA) {
				VERBOSE_MSG(qry,
				"=> id: '%05u' choosing: '%s'@'%s' with timeout %u ms zone cut: '%s'%s\n",
				qry->id, ns_name, ns_str ? ns_str : "", (*transport)->timeout, zonecut_str, (*transport)->safe_mode ? " SAFEMODE" : "");
			} else {
				const char *ip_version = (proto == KR_TRANSPORT_RESOLVE_A) ? "A" : "AAAA";
				VERBOSE_MSG(qry,
				"=> id: '%05u' choosing to resolve %s: '%s' zone cut: '%s'\n",
				qry->id, ip_version, ns_name, zonecut_str);
			}
		} else {
			 VERBOSE_MSG(qry,
			"=> id: '%05u' no suitable transport, zone cut: '%s'%s\n",
			qry->id, zonecut_str, nxnsattack_mitigation ? " (stopped due to mitigation for NXNSAttack CVE-2020-12667)" : "");
		}
	}
}

void iter_success(struct kr_query *qry, const struct kr_transport *transport) {
}

void iter_error(struct kr_query *qry, const struct kr_transport *transport, enum kr_selection_error sel_error) {
	if (!qry->server_selection.initialized) {
		return;
	}
	struct iter_local_state *local_state = qry->server_selection.local_state->private;
	struct address_state *addr_state = get_address_state(local_state, transport);
	local_state->last_error = sel_error;
	error(qry, addr_state, transport, sel_error);
}

void iter_update_rtt(struct kr_query *qry, const struct kr_transport *transport, unsigned rtt) {
	if (!qry->server_selection.initialized) {
		return;
	}
	struct iter_local_state *local_state = qry->server_selection.local_state->private;
	struct address_state *addr_state = get_address_state(local_state, transport);
	update_rtt(qry, addr_state, transport, rtt);
}
