/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/selection_iter.h"
#include "lib/selection.h"

#include "lib/generic/trie.h"
#include "lib/generic/pack.h"
#include "lib/zonecut.h"
#include "lib/resolve.h"

#define VERBOSE_MSG(qry, ...) QRVERBOSE((qry), "nsrep",  __VA_ARGS__)

// To be held per query and locally
struct iter_local_state {
    trie_t *unresolved_names;
    trie_t *addresses;
    unsigned int generation; // Used to distinguish old and valid records in tries
};

// To be held per NS name and locally
struct iter_name_state {
    unsigned int generation;
};

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

void iter_update_state_from_rtt_cache(struct iter_local_state *local_state, struct kr_cache *cache) {
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
            printf("[nsrep] rtt of %s is %d, variance is %d\n", ns_str, address_state->rtt_state.srtt, address_state->rtt_state.variance);
        }
    }
    trie_it_free(it);
}


void iter_update_state_from_zonecut(struct iter_local_state *local_state, struct kr_zonecut *zonecut, struct knot_mm *mm) {
	if (local_state->unresolved_names == NULL || local_state->addresses == NULL) {
        // Local state initialization
        memset(local_state, 0, sizeof(struct iter_local_state));
        local_state->unresolved_names = trie_create(mm);
        local_state->addresses = trie_create(mm);
    }

    local_state->generation++;

    trie_it_t *it;
    unsigned int current_generation = local_state->generation;

    for(it = trie_it_begin(zonecut->nsset); !trie_it_finished(it); trie_it_next(it)) {
        knot_dname_t *dname = (knot_dname_t *)trie_it_key(it, NULL);
        pack_t *addresses = (pack_t *)*trie_it_val(it);

        if (addresses->len == 0) {
            // Name with no address
            trie_val_t *val = trie_get_ins(local_state->unresolved_names, (char *)dname, knot_dname_size(dname));
            if (!*val) {
                // that we encountered for the first time
                *val = mm_alloc(mm, sizeof(struct iter_name_state));
                memset(*val, 0, sizeof(struct iter_name_state));
            }
            (*(struct iter_name_state **)val)->generation = current_generation;
        } else {
            // We have some addresses to work with, let's iterate over them
            for(uint8_t *obj = pack_head(*addresses); obj != pack_tail(*addresses); obj = pack_obj_next(obj)) {
                uint8_t *address = pack_obj_val(obj);
                size_t address_len = pack_obj_len(obj);
                trie_val_t *val = trie_get_ins(local_state->addresses, (char *)address, address_len);
                if (!*val) {
                    // We have have not seen this address before.
                    *val = mm_alloc(mm, sizeof(struct address_state));
                    memset(*val, 0, sizeof(struct address_state));
                }
                struct address_state *address_state = (*(struct address_state **)val);
                address_state->generation = current_generation;
                address_state->name = dname;
            }
        }
    }

    trie_it_free(it);
}

void iter_choose_transport(struct kr_query *qry, struct kr_transport **transport) {
    struct knot_mm *mempool = qry->request->rplan.pool;
    struct iter_local_state *local_state = (struct iter_local_state *)qry->server_selection.local_state;

    iter_update_state_from_zonecut(local_state, &qry->zone_cut, mempool);
    iter_update_state_from_rtt_cache(local_state, &qry->request->ctx->cache);

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
        check_tcp_connections(address_state, qry->request, &tmp_address.ip);
        check_network_settings(address_state, address_len, qry->flags.NO_IPV4, qry->flags.NO_IPV6);
    }
    trie_it_free(it);

    int num_addresses = trie_weight(local_state->addresses);
    int num_unresolved_names = trie_weight(local_state->unresolved_names);

    struct choice choices[num_addresses]; // Some will get unused, oh well
    knot_dname_t *unresolved_names[num_unresolved_names];

    int valid_addresses = 0;
    for(it = trie_it_begin(local_state->addresses); !trie_it_finished(it); trie_it_next(it)) {
        size_t address_len;
        uint8_t* address = (uint8_t *)trie_it_key(it, &address_len);
        struct address_state *address_state = (struct address_state *)*trie_it_val(it);
        if (address_state->generation == local_state->generation) {
            choices[valid_addresses].address = address;
            choices[valid_addresses].address_len = address_len;
            choices[valid_addresses].address_state = address_state;
            valid_addresses++;
        }

    }

    trie_it_free(it);

    int to_resolve = 0;
    for(it = trie_it_begin(local_state->unresolved_names); !trie_it_finished(it); trie_it_next(it)) {
        struct iter_name_state *name_state = *(struct iter_name_state **)trie_it_val(it);
        if (name_state->generation == local_state->generation) {
            knot_dname_t *name = (knot_dname_t *)trie_it_key(it, NULL);
            unresolved_names[to_resolve++] = name;
        }
    }

    trie_it_free(it);

    if (valid_addresses || to_resolve) {
        *transport = choose_transport(choices, valid_addresses, unresolved_names, to_resolve, qry->server_selection.timeouts, mempool, qry->flags.TCP, NULL);
    } else {
        *transport = NULL;
    }

    WITH_VERBOSE(qry) {
        KR_DNAME_GET_STR(zonecut_str, qry->zone_cut.name);
        if (*transport) {
            KR_DNAME_GET_STR(ns_name, (*transport)->name);
            const char *ns_str = kr_straddr(&(*transport)->address.ip);
            VERBOSE_MSG(qry,
			"=> id: '%05u' choosing: '%s'@'%s' with timeout %d ms zone cut: '%s'\n",
			qry->id, ns_name, ns_str ? ns_str : "", (*transport)->timeout, zonecut_str);
        } else {
             VERBOSE_MSG(qry,
			"=> id: '%05u' no suitable transport, zone cut: '%s'\n",
			qry->id, zonecut_str);
        }
	}
}

void iter_success(struct kr_query *qry, const struct kr_transport *transport) {
}

void iter_error(struct kr_query *qry, const struct kr_transport *transport, enum kr_selection_error sel_error) {
    if (!qry->server_selection.initialized) {
        return;
    }
	struct iter_local_state *local_state = qry->server_selection.local_state;
	struct address_state *addr_state = get_address_state(local_state, transport);
	error(qry, addr_state, transport, sel_error);
}

void iter_update_rtt(struct kr_query *qry, const struct kr_transport *transport, unsigned rtt) {
    if (!qry->server_selection.initialized) {
        return;
    }
	struct iter_local_state *local_state = qry->server_selection.local_state;
	struct address_state *addr_state = get_address_state(local_state, transport);
    update_rtt(qry, addr_state, transport, rtt);
}
