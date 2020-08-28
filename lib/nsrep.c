#include <libknot/dname.h>

#include "lib/nsrep.h"
#include "lib/generic/lru.h"
#include "lib/generic/pack.h"
#include "lib/generic/trie.h"
#include "lib/rplan.h"
#include "lib/cache/api.h"
#include "lib/resolve.h"

#include "daemon/worker.h"
#include "daemon/tls.h"

#include "lib/utils.h"

#define VERBOSE_MSG(qry, ...) QRVERBOSE((qry), "nsrep",  __VA_ARGS__)

/** @internal Macro to set address structure. */
#define ADDR_SET(sa, family, addr, len, port) do {\
    	memcpy(&sa ## _addr, (addr), (len)); \
    	sa ## _family = (family); \
	sa ## _port = htons(port); \
} while (0)

// To be held per IP address in the global LMDB cache
struct rtt_state {
    int32_t srtt;
    int32_t variance;
};

// To be held per query and locally
struct iter_local_state {
    trie_t *unresolved_names;
    trie_t *addresses;
    unsigned int generation; // Used to distinguish old and valid records in tries
    knot_dname_t *zonecut_name;
};

// To be held per NS name and locally
struct iter_name_state {
    unsigned int generation;
};

// To be held per IP address and locally
struct iter_address_state {
    unsigned int generation;
    struct rtt_state rtt_state;
    knot_dname_t *name;
    bool tls_capable : 1;
    bool tcp_waiting : 1;
    bool tcp_connected : 1;

	int success_count;
    int error_count;
	int errors[KR_SELECTION_NUMBER_OF_ERRORS];
};

struct forward_local_state {
    struct sockaddr *targets;
    size_t target_num;
};

// Array of these is one of inputs for the actual selection algorithm (`iter_get_best_transport`)
struct choice {
    uint8_t *address;
    size_t address_len;
    struct iter_address_state *address_state;
};



/* Simple cache interface follows */

#define KEY_PREFIX 'S'

void *prefix_key(const uint8_t *ip, size_t len) {
    void *key = malloc(len+1);
    *(char*) key = KEY_PREFIX;
    memcpy(key+1, ip, len);
    return key;
}

#undef PREFIX

struct rtt_state get_rtt_state(const uint8_t *ip, size_t len, struct kr_cache *cache) {
    struct rtt_state state = {0,0};
    knot_db_val_t value;
    knot_db_t *db = cache->db;
    struct kr_cdb_stats *stats = &cache->stats;
    uint8_t *prefixed_ip = prefix_key(ip, len);

    knot_db_val_t key = {.len = len + 1, .data = prefixed_ip};

    if(cache->api->read(db, stats, &key, &value, 1)) {
        state = (struct rtt_state){-1, -1}; // No value
    } else {
        assert(value.len == sizeof(struct rtt_state));
        state = *(struct rtt_state *)value.data;
    }

    free(prefixed_ip);
    return state;
}

int put_rtt_state(const uint8_t *ip, size_t len, struct rtt_state state, struct kr_cache *cache) {
    knot_db_t *db = cache->db;
    struct kr_cdb_stats *stats = &cache->stats;
    uint8_t *prefixed_ip = prefix_key(ip, len);

    knot_db_val_t key = {.len = len + 1, .data = prefixed_ip};
    knot_db_val_t value = {.len = sizeof(struct rtt_state), .data = &state};

    int ret = cache->api->write(db, stats, &key, &value, 1);
    cache->api->commit(db, stats);

    free(prefixed_ip);
    return ret;
}

/* IP helper functions */

void bytes_to_ip(uint8_t *bytes, size_t len, union inaddr *dst) {
    switch(len) {
    case sizeof(struct in_addr):
        ADDR_SET(dst->ip4.sin, AF_INET, bytes, len, 0);
        break;
    case sizeof(struct in6_addr):
        ADDR_SET(dst->ip6.sin6, AF_INET6, bytes, len, 0);
        break;
    default:
        assert(0);
    }
}

uint8_t* ip_to_bytes(const union inaddr *src, size_t len) {
    switch(len) {
    case sizeof(struct in_addr):
        return (uint8_t *)&src->ip4.sin_addr;
    case sizeof(struct in6_addr):
        return (uint8_t *)&src->ip6.sin6_addr;
    default:
        assert(0);
    }
}

#define DEFAULT_TIMEOUT 200
#define MINIMAL_TIMEOUT_ADDITION 20

// This is verbatim (minus the default timeout value and minimal variance) RFC2988, sec. 2
int32_t calc_timeout(struct rtt_state state) {
    if (state.srtt == -1 && state.variance == -1) {
        return DEFAULT_TIMEOUT;
    }
    return state.srtt + MAX(4 * state.variance, MINIMAL_TIMEOUT_ADDITION);
}

// This is verbatim RFC2988, sec. 2
struct rtt_state calc_rtt_state(struct rtt_state old, unsigned new_rtt) {
    if (old.srtt == -1 && old.variance == -1) {
        return (struct rtt_state){new_rtt, new_rtt/2};
    }

    struct rtt_state ret;

    ret.srtt = 0.75 * old.srtt + 0.25 * new_rtt;
    ret.variance = 0.875 * old.variance + 0.125 * abs(old.srtt - new_rtt);

    return ret;
}

// Allows the selection algorithm to start asynchronous NS name resolution for future use
void async_ns_resolution(knot_dname_t *name, enum knot_rr_type type) {
    struct kr_qflags flags;
    memset(&flags, 0, sizeof(struct kr_qflags));
    knot_pkt_t* pkt = worker_resolve_mk_pkt_dname(name, type, KNOT_CLASS_IN, &flags);
    worker_resolve_start(pkt, flags);
    free(pkt);
}

bool zonecut_changed(knot_dname_t *new, knot_dname_t *old) {
    return knot_dname_cmp(old, new);
}

void iter_update_state_from_rtt_cache(struct iter_local_state *local_state, struct kr_cache *cache) {
    trie_it_t *it;
    for(it = trie_it_begin(local_state->addresses); !trie_it_finished(it); trie_it_next(it)) {
        size_t address_len;
        uint8_t *address = (uint8_t *)trie_it_key(it, &address_len);
        struct iter_address_state *address_state = (struct iter_address_state *)*trie_it_val(it);
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
	if (zonecut_changed(zonecut->name, local_state->zonecut_name) ||
        local_state->unresolved_names == NULL || local_state->addresses == NULL) {
        // Local state initialization
        memset(local_state, 0, sizeof(struct iter_local_state));
        local_state->unresolved_names = trie_create(mm);
        local_state->addresses = trie_create(mm);
        local_state->zonecut_name = knot_dname_copy(zonecut->name, mm);
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
                uint8_t *address = (uint8_t *)pack_obj_val(obj);
                size_t address_len = pack_obj_len(obj);
                trie_val_t *val = trie_get_ins(local_state->addresses, (char *)address, address_len);
                if (!*val) {
                    // We have have not seen this address before.
                    *val = mm_alloc(mm, sizeof(struct iter_address_state));
                    memset(*val, 0, sizeof(struct iter_address_state));
                }
                struct iter_address_state *address_state = (*(struct iter_address_state **)val);
                address_state->generation = current_generation;
                address_state->name = dname;
            }
        }
    }

    trie_it_free(it);
}

void iter_get_tls_capable_peers(trie_t *addresses) {
    trie_it_t *it;
    for(it = trie_it_begin(addresses); !trie_it_finished(it); trie_it_next(it)) {
            size_t address_len;
            uint8_t* address = (uint8_t *)trie_it_key(it, &address_len);

            union inaddr tmp_address;
            bytes_to_ip(address, address_len, &tmp_address);

            struct iter_address_state *address_state = (struct iter_address_state *)*trie_it_val(it);
            tls_client_param_t *tls_entry = tls_client_param_get(the_worker->engine->net.tls_client_params, &tmp_address.ip);
            if (tls_entry) {
                address_state->tls_capable = true;
            } else {
                address_state->tls_capable = false;
            }
    }
    trie_it_free(it);
}

void iter_get_tcp_open_connections(trie_t *addresses) {
    trie_it_t *it;
    for(it = trie_it_begin(addresses); !trie_it_finished(it); trie_it_next(it)) {
            size_t address_len;
            uint8_t* address = (uint8_t *)trie_it_key(it, &address_len);

            union inaddr tmp_address;
            bytes_to_ip(address, address_len, &tmp_address);

            struct iter_address_state *address_state = (struct iter_address_state *)*trie_it_val(it);
            if (worker_find_tcp_connected(the_worker, &tmp_address.ip)) {
                address_state->tcp_connected = true;
            } else {
                address_state->tcp_connected = false;
            }
            if (worker_find_tcp_waiting(the_worker, &tmp_address.ip)) {
                address_state->tcp_waiting = true;
            } else {
                address_state->tcp_waiting = false;
            }
    }
    trie_it_free(it);
}

void iter_get_network_settings(trie_t *addresses, bool no_ipv4, bool no_ipv6) {
    trie_it_t *it;
    for(it = trie_it_begin(addresses); !trie_it_finished(it); trie_it_next(it)) {
            size_t address_len;
            uint8_t* address = (uint8_t *)trie_it_key(it, &address_len);

            union inaddr tmp_address;
            bytes_to_ip(address, address_len, &tmp_address);

            struct iter_address_state *address_state = (struct iter_address_state *)*trie_it_val(it);
            if (no_ipv4 && address_len == sizeof(struct in_addr)) {
                address_state->generation = -1; // Invalidate due to IPv4 being disabled in flags
            }
            if (no_ipv6 && address_len == sizeof(struct in6_addr)) {
                address_state->generation = -1; // Invalidate due to IPv6 being disabled in flags
            }
    }
    trie_it_free(it);
}

void iter_local_state_init(struct knot_mm *mm, void **local_state) {
    *local_state = mm_alloc(mm, sizeof(struct iter_local_state));
    memset(*local_state, 0, sizeof(struct iter_local_state));
}


void forward_local_state_init(struct knot_mm *mm, void **local_state, struct kr_request *req) {
    assert(req->forwarding_targets);
    *local_state = mm_alloc(mm, sizeof(struct forward_local_state));
    memset(*local_state, 0, sizeof(struct forward_local_state));

    struct forward_local_state *forward_state = (struct forward_local_state *)*local_state;
    forward_state->targets = req->forwarding_targets;
}


int cmp_choices(const void *a, const void *b) {
    struct choice *a_ = (struct choice *) a;
    struct choice *b_ = (struct choice *) b;

    int diff;
    if ((diff = a_->address_state->errors - b_->address_state->errors)) {
        return diff;
    }
    if ((diff = calc_timeout(a_->address_state->rtt_state) - calc_timeout(b_->address_state->rtt_state))) {
        return diff;
    }
    return 0;
}

#define ERROR_LIMIT 2

// Return a pointer to newly chosen (and allocated) transport. NULL if there is no choice.
// Performs the actual selection (currently epsilon-greedy with epsilon = 0.05).
struct kr_transport *iter_get_best_transport(struct choice choices[],
                                             int choices_len,
                                             knot_dname_t **unresolved,
                                             int unresolved_len,
                                             struct iter_local_state *local_state,
                                             struct knot_mm *mempool,
                                             bool tcp) {

    struct kr_transport *transport = mm_alloc(mempool, sizeof(struct kr_transport));
    memset(transport, 0, sizeof(struct kr_transport));
    int choice = 0;

    if (kr_rand_coin(1, 20) || choices_len == 0) {
        // EXPLORE
        int index = kr_rand_bytes(1) % (choices_len + unresolved_len);
        if (index < unresolved_len) {
            // We will resolve a new NS name
            *transport = (struct kr_transport) {
                .protocol = KR_TRANSPORT_NOADDR,
                .name = unresolved[index]
            };
            return transport;
        } else {
            choice = index - unresolved_len;
        }
    } else {
        // EXPLOIT
        qsort(choices, choices_len, sizeof(struct choice), cmp_choices);
        if (choices[0].address_state->error_count > ERROR_LIMIT) {
            return NULL;
        } else {
            choice = 0;
        }
    }

    *transport = (struct kr_transport) {
        .name = choices[choice].address_state->name,
        .protocol = tcp ? KR_TRANSPORT_TCP : KR_TRANSPORT_UDP,
        .timeout = calc_timeout(choices[choice].address_state->rtt_state),
    };


    int port;
    switch (transport->protocol)
    {
    case KR_TRANSPORT_TLS:
        port = KR_DNS_TLS_PORT;
        break;
    case KR_TRANSPORT_UDP:
    case KR_TRANSPORT_TCP:
        port = KR_DNS_PORT;
        break;
    default:
        assert(0);
        break;
    }


    switch (choices[choice].address_len)
    {
    case sizeof(struct in_addr):
        ADDR_SET(transport->address.ip4.sin, AF_INET, choices[choice].address, choices[choice].address_len, port);
        transport->address_len = choices[choice].address_len;
        break;
    case sizeof(struct in6_addr):
        ADDR_SET(transport->address.ip6.sin6, AF_INET6, choices[choice].address, choices[choice].address_len, port);
        transport->address_len = choices[choice].address_len;
        break;
    default:
        assert(0);
        break;
    }

    return transport;

}

// Prepares all the data for selection. The naming sucks currently. So TODO renaming.
// Maybe factor the preparation out and have this be function that calls one and then the other function.
void iter_choose_transport(struct kr_query *qry, struct kr_transport **transport) {
    struct knot_mm *mempool = qry->request->rplan.pool;
    struct iter_local_state *local_state = (struct iter_local_state *)qry->server_selection.local_state;

    iter_update_state_from_zonecut(local_state, &qry->zone_cut, mempool);
    iter_update_state_from_rtt_cache(local_state, &qry->request->ctx->cache);

    // Consider going through the trie only once by refactoring these:
    iter_get_tls_capable_peers(local_state->addresses);
    iter_get_tcp_open_connections(local_state->addresses);
    iter_get_network_settings(local_state->addresses, qry->flags.NO_IPV4, qry->flags.NO_IPV4);

    // also take qry->flags.TCP into consideration (do that in the actual choosing function)

    int num_addresses = trie_weight(local_state->addresses);
    int num_unresolved_names = trie_weight(local_state->unresolved_names);

    struct choice choices[num_addresses]; // Some will get unused, oh well
    knot_dname_t *unresolved_names[num_unresolved_names];

    trie_it_t *it;

    int valid_addresses = 0;
    for(it = trie_it_begin(local_state->addresses); !trie_it_finished(it); trie_it_next(it)) {
        size_t address_len;
        uint8_t* address = (uint8_t *)trie_it_key(it, &address_len);
        struct iter_address_state *address_state = (struct iter_address_state *)*trie_it_val(it);
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
        *transport = iter_get_best_transport(choices, valid_addresses, unresolved_names, to_resolve, local_state, mempool, qry->flags.TCP);
    } else {
        *transport = NULL;
    }

    WITH_VERBOSE(qry) {

	KR_DNAME_GET_STR(ns_name, (*transport)->name);
	KR_DNAME_GET_STR(zonecut_str, qry->zone_cut.name);
	const char *ns_str = kr_straddr(&(*transport)->address.ip);

	VERBOSE_MSG(qry,
			"=> id: '%05u' choosing: '%s'@'%s' zone cut: '%s'\n",
			qry->id, ns_name, ns_str ? ns_str : "", zonecut_str);
	}
}

struct iter_address_state *get_address_state(struct iter_local_state *local_state, const struct kr_transport *transport) {
	trie_t *addresses = local_state->addresses;
	uint8_t *address = ip_to_bytes(&transport->address, transport->address_len);

	trie_val_t *address_state = trie_get_try(addresses, (char *)address, transport->address_len);

	if (!address_state) {
		assert(0);
	}
	return (struct iter_address_state *)*address_state;
}

void iter_success(struct kr_query *qry, const struct kr_transport *transport) {
    if (!transport) {
        return;
    }

	struct iter_local_state *local_state = qry->server_selection.local_state;
	struct iter_address_state *addr_state = get_address_state(local_state, transport);

	addr_state->success_count++;
}

void iter_update_rtt(struct kr_query *qry, const struct kr_transport *transport, unsigned rtt) {
    if (!transport) {
        return;
    }

	struct iter_local_state *local_state = qry->server_selection.local_state;
	struct iter_address_state *addr_state = get_address_state(local_state, transport);
	struct kr_cache *cache = &qry->request->ctx->cache;

    struct rtt_state new_rtt_state = calc_rtt_state(addr_state->rtt_state, rtt);
    uint8_t *address = ip_to_bytes(&transport->address, transport->address_len);
	put_rtt_state(address, transport->address_len, new_rtt_state, cache);

    WITH_VERBOSE(qry) {

	KR_DNAME_GET_STR(ns_name, transport->name);
	KR_DNAME_GET_STR(zonecut_str, qry->zone_cut.name);
	const char *ns_str = kr_straddr(&transport->address.ip);

	VERBOSE_MSG(qry,
			"=> id: '%05u' updating: '%s'@'%s' zone cut: '%s' with rtt %u to srtt: %d and variance: %d \n",
			qry->id, ns_name, ns_str ? ns_str : "", zonecut_str, rtt, new_rtt_state.srtt, new_rtt_state.variance);
	}
}

void iter_error(struct kr_query *qry, const struct kr_transport *transport, enum kr_selection_error error) {
    if (!transport) {
        return;
    }

    if (error >= KR_SELECTION_NUMBER_OF_ERRORS) {
        assert(0);
    }

	struct iter_local_state *local_state = qry->server_selection.local_state;
	struct iter_address_state *addr_state = get_address_state(local_state, transport);
	addr_state->errors[error]++;
    addr_state->error_count++;

    WITH_VERBOSE(qry) {

	KR_DNAME_GET_STR(ns_name, transport->name);
	KR_DNAME_GET_STR(zonecut_str, qry->zone_cut.name);
	const char *ns_str = kr_straddr(&transport->address.ip);

	VERBOSE_MSG(qry,
			"=> id: '%05u' noting selection error: '%s'@'%s' zone cut: '%s' error no.:%d\n",
			qry->id, ns_name, ns_str ? ns_str : "", zonecut_str, error);
	}
}

// TODO: Forwarding functions
void forward_choose_transport(struct kr_query *qry, struct kr_transport **transport) {return;}
void forward_success(struct kr_query *qry, const struct kr_transport *transport) {return;}
void forward_update_rtt(struct kr_query *qry, const struct kr_transport *transport, unsigned rtt) {return;}
void forward_error(struct kr_query *qry, const struct kr_transport *transport, enum kr_selection_error error) {return;}


void kr_server_selection_init(struct kr_query *qry) {
    struct knot_mm *mempool = &qry->request->pool;
    if (qry->flags.FORWARD || qry->flags.STUB) {
        qry->server_selection = (struct kr_server_selection){
            .initialized = true,
            .choose_transport = forward_choose_transport,
            .success = forward_success,
            .update_rtt = forward_update_rtt,
            .error = forward_error,
            .local_state = NULL,
        };
        forward_local_state_init(mempool, &qry->server_selection.local_state, qry->request);
    } else {
        qry->server_selection = (struct kr_server_selection){
            .initialized = true,
            .choose_transport = iter_choose_transport,
            .success = iter_success,
            .update_rtt = iter_update_rtt,
            .error = iter_error,
            .local_state = NULL,
        };
        iter_local_state_init(mempool, &qry->server_selection.local_state);
    }
}

int kr_forward_add_target(struct kr_request *req, size_t index, const struct sockaddr *sock) {
    if (!req->forwarding_targets) {
        req->forwarding_targets = mm_alloc(&req->pool, req->forward_targets_num * sizeof(struct sockaddr));
    }
    req->forwarding_targets[index] = *sock;
    return kr_ok();
}

