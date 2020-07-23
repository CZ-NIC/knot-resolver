#include <libknot/dname.h>

#include "lib/nsrep.h"
#include "lib/generic/lru.h"
#include "lib/generic/pack.h"
#include "lib/generic/trie.h"
#include "lib/rplan.h"
#include "lib/cache/api.h"
#include "lib/resolve.h"

#define PREFIX 'S'

/** @internal Macro to set address structure. */
#define ADDR_SET(sa, family, addr, len, port) do {\
    	memcpy(&sa ## _addr, (addr), (len)); \
    	sa ## _family = (family); \
	sa ## _port = htons(port); \
} while (0)


void *prefix_key(const uint8_t *ip, size_t len) {
    void *key = malloc(len+1);
    *(char*) key = PREFIX;
    memcpy(key+1, ip, len);
    return key;
}

#undef PREFIX

int32_t get_score(const uint8_t *ip, size_t len, struct kr_cache *cache) {
    int32_t score;
    knot_db_val_t value;
    knot_db_t *db = cache->db;
    struct kr_cdb_stats *stats = &cache->stats;
    uint8_t *prefixed_ip = prefix_key(ip, len);

    knot_db_val_t key = {.len = len + 1, .data = prefixed_ip};

    if(cache->api->read(db, stats, &key, &value, 1)) {
        score = -1;
    } else {
        assert(value.len == sizeof(int32_t));
        score = *(int32_t*)value.data;
    }

    free(prefixed_ip);
    return score;
}

int update_score(const uint8_t *ip, size_t len, int32_t score, struct kr_cache *cache) {
    knot_db_t *db = cache->db;
    struct kr_cdb_stats *stats = &cache->stats;
    uint8_t *prefixed_ip = prefix_key(ip, len);

    knot_db_val_t key = {.len = len + 1, .data = prefixed_ip};
    knot_db_val_t value = {.len = sizeof(int32_t), .data = &score};

    int ret = cache->api->write(db, stats, &key, &value, 1);

    free(prefixed_ip);
    return ret;
}

struct server {
    knot_dname_t *name;
    const void* ip;
    size_t ip_len;
    int32_t score;
};

int cmp_servers(const void* a, const void* b) {
    const struct server *a_ = (struct server*) a;
    const struct server *b_ = (struct server*) b;
    return a_->score - b_->score;
}

struct server *choose(struct server *choice, size_t len) {
    qsort(choice, len, sizeof(struct server), &cmp_servers);
    return choice;
}

struct iter_local_state {
    trie_t *unresolved_names;
    trie_t *addresses;
    unsigned int generation; // Used to distinguish old and valid records in tries
};

struct iter_name_state {
    unsigned int generation;
};

struct iter_address_state {
    unsigned int generation;
    int32_t current_score;
    knot_dname_t *name;
};

void iter_update_state_rtt_cache(struct iter_local_state *local_state, struct kr_cache *cache) {
    trie_it_t *it;
    for(it = trie_it_begin(local_state->addresses); !trie_it_finished(it); trie_it_next(it)) {
        size_t address_len;
        uint8_t *address = (uint8_t *)trie_it_key(it, &address_len);
        struct iter_address_state *address_state = (struct iter_address_state *)trie_it_val(it);
        address_state->current_score = get_score(address, address_len, cache);
    }
    trie_it_free(it);
}

void iter_update_state_from_zonecut(struct iter_local_state *local_state, trie_t *zonecut, struct knot_mm *mm) {
	if (local_state->unresolved_names == NULL || local_state->addresses == NULL) {
        // Local state initialization
        local_state->unresolved_names = trie_create(mm);
        local_state->addresses = trie_create(mm);
        local_state->generation = 0;
    }

    local_state->generation++;

    trie_it_t *it;
    unsigned int current_generation = local_state->generation;

    for(it = trie_it_begin(zonecut); !trie_it_finished(it); trie_it_next(it)) {
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
                printf("address len %d\n", address_len);
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

void iter_local_state_init(struct knot_mm *mm, void **local_state) {
    *local_state = mm_alloc(mm, sizeof(struct iter_local_state));
    memset(*local_state, 0, sizeof(struct iter_local_state));
}

void iter_choose_transport(struct kr_query *qry) {
    struct knot_mm *mempool = qry->request->rplan.pool;
    if (!qry->server_selection.local_state) {
        iter_local_state_init(mempool, &qry->server_selection.local_state);
    }
    struct iter_local_state *local_state = (struct iter_local_state *)qry->server_selection.local_state;

    iter_update_state_from_zonecut(local_state, qry->zone_cut.nsset, mempool);
    iter_update_state_rtt_cache(local_state, &qry->request->ctx->cache);

    const int num_addresses = trie_weight(local_state->addresses);

    struct {
        uint8_t *address;
        size_t address_len;
        struct iter_address_state *address_state;
    } choices[num_addresses];

    trie_it_t *it;

    if (num_addresses == 0) {
        for(it = trie_it_begin(local_state->unresolved_names); !trie_it_finished(it); trie_it_next(it)) {
            struct iter_name_state *name_state = *(struct iter_name_state **)trie_it_val(it);
            if (name_state->generation == local_state->generation) {
                knot_dname_t *name = (knot_dname_t *)trie_it_key(it, NULL);
                qry->transport = (struct kr_transport) {
                    .name = name,
                    .protocol = KR_TRANSPORT_NOADDR,
                };
                trie_it_free(it);
                return;
            }
        }
        trie_it_free(it);
    }

    // This block will be replaced with function call that does the choice logic
    int choice;
    {
        int i = 0;
        for(it = trie_it_begin(local_state->addresses); !trie_it_finished(it); trie_it_next(it), i++) {
            choices[i].address = (uint8_t *)trie_it_key(it, &choices[i].address_len);
            choices[i].address_state = (struct iter_address_state *)trie_it_val(it);
        }
        trie_it_free(it);

        // Random for now, yay!
        choice = kr_rand_bytes(1) % num_addresses;

        qry->transport = (struct kr_transport) {
            .name = choices[choice].address_state->name,
            .protocol = KR_TRANSPORT_UDP,
            .timeout = 200,
        };
    }

    switch (choices[choice].address_len)
    {
    case sizeof(struct in_addr):
        ADDR_SET(qry->transport.address.ip4.sin, AF_INET, choices[choice].address, choices[choice].address_len, KR_DNS_PORT);
        break;
    case sizeof(struct in6_addr):
        ADDR_SET(qry->transport.address.ip6.sin6, AF_INET6, choices[choice].address, choices[choice].address_len, KR_DNS_PORT);
        break;
    default:
        assert(0);
        break;
    }
}

void iter_success(struct kr_query *qry, struct kr_transport transport) {return;}
void iter_update_rtt(struct kr_query *qry, struct kr_transport transport, unsigned rtt) {return;}
void iter_error(struct kr_query *qry, struct kr_transport transport, enum kr_selection_error error) {return;}

void forward_choose_transport(struct kr_query *qry) {return;}
void forward_success(struct kr_query *qry, struct kr_transport transport) {return;}
void forward_update_rtt(struct kr_query *qry, struct kr_transport transport, unsigned rtt) {return;}
void forward_error(struct kr_query *qry, struct kr_transport transport, enum kr_selection_error error) {return;}


void kr_server_selection_init(struct kr_query *qry) {
    if (qry->flags.FORWARD || qry->flags.STUB) {
        qry->server_selection = (struct kr_server_selection){
            .choose_transport = forward_choose_transport,
            .success = forward_success,
            .update_rtt = forward_update_rtt,
            .error = forward_error,
            .local_state = NULL,
        };
    } else {
        qry->server_selection = (struct kr_server_selection){
            .choose_transport = iter_choose_transport,
            .success = iter_success,
            .update_rtt = iter_update_rtt,
            .error = iter_error,
            .local_state = NULL,
        };
    }
}

/*
int kr_nsrep_elect(struct kr_query *qry, struct kr_context *ctx)
{
    // Unpack available servers
    const int nsset_len = trie_weight(qry->zone_cut.nsset);
	struct {
		knot_dname_t *name;
		const pack_t *addr_set;
	} nsset[nsset_len];

	trie_it_t *it;

	int name_count = 0;
    int addr_count = 0;

    printf("Available names: \n");
	for(it = trie_it_begin(qry->zone_cut.nsset); !trie_it_finished(it);
							trie_it_next(it), ++name_count) {
		// we trust it's a correct dname
		nsset[name_count].name = (knot_dname_t *)trie_it_key(it, NULL);

        char dname[1024];
        knot_dname_to_str(dname, nsset[name_count].name, 1023);
        printf("%s\n", dname);

		nsset[name_count].addr_set = (const pack_t *)*trie_it_val(it);
        for(uint8_t *jt = pack_head(*nsset[name_count].addr_set); jt != pack_tail(*nsset[name_count].addr_set);
						jt = pack_obj_next(jt)) {
            addr_count++;
        }
	}
    printf("\n");
	trie_it_free(it);
	assert(name_count == nsset_len);

    if(!addr_count) {
        // All the NSes are glueless, let's resolve them and try again
        // If there are some glued ones, with don't do this at all
        printf("No name with address, we will plan to resolve them now.\n");
        for(int i = 0; i < name_count; i++) {

            char dname[1024];
            knot_dname_to_str(dname, nsset[i].name, 1023);
            printf("%s\n", dname);

            // We should probably check the return code of these
            qry->ns.name = nsset[i].name;
            qry->ns.addr[0].ip.sa_family = AF_UNSPEC;
            kr_ns_resolve_addr(qry, qry->request);
        }
        return KR_STATE_PRODUCE; // Retry!
    }

    // Flatten the structure
    struct server server_set[addr_count];

    int c = 0;
    for(int i = 0; i < name_count; i++) {
        for(uint8_t *obj = pack_head(*nsset[i].addr_set); obj != pack_tail(*nsset[i].addr_set);
						obj = pack_obj_next(obj)) {
            server_set[c].name = nsset[i].name;
            server_set[c].ip = pack_obj_val(obj);
            server_set[c].ip_len = pack_obj_len(obj);
            c++;
        }
    }
    assert(c == addr_count);

    // Retrieve current scores
    struct kr_cache *cache = &ctx->cache;
    for(int i = 0; i < addr_count; i++) {
        struct server *cur = &server_set[i];
        // Currently no feedback, but we set the scores to random values
        update_score(cur->ip, cur->ip_len, kr_rand_bytes(1), cache);

        cur->score = get_score(cur->ip, cur->ip_len, cache);
    }

    // This prints the IP addresses (kinda :P):
    printf("Names with addresses:\n");
    for(int i = 0; i < addr_count; i++) {
        char dname[1024];
        knot_dname_to_str(dname, server_set[i].name, 1023);
        printf("%s ", dname);
        size_t len = server_set[i].ip_len;
        const uint8_t *ptr = server_set[i].ip;
        for(int j = 0; j < len; j++) {
            uint8_t b = *(ptr+j);
            printf("%02hx", b);
        }
        printf(" %d", server_set[i].score);
        printf("\n");
    }

    printf("Total addr_count %d\n", c);

    // Choose the _best_ server
    struct server *choice = choose(server_set, addr_count);

    ///
    printf("Chose ");
    char dname[1024];
    knot_dname_to_str(dname, choice->name, 1023);
    printf("%s ", dname);
    size_t len = choice->ip_len;
    const uint8_t *ptr = choice->ip;
    for(int j = 0; j < len; j++) {
        uint8_t b = *(ptr+j);
        printf("%02hx", b);
    }
    printf("\n");
    ///

    // Set it as next server
    qry->ns.name = choice->name;
    if (choice->ip_len == sizeof(struct in_addr)) {
        ADDR_SET(qry->ns.addr[0].ip4.sin, AF_INET, choice->ip, choice->ip_len, KR_DNS_PORT);
    }

    if (choice->ip_len == sizeof(struct in6_addr)) {
        ADDR_SET(qry->ns.addr[0].ip6.sin6, AF_INET6, choice->ip, choice->ip_len, KR_DNS_PORT);
    }

    return kr_ok();
}

*/