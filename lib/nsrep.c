#include <libknot/dname.h>

#include "lib/nsrep.h"
#include "lib/generic/lru.h"
#include "lib/generic/pack.h"
#include "lib/generic/trie.h"
#include "lib/rplan.h"
#include "lib/cache/api.h"
#include "lib/resolve.h"

// Old code

/** @internal Macro to set address structure. */
#define ADDR_SET(sa, family, addr, len, port) do {\
    	memcpy(&sa ## _addr, (addr), (len)); \
    	sa ## _family = (family); \
	sa ## _port = htons(port); \
} while (0)

#define PREFIX 'S'

void *prefix_key(const void *ip, size_t len) {
    void *key = malloc(len+1);
    *(char*) key = PREFIX;
    memcpy(key+1, ip, len);
    return key;
}

#undef PREFIX

int32_t get_score(const void *ip, size_t len, struct kr_cache *cache) {
    int32_t score;
    knot_db_val_t value;
    knot_db_t *db = cache->db;
    struct kr_cdb_stats *stats = &cache->stats;
    void *prefixed_ip = prefix_key(ip, len);

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

int update_score(const void *ip, size_t len, int32_t score, struct kr_cache *cache) {
    knot_db_t *db = cache->db;
    struct kr_cdb_stats *stats = &cache->stats;
    void *prefixed_ip = prefix_key(ip, len);

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
		/* we trust it's a correct dname */
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
        // Currently no feedback, but we set random values
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
