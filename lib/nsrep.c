#include <libknot/dname.h>

#include "lib/nsrep.h"
#include "lib/generic/lru.h"
#include "lib/generic/pack.h"
#include "lib/generic/trie.h"
#include "lib/rplan.h"

/** @internal Macro to set address structure. */
#define ADDR_SET(sa, family, addr, len, port) do {\
    	memcpy(&sa ## _addr, (addr), (len)); \
    	sa ## _family = (family); \
	sa ## _port = htons(port); \
} while (0)

int kr_nsrep_elect(struct kr_query *qry)
{
    const int nsset_len = trie_weight(qry->zone_cut.nsset);
	struct {
		const knot_dname_t *name;
		const pack_t *addrs;
	} nsset[nsset_len];

	trie_it_t *it;
    printf("hi\n");
	int i = 0;
	for (it = trie_it_begin(qry->zone_cut.nsset); !trie_it_finished(it);
							trie_it_next(it), ++i) {
		/* we trust it's a correct dname */
		nsset[i].name = (const knot_dname_t *)trie_it_key(it, NULL);
		nsset[i].addrs = (const pack_t *)*trie_it_val(it);
	}
	trie_it_free(it);
	assert(i == nsset_len);

    char dname[256];
    knot_dname_to_str(dname, nsset[0].name, 255);
    printf("NS name: %s\n", dname);

    if (!pack_obj_len(nsset[0].addrs)) {
        printf("fuck, there is no address in cache, fuck\n");
        qry->ns.addr[0].ip.sa_family = AF_UNSPEC;
        return kr_error(1);
    }
    uint8_t *head = pack_head(*nsset[0].addrs);


    void *val = pack_obj_val(head);
    size_t len = pack_obj_len(head);

    printf("ip %u\n", *(unsigned *)val);
    // printf("ip? %s\n", kr_straddr(kr_inaddr(ip)));

    qry->ns.name = nsset[0].name;
    if (len == sizeof(struct in_addr)) {
        ADDR_SET(qry->ns.addr[0].ip4.sin, AF_INET, val, len, KR_DNS_PORT);
    }

    if (len == sizeof(struct in6_addr)) {
        ADDR_SET(qry->ns.addr[0].ip6.sin6, AF_INET6, val, len, KR_DNS_PORT);
    }

    return kr_ok();
}