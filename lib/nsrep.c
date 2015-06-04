/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <libknot/internal/sockaddr.h>

#include "lib/nsrep.h"
#include "lib/rplan.h"
#include "lib/defines.h"
#include "lib/generic/pack.h"

/** Some built-in unfairness ... */
#define FAVOUR_IPV6 20 /* 20ms bonus for v6 */

/** @internal Macro to set address structure. */
#define ADDR_SET(sa, family, addr, len) do {\
    	memcpy(&sa ## _addr, (addr), (len)); \
    	sa ## _family = (family); \
	sa ## _port = htons(KR_DNS_PORT); \
} while (0)

/** Update nameserver representation with current name/address pair. */
static void update_nsrep(struct kr_nsrep *ns, const knot_dname_t *name, uint8_t *addr, unsigned score)
{
	ns->name = name;
	ns->score = score;
	if (addr == NULL) {
		ns->addr.ip.sa_family = AF_UNSPEC;
		return;
	}

	size_t len = pack_obj_len(addr);
	void *addr_val = pack_obj_val(addr);
	switch(len) {
	case sizeof(struct in_addr):
		ADDR_SET(ns->addr.ip4.sin, AF_INET, addr_val, len); break;
	case sizeof(struct in6_addr):
		ADDR_SET(ns->addr.ip6.sin6, AF_INET6, addr_val, len); break;
	default: assert(0); break;
	}
}

#undef ADDR_SET

static unsigned eval_addr_set(pack_t *addr_set, kr_nsrep_lru_t *rttcache, unsigned score, uint8_t **addr)
{
	/* Name server is better candidate if it has address record. */
	uint8_t *it = pack_head(*addr_set);
	while (it != pack_tail(*addr_set)) {
		void *val = pack_obj_val(it);
		size_t len = pack_obj_len(it);
		/* Get RTT for this address (if known) */
		unsigned *cached = rttcache ? lru_get(rttcache, val, len) : NULL;
		unsigned addr_score = (cached) ? *cached : KR_NS_UNKNOWN / 2;
		/* Give v6 a head start */
		unsigned favour = (len == sizeof(struct in6_addr)) ? FAVOUR_IPV6 : 0;
		if (addr_score < score + favour) {
			*addr = it;
			score = addr_score;
		}
		it = pack_obj_next(it);
	}
	return score;
}

static int eval_nsrep(const char *k, void *v, void *baton)
{
	struct kr_nsrep *ns = baton;
	unsigned score = KR_NS_MAX_SCORE;
	uint8_t *addr = NULL;

	/* Favour nameservers with unknown addresses to probe them,
	 * otherwise discover the current best address for the NS. */
	pack_t *addr_set = (pack_t *)v;
	if (addr_set->len == 0) {
		score = KR_NS_UNKNOWN;
	} else {
		score = eval_addr_set(addr_set, ns->repcache, score, &addr);
	}

	/* Probabilistic bee foraging strategy (naive).
	 * The fastest NS is preferred by workers until it is depleted (timeouts or degrades),
	 * at the same time long distance scouts probe other sources (low probability).
	 * Servers on TIMEOUT (depleted) can be probed by the dice roll only */
	if (score < ns->score && (ns->flags & QUERY_NO_THROTTLE || score < KR_NS_TIMEOUT)) {
		update_nsrep(ns, (const knot_dname_t *)k, addr, score);
	} else {
		/* With 5% chance, probe server with a probability given by its RTT / MAX_RTT */
		unsigned roll = rand() % KR_NS_MAX_SCORE;
		if ((roll % 100 < 5) && (roll >= score)) {
			update_nsrep(ns, (const knot_dname_t *)k, addr, score);
			return 1; /* Stop evaluation */
		}
	}

	return kr_ok();
}

int kr_nsrep_elect(struct kr_nsrep *ns, map_t *nsset, kr_nsrep_lru_t *repcache)
{
	ns->repcache = repcache;
	ns->addr.ip.sa_family = AF_UNSPEC;
	ns->score = KR_NS_MAX_SCORE + 1;
	return map_walk(nsset, eval_nsrep, ns);
}

int kr_nsrep_update(struct kr_nsrep *ns, unsigned score, kr_nsrep_lru_t *repcache)
{
	if (!ns || !repcache || ns->addr.ip.sa_family == AF_UNSPEC) {
		return kr_error(EINVAL);
	}

	char *addr = kr_nsrep_inaddr(ns->addr);
	size_t addr_len = kr_nsrep_inaddr_len(ns->addr);
	unsigned *cur = lru_set(repcache, addr, addr_len);
	if (!cur) {
		return kr_error(ENOMEM);
	}
	/* Score limits */
	if (score > KR_NS_MAX_SCORE) {
		score = KR_NS_MAX_SCORE;
	}
	if (score <= KR_NS_UNKNOWN) {
		score = KR_NS_UNKNOWN + 1;
	}
	/* Set initial value or smooth over last two measurements */
	if (*cur != 0) {
		*cur = (*cur + score) / 2;
	} else {
	/* First measurement, reset */
		*cur = score;
	}
	return kr_ok();
}
