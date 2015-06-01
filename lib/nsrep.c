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
#include "lib/defines.h"
#include "lib/generic/pack.h"

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

static int eval_nsrep(const char *k, void *v, void *baton)
{
	struct kr_nsrep *ns = baton;
	unsigned score = ns->score;
	pack_t *addr_set = v;
	uint8_t *addr = NULL;

	/* Name server is better candidate if it has address record. */
	uint8_t *it = pack_head(*addr_set);
	while (it != pack_tail(*addr_set)) {
		void *val = pack_obj_val(it);
		size_t len = pack_obj_len(it);
		unsigned *cached = lru_get(ns->repcache, val, len);
		unsigned addr_score = (cached) ? *cached : KR_NS_UNKNOWN / 2;
		/** @todo Favorize IPv6 */
		if (addr_score <= score) {
			addr = it;
			score = addr_score;
		}
		it = pack_obj_next(it);
	}
	/* No known address */
	if (!addr) {
		score = KR_NS_UNKNOWN;
	}

	/* Update best scoring nameserver. */
	if (score < ns->score) {
		update_nsrep(ns, (const knot_dname_t *)k, addr, score);
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
	/* Set initial value or smooth over last two measurements */
	if (*cur != 0) {
		*cur = (*cur + score) / 2;
	} else {
	/* First measurement, reset */
		*cur = score;
	}
	return kr_ok();
}
