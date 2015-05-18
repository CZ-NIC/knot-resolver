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
	unsigned score = KR_NS_VALID;
	struct kr_nsrep *ns = baton;
	pack_t *addr_set = v;
	uint8_t *addr = NULL;

	/* Name server is better candidate if it has address record. */
	if (addr_set->len > 0) {
		addr = pack_head(*addr_set);
		score += 1;
	}

	/* Update best scoring nameserver. */
	if (ns->score < score) {
		update_nsrep(ns, (const knot_dname_t *)k, addr, score);
	}

	return kr_ok();
}

int kr_nsrep_elect(struct kr_nsrep *ns, map_t *nsset)
{
	ns->addr.ip.sa_family = AF_UNSPEC;
	ns->score = KR_NS_INVALID;
	return map_walk(nsset, eval_nsrep, ns);
}
