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
#include "lib/rplan.h"
#include "lib/resolve.h"
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
static void update_nsrep(struct kr_nsrep *ns, size_t pos, uint8_t *addr, size_t addr_len)
{
	if (addr == NULL) {
		ns->addr[pos].ip.sa_family = AF_UNSPEC;
		return;
	}

	/* Rotate previous addresses to the right. */
	memmove(ns->addr + pos + 1, ns->addr + pos, (KR_NSREP_MAXADDR - pos - 1) * sizeof(ns->addr[0]));

	switch(addr_len) {
	case sizeof(struct in_addr):
		ADDR_SET(ns->addr[pos].ip4.sin, AF_INET, addr, addr_len); break;
	case sizeof(struct in6_addr):
		ADDR_SET(ns->addr[pos].ip6.sin6, AF_INET6, addr, addr_len); break;
	default: assert(0); break;
	}
}

static void update_nsrep_set(struct kr_nsrep *ns, const knot_dname_t *name, uint8_t *addr[], unsigned score)
{
	/* NSLIST is not empty, empty NS cannot be a leader. */
	if (!addr[0] && ns->addr[0].ip.sa_family != AF_UNSPEC) {
		return;
	}
	/* Set new NS leader */
	ns->name = name;
	ns->score = score;
	for (size_t i = 0; i < KR_NSREP_MAXADDR; ++i) {
		if (addr[i]) {
			void *addr_val = pack_obj_val(addr[i]);
			size_t len = pack_obj_len(addr[i]);
			update_nsrep(ns, i, addr_val, len);
		} else {
			break;
		}
	}
}

#undef ADDR_SET

static unsigned eval_addr_set(pack_t *addr_set, kr_nsrep_lru_t *rttcache, unsigned score, uint8_t *addr[], uint32_t opts)
{
	/* Name server is better candidate if it has address record. */
	uint8_t *it = pack_head(*addr_set);
	while (it != pack_tail(*addr_set)) {
		void *val = pack_obj_val(it);
		size_t len = pack_obj_len(it);
		unsigned favour = 0;
		bool is_valid = false;
		/* Check if the address isn't disabled. */
		if (len == sizeof(struct in6_addr)) {
			is_valid = !(opts & QUERY_NO_IPV6);
			favour = FAVOUR_IPV6;
		} else {
			is_valid = !(opts & QUERY_NO_IPV4);
		}
		/* Get RTT for this address (if known) */
		if (is_valid) {
			unsigned *cached = rttcache ? lru_get(rttcache, val, len) : NULL;
			unsigned addr_score = (cached) ? *cached : KR_NS_GLUED;
			if (addr_score < score + favour) {
				/* Shake down previous contenders */
				for (size_t i = KR_NSREP_MAXADDR - 1; i > 0; --i)
					addr[i] = addr[i - 1];
				addr[0] = it;
				score = addr_score;
			}
		}
		it = pack_obj_next(it);
	}
	return score;
}

static int eval_nsrep(const char *k, void *v, void *baton)
{
	struct kr_query *qry = baton;
	struct kr_nsrep *ns = &qry->ns;
	struct kr_context *ctx = ns->ctx;
	unsigned score = KR_NS_MAX_SCORE;
	unsigned reputation = 0;
	uint8_t *addr_choice[KR_NSREP_MAXADDR] = { NULL, };

	/* Fetch NS reputation */
	if (ctx->cache_rep) {
		unsigned *cached = lru_get(ctx->cache_rep, k, knot_dname_size((const uint8_t *)k));
		if (cached) {
			reputation = *cached;
		}
	}

	/* Favour nameservers with unknown addresses to probe them,
	 * otherwise discover the current best address for the NS. */
	pack_t *addr_set = (pack_t *)v;
	if (addr_set->len == 0) {
		score = KR_NS_UNKNOWN;
		/* If the server doesn't have IPv6, give it disadvantage. */
		if (reputation & KR_NS_NOIP6) {
			score += FAVOUR_IPV6;
			/* If the server is unknown but has rep record, treat it as timeouted */
			if (reputation & KR_NS_NOIP4) {
				score = KR_NS_UNKNOWN;
				reputation = 0; /* Start with clean slate */
			}
		}
	} else {
		score = eval_addr_set(addr_set, ctx->cache_rtt, score, addr_choice, ctx->options);
	}

	/* Probabilistic bee foraging strategy (naive).
	 * The fastest NS is preferred by workers until it is depleted (timeouts or degrades),
	 * at the same time long distance scouts probe other sources (low probability).
	 * Servers on TIMEOUT (depleted) can be probed by the dice roll only */
	if (score <= ns->score && (qry->flags & QUERY_NO_THROTTLE || score < KR_NS_TIMEOUT)) {
		update_nsrep_set(ns, (const knot_dname_t *)k, addr_choice, score);
		ns->reputation = reputation;
	} else {
		/* With 10% chance, probe server with a probability given by its RTT / MAX_RTT */
		if ((kr_rand_uint(100) < 10) && (kr_rand_uint(KR_NS_MAX_SCORE) >= score)) {
			/* If this is a low-reliability probe, go with TCP to get ICMP reachability check. */
			if (score >= KR_NS_LONG) {
				qry->flags |= QUERY_TCP;
			}
			update_nsrep_set(ns, (const knot_dname_t *)k, addr_choice, score);
			ns->reputation = reputation;
			return 1; /* Stop evaluation */
		}
	}

	return kr_ok();
}

int kr_nsrep_set(struct kr_query *qry, uint8_t *addr, size_t addr_len)
{
	if (!qry || !addr) {
		return kr_error(EINVAL);
	}
	qry->ns.name = (const uint8_t *)"";
	qry->ns.score = KR_NS_UNKNOWN;
	qry->ns.reputation = 0;
	update_nsrep(&qry->ns, 0, addr, addr_len);
	update_nsrep(&qry->ns, 1, NULL, 0);
	return kr_ok();
}

#define ELECT_INIT(ns, ctx_) do { \
	(ns)->ctx = (ctx_); \
	(ns)->addr[0].ip.sa_family = AF_UNSPEC; \
	(ns)->reputation = 0; \
	(ns)->score = KR_NS_MAX_SCORE + 1; \
} while (0)

int kr_nsrep_elect(struct kr_query *qry, struct kr_context *ctx)
{
	if (!qry || !ctx) {
		return kr_error(EINVAL);
	}

	struct kr_nsrep *ns = &qry->ns;
	ELECT_INIT(ns, ctx);
	return map_walk(&qry->zone_cut.nsset, eval_nsrep, qry);
}

int kr_nsrep_elect_addr(struct kr_query *qry, struct kr_context *ctx)
{
	if (!qry || !ctx) {
		return kr_error(EINVAL);
	}

	/* Get address list for this NS */
	struct kr_nsrep *ns = &qry->ns;
	ELECT_INIT(ns, ctx);
	pack_t *addr_set = map_get(&qry->zone_cut.nsset, (const char *)ns->name);
	if (!addr_set) {
		return kr_error(ENOENT);
	}
	/* Evaluate addr list */
	uint8_t *addr_choice[KR_NSREP_MAXADDR] = { NULL, };
	unsigned score = eval_addr_set(addr_set, ctx->cache_rtt, ns->score, addr_choice, ctx->options);
	update_nsrep_set(ns, ns->name, addr_choice, score);
	return kr_ok();
}

#undef ELECT_INIT

int kr_nsrep_update_rtt(struct kr_nsrep *ns, const struct sockaddr *addr, unsigned score, kr_nsrep_lru_t *cache)
{
	if (!ns || !cache || ns->addr[0].ip.sa_family == AF_UNSPEC) {
		return kr_error(EINVAL);
	}

	const char *addr_in = kr_nsrep_inaddr(ns->addr[0]);
	size_t addr_len = kr_nsrep_inaddr_len(ns->addr[0]);
	if (addr) { /* Caller provided specific address */
		if (addr->sa_family == AF_INET) {
			addr_in = (const char *)&((struct sockaddr_in *)addr)->sin_addr;
			addr_len = sizeof(struct in_addr);
		} else if (addr->sa_family == AF_INET6) {
			addr_in = (const char *)&((struct sockaddr_in6 *)addr)->sin6_addr;
			addr_len = sizeof(struct in6_addr);
		}
	}
	unsigned *cur = lru_set(cache, addr_in, addr_len);
	if (!cur) {
		return kr_error(ENOMEM);
	}
	/* Score limits */
	if (score > KR_NS_MAX_SCORE) {
		score = KR_NS_MAX_SCORE;
	}
	if (score <= KR_NS_GLUED) {
		score = KR_NS_GLUED + 1;
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

int kr_nsrep_update_rep(struct kr_nsrep *ns, unsigned reputation, kr_nsrep_lru_t *cache)
{
	if (!ns || !cache ) {
		return kr_error(EINVAL);
	}

	/* Store in the struct */
	ns->reputation = reputation;
	/* Store reputation in the LRU cache */
	unsigned *cur = lru_set(cache, (const char *)ns->name, knot_dname_size(ns->name));
	if (!cur) {
		return kr_error(ENOMEM);
	}
	*cur = reputation;
	return kr_ok();
}