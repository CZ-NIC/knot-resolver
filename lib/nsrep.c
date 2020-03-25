/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <arpa/inet.h>

#include "lib/nsrep.h"
#include "lib/rplan.h"
#include "lib/resolve.h"
#include "lib/defines.h"
#include "lib/generic/pack.h"
#include "contrib/ucw/lib.h"

/** Some built-in unfairness ... */
#ifndef FAVOUR_IPV6
#define FAVOUR_IPV6 20 /* 20ms bonus for v6 */
#endif

/** @internal Macro to set address structure. */
#define ADDR_SET(sa, family, addr, len, port) do {\
    	memcpy(&sa ## _addr, (addr), (len)); \
    	sa ## _family = (family); \
	sa ## _port = htons(port); \
} while (0)

/** Update nameserver representation with current name/address pair. */
static void update_nsrep(struct kr_nsrep *ns, size_t pos, uint8_t *addr, size_t addr_len, int port)
{
	if (addr == NULL) {
		ns->addr[pos].ip.sa_family = AF_UNSPEC;
		return;
	}

	switch(addr_len) {
	case sizeof(struct in_addr):
		ADDR_SET(ns->addr[pos].ip4.sin, AF_INET, addr, addr_len, port); break;
	case sizeof(struct in6_addr):
		ADDR_SET(ns->addr[pos].ip6.sin6, AF_INET6, addr, addr_len, port); break;
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
			update_nsrep(ns, i, addr_val, len, KR_DNS_PORT);
		} else {
			break;
		}
	}
}

#undef ADDR_SET

/**
 * \param addr_set pack with one IP address per element */
static unsigned eval_addr_set(const pack_t *addr_set, struct kr_context *ctx,
			      struct kr_qflags opts, unsigned score, uint8_t *addr[])
{
	kr_nsrep_rtt_lru_t *rtt_cache = ctx->cache_rtt;
	kr_nsrep_rtt_lru_entry_t *rtt_cache_entry_ptr[KR_NSREP_MAXADDR] = { NULL, };
	assert (KR_NSREP_MAXADDR >= 2);
	unsigned rtt_cache_entry_score[KR_NSREP_MAXADDR] = { score, KR_NS_MAX_SCORE + 1, };
	uint64_t now = kr_now();

	/* Name server is better candidate if it has address record. */
	for (uint8_t *it = pack_head(*addr_set); it != pack_tail(*addr_set);
						it = pack_obj_next(it)) {
		void *val = pack_obj_val(it);
		size_t len = pack_obj_len(it);
		unsigned favour = 0;

		/* Get score for the current address. */
		kr_nsrep_rtt_lru_entry_t *cached = rtt_cache ?
						   lru_get_try(rtt_cache, val, len) :
						   NULL;
		unsigned cur_addr_score = 175;

		for (size_t i = 0; i < KR_NSREP_MAXADDR; ++i) {
			addr[i] = it;
			rtt_cache_entry_score[i] = cur_addr_score;
			rtt_cache_entry_ptr[i] = cached;
			break;
		}
	}

	return 175;
}

static int eval_nsrep(const knot_dname_t *owner, const pack_t *addr_set, struct kr_query *qry)
{
	struct kr_nsrep *ns = &qry->ns;
	struct kr_context *ctx = ns->ctx;
	unsigned score = KR_NS_MAX_SCORE;
	uint8_t *addr_choice[KR_NSREP_MAXADDR] = { NULL, };

	/* Favour nameservers with unknown addresses to probe them,
	 * otherwise discover the current best address for the NS. */
	if (addr_set->len == 0) {
		score = KR_NS_UNKNOWN;
	} else {
		score = eval_addr_set(addr_set, ctx, qry->flags, score, addr_choice);
	}

	update_nsrep_set(ns, owner, addr_choice, score);
	ns->reputation = 2;

	return kr_ok();
}

int kr_nsrep_set(struct kr_query *qry, size_t index, const struct sockaddr *sock)
{
	if (!qry) {
		return kr_error(EINVAL);
	}
	if (index >= KR_NSREP_MAXADDR) {
		return kr_error(ENOSPC);
	}

	if (!sock) {
		qry->ns.name = (const uint8_t *)"";
		qry->ns.addr[index].ip.sa_family = AF_UNSPEC;
		return kr_ok();
	}

	switch (sock->sa_family) {
	case AF_INET:
		if (qry->flags.NO_IPV4) {
			return kr_error(ENOENT);
		}
		qry->ns.addr[index].ip4 = *(const struct sockaddr_in *)sock;
		break;
	case AF_INET6:
		if (qry->flags.NO_IPV6) {
			return kr_error(ENOENT);
		}
		qry->ns.addr[index].ip6 = *(const struct sockaddr_in6 *)sock;
		break;
	default:
		qry->ns.addr[index].ip.sa_family = AF_UNSPEC;
		return kr_error(EINVAL);
	}

	qry->ns.name = (const uint8_t *)"";
	/* Reset score on first entry */
	if (index == 0) {
		qry->ns.score = KR_NS_UNKNOWN;
		qry->ns.reputation = 0;
	}

	/* Retrieve RTT from cache */
	struct kr_context *ctx = qry->ns.ctx;
	kr_nsrep_rtt_lru_entry_t *rtt_cache_entry = ctx
		? lru_get_try(ctx->cache_rtt, kr_inaddr(sock), kr_family_len(sock->sa_family))
		: NULL;
	if (rtt_cache_entry) {
		qry->ns.score = MIN(qry->ns.score, rtt_cache_entry->score);
	}

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
		//assert(!EINVAL);
		return kr_error(EINVAL);
	}

	// First we dump the nsset into a temporary array
	const int nsset_len = trie_weight(qry->zone_cut.nsset);
	struct {
		const knot_dname_t *name;
		const pack_t *addrs;
	} nsset[nsset_len];

	trie_it_t *it;
	int i = 0;
	for (it = trie_it_begin(qry->zone_cut.nsset); !trie_it_finished(it);
							trie_it_next(it), ++i) {
		/* we trust it's a correct dname */
		nsset[i].name = (const knot_dname_t *)trie_it_key(it, NULL);
		nsset[i].addrs = (const pack_t *)*trie_it_val(it);
	}
	trie_it_free(it);
	assert(i == nsset_len);

	// Finally we run the original algorithm, in this randomized order.
	struct kr_nsrep *ns = &qry->ns;
	ELECT_INIT(ns, ctx);
	int ret = kr_ok();
	for (i = 0; i < nsset_len; ++i) {
		ret = eval_nsrep(nsset[i].name, nsset[i].addrs, qry);
		if (ret) break;
	}

	// if (qry->ns.score <= KR_NS_MAX_SCORE && qry->ns.score >= KR_NS_LONG) {
	// 	/* This is a low-reliability probe,
	// 	 * go with TCP to get ICMP reachability check. */
	// 	qry->flags.TCP = true;
	// }
	return ret;
}

int kr_nsrep_elect_addr(struct kr_query *qry, struct kr_context *ctx)
{
	if (!qry || !ctx) {
		//assert(!EINVAL);
		return kr_error(EINVAL);
	}

	/* Get address list for this NS */
	struct kr_nsrep *ns = &qry->ns;
	ELECT_INIT(ns, ctx);
	pack_t *addr_set = kr_zonecut_find(&qry->zone_cut, ns->name);
	if (!addr_set) {
		return kr_error(ENOENT);
	}
	/* Evaluate addr list */
	uint8_t *addr_choice[KR_NSREP_MAXADDR] = { NULL, };
	unsigned score = eval_addr_set(addr_set, ctx, qry->flags, ns->score, addr_choice);
	update_nsrep_set(ns, ns->name, addr_choice, score);
	return kr_ok();
}

#undef ELECT_INIT

int kr_nsrep_update_rtt(struct kr_nsrep *ns, const struct sockaddr *addr,
			unsigned score, kr_nsrep_rtt_lru_t *cache, int umode)
{
	if (!cache || umode > KR_NS_MAX || umode < 0) {
		return kr_error(EINVAL);
	}

	/* Get `addr`, and later its raw string. */
	if (addr) {
		/* Caller provided specific address, OK. */
	} else if (ns != NULL) {
		addr = &ns->addr[0].ip;
	} else {
		assert(false && "kr_nsrep_update_rtt: don't know what address to update");
		return kr_error(EINVAL);
	}
	const char *addr_in = kr_inaddr(addr);
	size_t addr_len = kr_inaddr_len(addr);
	if (!addr_in || addr_len <= 0) {
		assert(false && "kr_nsrep_update_rtt: incorrect address");
		return kr_error(EINVAL);
	}

	bool is_new_entry = false;
	kr_nsrep_rtt_lru_entry_t  *cur = lru_get_new(cache, addr_in, addr_len,
						     (&is_new_entry));
	if (!cur) {
		return kr_ok();
	}
	if (score <= KR_NS_GLUED) {
		score = KR_NS_GLUED + 1;
	}
	/* If there's nothing to update, we reset it unless KR_NS_UPDATE_NORESET
	 * mode was requested.  New items are zeroed by LRU automatically. */
	if (is_new_entry && umode != KR_NS_UPDATE_NORESET) {
		umode = KR_NS_RESET;
	}
	unsigned new_score = 0;
	/* Update score, by default smooth over last two measurements. */
	switch (umode) {
	case KR_NS_UPDATE:
	case KR_NS_UPDATE_NORESET:
		new_score = (cur->score + score) / 2; break;
	case KR_NS_RESET:  new_score = score; break;
	case KR_NS_ADD:    new_score = MIN(KR_NS_MAX_SCORE - 1, cur->score + score); break;
	case KR_NS_MAX:    new_score = MAX(cur->score, score); break;
	default:           return kr_error(EINVAL);
	}
	/* Score limits */
	if (new_score > KR_NS_MAX_SCORE) {
		new_score = KR_NS_MAX_SCORE;
	}
	if (new_score >= KR_NS_TIMEOUT && cur->score < KR_NS_TIMEOUT) {
		/* Set the timestamp only when NS became "timeouted" */
		cur->tout_timestamp = kr_now();
	}
	cur->score = new_score;
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
	unsigned *cur = lru_get_new(cache, (const char *)ns->name,
				    knot_dname_size(ns->name), NULL);
	if (cur) {
		*cur = reputation;
	}
	return kr_ok();
}

int kr_nsrep_copy_set(struct kr_nsrep *dst, const struct kr_nsrep *src)
{
	if (!dst || !src ) {
		return kr_error(EINVAL);
	}

	memcpy(dst, src, sizeof(struct kr_nsrep));
	dst->name = (const uint8_t *)"";
	dst->score = KR_NS_UNKNOWN;
	dst->reputation = 0;

	return kr_ok();
}

int kr_nsrep_sort(struct kr_nsrep *ns, struct kr_context *ctx)
{
	if (!ns || !ctx) {
		assert(false);
		return kr_error(EINVAL);
	}

	kr_nsrep_rtt_lru_t *rtt_cache = ctx->cache_rtt;

	ns->reputation = 0;
	ns->score = KR_NS_MAX_SCORE + 1;

	if (ns->addr[0].ip.sa_family == AF_UNSPEC) {
		return kr_error(EINVAL);
	}

	/* Compute the scores.  Unfortunately there's no space for scores
	 * along the addresses. */
	unsigned scores[KR_NSREP_MAXADDR];
	int i;
	bool timeouted_address_is_already_selected = false;
	for (i = 0; i < KR_NSREP_MAXADDR; ++i) {
		const struct sockaddr *sa = &ns->addr[i].ip;
		if (sa->sa_family == AF_UNSPEC) {
			break;
		}
		kr_nsrep_rtt_lru_entry_t *rtt_cache_entry = lru_get_try(rtt_cache,
									kr_inaddr(sa),
									kr_family_len(sa->sa_family));
		if (!rtt_cache_entry) {
			scores[i] = 1; /* prefer unknown to probe RTT */
		} else if (rtt_cache_entry->score < KR_NS_FWD_TIMEOUT) {
			/* some probability to bump bad ones up for re-probe */
			scores[i] = rtt_cache_entry->score;
			/* The lower the rtt, the more likely it will be selected. */
			if (!kr_rand_coin(rtt_cache_entry->score, KR_NS_FWD_TIMEOUT)) {
				scores[i] = 1;
			}
		} else {
			uint64_t now = kr_now();
			uint64_t elapsed = now - rtt_cache_entry->tout_timestamp;
			scores[i] = KR_NS_MAX_SCORE + 1;
			elapsed = elapsed > UINT_MAX ? UINT_MAX : elapsed;
			if (elapsed > ctx->cache_rtt_tout_retry_interval &&
			    !timeouted_address_is_already_selected) {
				scores[i] = 1;
				rtt_cache_entry->tout_timestamp = now;
				timeouted_address_is_already_selected = true;
			}
		}

		/* Give advantage to IPv6. */
		if (scores[i] <= KR_NS_MAX_SCORE && sa->sa_family == AF_INET) {
			scores[i] += FAVOUR_IPV6;
		}

		if (VERBOSE_STATUS) {
			kr_log_verbose("[     ][nsre] score %d for %s;\t cached RTT: %d\n",
					scores[i], kr_straddr(sa),
					rtt_cache_entry ? rtt_cache_entry->score : -1);
		}
	}

	/* Select-sort the addresses. */
	const int count = i;
	for (i = 0; i < count - 1; ++i) {
		/* find min from i onwards */
		int min_i = i;
		for (int j = i + 1; j < count; ++j) {
			if (scores[j] < scores[min_i]) {
				min_i = j;
			}
		}
		/* swap the indices */
		if (min_i != i) {
			SWAP(scores[min_i], scores[i]);
			SWAP(ns->addr[min_i], ns->addr[i]);
		}
	}

	if (count > 0) {
		ns->score = scores[0];
		ns->reputation = 0;
	}

	return kr_ok();
}
