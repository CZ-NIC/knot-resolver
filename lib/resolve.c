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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/descriptor.h>
#include <ucw/mempool.h>
#include "lib/resolve.h"
#include "lib/layer.h"
#include "lib/rplan.h"
#include "lib/layer/iterate.h"
#include "lib/dnssec/ta.h"
#if defined(ENABLE_COOKIES)
#include "lib/cookies/control.h"
#include "lib/cookies/helper.h"
#include "lib/cookies/nonce.h"
#endif /* defined(ENABLE_COOKIES) */

#define DEBUG_MSG(qry, fmt...) QRDEBUG((qry), "resl",  fmt)

/**
 * @internal Defer execution of current query.
 * The current layer state and input will be pushed to a stack and resumed on next iteration.
 */
static int consume_yield(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	knot_pkt_t *pkt_copy = knot_pkt_new(NULL, pkt->size, &req->pool);
	struct kr_layer_pickle *pickle = mm_alloc(&req->pool, sizeof(*pickle));
	if (pickle && pkt_copy && knot_pkt_copy(pkt_copy, pkt) == 0) {
		struct kr_query *qry = req->current_query;
		pickle->api = ctx->api;
		pickle->state = ctx->state;
		pickle->pkt = pkt_copy;
		pickle->next = qry->deferred;
		qry->deferred = pickle;
		return kr_ok();
	}
	return kr_error(ENOMEM);
}
static int begin_yield(knot_layer_t *ctx, void *module) { return kr_ok(); }
static int reset_yield(knot_layer_t *ctx) { return kr_ok(); }
static int finish_yield(knot_layer_t *ctx) { return kr_ok(); }
static int produce_yield(knot_layer_t *ctx, knot_pkt_t *pkt) { return kr_ok(); }

/** @internal Macro for iterating module layers. */
#define RESUME_LAYERS(from, req, qry, func, ...) \
    (req)->current_query = (qry); \
	for (size_t i = (from); i < (req)->ctx->modules->len; ++i) { \
		struct kr_module *mod = (req)->ctx->modules->at[i]; \
		if (mod->layer) { \
			struct knot_layer layer = {.state = (req)->state, .api = mod->layer(mod), .data = (req)}; \
			if (layer.api && layer.api->func) { \
				(req)->state = layer.api->func(&layer, ##__VA_ARGS__); \
				if ((req)->state == KNOT_STATE_YIELD) { \
					func ## _yield(&layer, ##__VA_ARGS__); \
					break; \
				} \
			} \
		} \
	} /* Invalidate current query. */ \
	(req)->current_query = NULL

/** @internal Macro for starting module iteration. */
#define ITERATE_LAYERS(req, qry, func, ...) RESUME_LAYERS(0, req, qry, func, ##__VA_ARGS__)

/** @internal Find layer id matching API. */
static inline size_t layer_id(struct kr_request *req, const struct knot_layer_api *api) {
	module_array_t *modules = req->ctx->modules;
	for (size_t i = 0; i < modules->len; ++i) {
		struct kr_module *mod = modules->at[i];
		if (mod->layer && mod->layer(mod) == api) {
			return i;
		}
	}
	return 0; /* Not found, try all. */
}

/* @internal We don't need to deal with locale here */
KR_CONST static inline bool isletter(unsigned chr)
{ return (chr | 0x20 /* tolower */) - 'a' <= 'z' - 'a'; }

/* Randomize QNAME letter case.
 * This adds 32 bits of randomness at maximum, but that's more than an average domain name length.
 * https://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00
 */
static void randomized_qname_case(knot_dname_t * restrict qname, uint32_t secret)
{
	assert(qname);
	const int len = knot_dname_size(qname) - 2; /* Skip first, last label. */
	for (int i = 0; i < len; ++i) {
		if (isletter(*++qname)) {
				*qname ^= ((secret >> (i & 31)) & 1) * 0x20;
		}
	}
}

/** Invalidate current NS/addr pair. */
static int invalidate_ns(struct kr_rplan *rplan, struct kr_query *qry)
{
	if (qry->ns.addr[0].ip.sa_family != AF_UNSPEC) {
		uint8_t *addr = kr_nsrep_inaddr(qry->ns.addr[0]);
		size_t addr_len = kr_nsrep_inaddr_len(qry->ns.addr[0]);
		/* @warning _NOT_ thread-safe */
		static knot_rdata_t rdata_arr[RDATA_ARR_MAX];
		knot_rdata_init(rdata_arr, addr_len, addr, 0);
		return kr_zonecut_del(&qry->zone_cut, qry->ns.name, rdata_arr);
	} else {
		return kr_zonecut_del(&qry->zone_cut, qry->ns.name, NULL);
	}
}

/** This turns of QNAME minimisation if there is a non-terminal between current zone cut, and name target.
 *  It save several minimization steps, as the zone cut is likely final one.
 */
static void check_empty_nonterms(struct kr_query *qry, knot_pkt_t *pkt, struct kr_cache *cache, uint32_t timestamp)
{
	if (qry->flags & QUERY_NO_MINIMIZE) {
		return;
	}

	const knot_dname_t *target = qry->sname;
	const knot_dname_t *cut_name = qry->zone_cut.name;
	if (!target || !cut_name)
		return;

	struct kr_cache_entry *entry = NULL;
	/* @note: The non-terminal must be direct child of zone cut (e.g. label distance <= 2),
	 *        otherwise this would risk leaking information to parent if the NODATA TTD > zone cut TTD. */
	int labels = knot_dname_labels(target, NULL) - knot_dname_labels(cut_name, NULL);
	while (target[0] && labels > 2) {
		target = knot_wire_next_label(target, NULL);
		--labels;
	}
	for (int i = 0; i < labels; ++i) {
		int ret = kr_cache_peek(cache, KR_CACHE_PKT, target, KNOT_RRTYPE_NS, &entry, &timestamp);
		if (ret == 0) { /* Either NXDOMAIN or NODATA, start here. */
			/* @todo We could stop resolution here for NXDOMAIN, but we can't because of broken CDNs */
			qry->flags |= QUERY_NO_MINIMIZE;
			kr_make_query(qry, pkt);
			return;
		}
		assert(target[0]);
		target = knot_wire_next_label(target, NULL);
	}
}

static int ns_fetch_cut(struct kr_query *qry, struct kr_request *req, knot_pkt_t *pkt)
{
	int ret = 0;

	/* Find closest zone cut from cache */
	struct kr_cache *cache = &req->ctx->cache;
	if (kr_cache_is_open(cache)) {
		/* If at/subdomain of parent zone cut, start from its encloser.
		 * This is for case when we get to a dead end (and need glue from parent), or DS refetch. */
		struct kr_query *parent = qry->parent;
		bool secured = (qry->flags & QUERY_DNSSEC_WANT);
		if (parent && parent->zone_cut.name[0] != '\0' && knot_dname_in(parent->zone_cut.name, qry->sname)) {
			const knot_dname_t *encloser = knot_wire_next_label(parent->zone_cut.name, NULL);
			ret = kr_zonecut_find_cached(req->ctx, &qry->zone_cut, encloser, qry->timestamp.tv_sec, &secured);
		} else {
			ret = kr_zonecut_find_cached(req->ctx, &qry->zone_cut, qry->sname, qry->timestamp.tv_sec, &secured);
		}
		/* Check if there's a non-terminal between target and current cut. */
		if (ret == 0) {
			check_empty_nonterms(qry, pkt, cache, qry->timestamp.tv_sec);
			/* Go insecure if the zone cut is provably insecure */
			if ((qry->flags & QUERY_DNSSEC_WANT) && !secured) {
				DEBUG_MSG(qry, "=> NS is provably without DS, going insecure\n");
				qry->flags &= ~QUERY_DNSSEC_WANT;
				qry->flags |= QUERY_DNSSEC_INSECURE;
			}
		}
	} else {
		ret = kr_error(ENOENT);
	}
	return ret;
}

static int ns_resolve_addr(struct kr_query *qry, struct kr_request *param)
{
	struct kr_rplan *rplan = &param->rplan;
	struct kr_context *ctx = param->ctx;


	/* Start NS queries from root, to avoid certain cases
	 * where a NS drops out of cache and the rest is unavailable,
	 * this would lead to dependency loop in current zone cut.
	 * Prefer IPv6 and continue with IPv4 if not available.
	 */
	uint16_t next_type = 0;
	if (!(qry->flags & QUERY_AWAIT_IPV6)) {
		next_type = KNOT_RRTYPE_AAAA;
		qry->flags |= QUERY_AWAIT_IPV6;
	} else if (!(qry->flags & QUERY_AWAIT_IPV4)) {
		next_type = KNOT_RRTYPE_A;
		qry->flags |= QUERY_AWAIT_IPV4;
		/* Hmm, no useable IPv6 then. */
		qry->ns.reputation |= KR_NS_NOIP6;
		kr_nsrep_update_rep(&qry->ns, qry->ns.reputation, ctx->cache_rep);
	}
	/* Bail out if the query is already pending or dependency loop. */
	if (!next_type || kr_rplan_satisfies(qry->parent, qry->ns.name, KNOT_CLASS_IN, next_type)) {
		/* Fall back to SBELT if root server query fails. */
		if (!next_type && qry->zone_cut.name[0] == '\0') {
			DEBUG_MSG(qry, "=> fallback to root hints\n");
			kr_zonecut_set_sbelt(ctx, &qry->zone_cut);
			qry->flags |= QUERY_NO_THROTTLE; /* Pick even bad SBELT servers */
			return kr_error(EAGAIN);
		}
		/* No IPv4 nor IPv6, flag server as unuseable. */
		DEBUG_MSG(qry, "=> unresolvable NS address, bailing out\n");
		qry->ns.reputation |= KR_NS_NOIP4 | KR_NS_NOIP6;
		kr_nsrep_update_rep(&qry->ns, qry->ns.reputation, ctx->cache_rep);
		invalidate_ns(rplan, qry);
		return kr_error(EHOSTUNREACH);
	}
	/* Push new query to the resolution plan */
	struct kr_query *next = kr_rplan_push(rplan, qry, qry->ns.name, KNOT_CLASS_IN, next_type);
	if (!next) {
		return kr_error(ENOMEM);
	}
	/* At the root level with no NS addresses, add SBELT subrequest. */
	int ret = 0;
	if (qry->zone_cut.name[0] == '\0') {
		ret = kr_zonecut_set_sbelt(ctx, &next->zone_cut);
		if (ret == 0) { /* Copy TA and key since it's the same cut to avoid lookup. */
			kr_zonecut_copy_trust(&next->zone_cut, &qry->zone_cut);
			kr_zonecut_set_sbelt(ctx, &qry->zone_cut); /* Add SBELT to parent in case query fails. */
			qry->flags |= QUERY_NO_THROTTLE; /* Pick even bad SBELT servers */
		}
	} else {
		next->flags |= QUERY_AWAIT_CUT;
	}
	return ret;
}

static int edns_put(knot_pkt_t *pkt)
{
	if (!pkt->opt_rr) {
		return kr_ok();
	}
	/* Reclaim reserved size. */
	int ret = knot_pkt_reclaim(pkt, knot_edns_wire_size(pkt->opt_rr));
	if (ret != 0) {
		return ret;
	}
	/* Write to packet. */
	assert(pkt->current == KNOT_ADDITIONAL);
	return knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, pkt->opt_rr, KNOT_PF_FREE);
}

static int edns_create(knot_pkt_t *pkt, knot_pkt_t *template, struct kr_request *req)
{
	pkt->opt_rr = knot_rrset_copy(req->ctx->opt_rr, &pkt->mm);
	size_t wire_size = knot_edns_wire_size(pkt->opt_rr);
#if defined(ENABLE_COOKIES)
	if (req->ctx->cookie_ctx.clnt.enabled) {
		wire_size += KR_COOKIE_OPT_MAX_LEN;
	}
#endif /* defined(ENABLE_COOKIES) */
	return knot_pkt_reserve(pkt, wire_size);
}

static int answer_prepare(knot_pkt_t *answer, knot_pkt_t *query, struct kr_request *req)
{
	if (knot_pkt_init_response(answer, query) != 0) {
		return kr_error(ENOMEM); /* Failed to initialize answer */
	}
	/* Handle EDNS in the query */
	if (knot_pkt_has_edns(query)) {
		int ret = edns_create(answer, query, req);
		if (ret != 0){
			return ret;
		}
		/* Set DO bit if set (DNSSEC requested). */
		if (knot_pkt_has_dnssec(query)) {
			knot_edns_set_do(answer->opt_rr);
		}
	}
	return kr_ok();
}

static void write_extra_records(rr_array_t *arr, knot_pkt_t *answer)
{
	for (size_t i = 0; i < arr->len; ++i) {
		knot_pkt_put(answer, 0, arr->at[i], 0);
	}
}

static int answer_finalize(struct kr_request *request, int state)
{
	/* Write authority records. */
	knot_pkt_t *answer = request->answer;
	if (answer->current < KNOT_AUTHORITY)
		knot_pkt_begin(answer, KNOT_AUTHORITY);
	write_extra_records(&request->authority, answer);
	/* Write additional records. */
	knot_pkt_begin(answer, KNOT_ADDITIONAL);
	write_extra_records(&request->additional, answer);
	/* Write EDNS information */
	if (answer->opt_rr) {
		int ret = edns_put(answer);
		if (ret != 0) {
			return ret;
		}
	}
	struct kr_rplan *rplan = &request->rplan;
	/* Always set SERVFAIL for bogus answers. */
	if (state == KNOT_STATE_FAIL && rplan->pending.len > 0) {
		struct kr_query *last = array_tail(rplan->pending);
		if ((last->flags & QUERY_DNSSEC_WANT) && (last->flags & QUERY_DNSSEC_BOGUS)) {
			knot_wire_set_rcode(answer->wire,KNOT_RCODE_SERVFAIL);
		}
	}
	/* Set AD=1 if succeeded and requested secured answer. */
	const bool has_ad = knot_wire_get_ad(answer->wire);
	knot_wire_clear_ad(answer->wire);
	if (state == KNOT_STATE_DONE && rplan->resolved.len > 0) {
		struct kr_query *last = array_tail(rplan->resolved);
		/* Do not set AD for RRSIG query, as we can't validate it. */
		const bool secure = (last->flags & QUERY_DNSSEC_WANT) && !(last->flags & QUERY_DNSSEC_INSECURE);
		if (has_ad && secure && knot_pkt_qtype(answer) != KNOT_RRTYPE_RRSIG) {
			knot_wire_set_ad(answer->wire);
		}
	}
	return kr_ok();
}

static int query_finalize(struct kr_request *request, struct kr_query *qry, knot_pkt_t *pkt)
{
	/* Randomize query case (if not in safemode) */
	qry->secret = (qry->flags & QUERY_SAFEMODE) ? 0 : kr_rand_uint(UINT32_MAX);
	knot_dname_t *qname_raw = (knot_dname_t *)knot_pkt_qname(pkt);
	randomized_qname_case(qname_raw, qry->secret);

	int ret = 0;
	knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	if (!(qry->flags & QUERY_SAFEMODE)) {
		ret = edns_create(pkt, request->answer, request);
		if (ret == 0) {
			/* Stub resolution (ask for +rd and +do) */
			if (qry->flags & QUERY_STUB) {
				knot_wire_set_rd(pkt->wire);
				if (knot_pkt_has_dnssec(request->answer))
					knot_edns_set_do(pkt->opt_rr);
			/* Full resolution (ask for +cd and +do) */
			} else if (qry->flags & QUERY_DNSSEC_WANT) {
				knot_edns_set_do(pkt->opt_rr);
				knot_wire_set_cd(pkt->wire);
			}
			ret = edns_put(pkt);
		}
	}
	return ret;
}

int kr_resolve_begin(struct kr_request *request, struct kr_context *ctx, knot_pkt_t *answer)
{
	/* Initialize request */
	request->ctx = ctx;
	request->answer = answer;
	request->options = ctx->options;
	request->state = KNOT_STATE_CONSUME;
	request->current_query = NULL;
	array_init(request->authority);
	array_init(request->additional);

	/* Expect first query */
	kr_rplan_init(&request->rplan, request, &request->pool);
	return KNOT_STATE_CONSUME;
}

#if defined(ENABLE_COOKIES)
/**
 * @brief Put cookie into answer packet.
 * @param clnt_sockaddr client socket address
 * @param srvr_sett settings structure of the server cookie algorithm
 * @param cookies obtained cookies
 * @param answer answer packet
 * @return state
 */
static int cookie_answer(const void *clnt_sockaddr,
                         const struct kr_cookie_settings *srvr_sett,
                         struct knot_dns_cookies *cookies, knot_pkt_t *answer)
{
	assert(srvr_sett && cookies && answer);

	/* Initialise answer. */
	knot_wire_set_qr(answer->wire);
	knot_wire_clear_aa(answer->wire);
	knot_wire_set_ra(answer->wire);
	knot_wire_set_rcode(answer->wire, KNOT_RCODE_NOERROR);

	struct knot_sc_private srvr_data = {
		.clnt_sockaddr = clnt_sockaddr,
		.secret_data = srvr_sett->current.secr->data,
		.secret_len = srvr_sett->current.secr->size
	};

	struct timeval tv;
	gettimeofday(&tv, NULL);

	struct kr_nonce_input nonce = {
		.rand = kr_rand_uint(UINT32_MAX),
		.time = tv.tv_sec
	};

	/* Add fres cookie into the answer. */
	int ret = kr_answer_write_cookie(&srvr_data,
	                                 cookies->cc, cookies->cc_len, &nonce,
	                                 kr_sc_algs[srvr_sett->current.alg_id], answer);
	if (ret != kr_ok()) {
		return KNOT_STATE_FAIL;
	}

	/* Check server cookie only with current settings. */
	ret = knot_sc_check(KR_NONCE_LEN, cookies, &srvr_data,
	                    kr_sc_algs[srvr_sett->current.alg_id]);
	if (ret != KNOT_EOK) {
		/* RFC7873 5.4 */
		kr_pkt_set_ext_rcode(answer, KNOT_RCODE_BADCOOKIE);
		return KNOT_STATE_FAIL | KNOT_STATE_DONE;
	}

	return KNOT_STATE_DONE;
}
#endif /* defined(ENABLE_COOKIES) */

static int resolve_query(struct kr_request *request, const knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;
	const knot_dname_t *qname = knot_pkt_qname(packet);
	uint16_t qclass = knot_pkt_qclass(packet);
	uint16_t qtype = knot_pkt_qtype(packet);
	struct kr_query *qry = kr_rplan_push(rplan, NULL, qname, qclass, qtype);
	if (!qry) {
#if defined(ENABLE_COOKIES)
		/* RFC7873 5.4 specifies a query for server cookie. Such query
		 * has QDCOUNT == 0 and contains a cookie option.
		 *
		 * The layers don't expect to handle queries with QDCOUNT != 1
		 * so such queries are handled directly here. */
		struct knot_dns_cookies cookies = { 0, };
		uint8_t *cookie_opt = kr_no_question_cookie_query(packet);
		if (cookie_opt && request->ctx->cookie_ctx.clnt.enabled) {
			if (kr_ok() != kr_parse_cookie_opt(cookie_opt,
			                                   &cookies)) {
				/* RFC7873 5.2.2 malformed cookie. */
				knot_wire_set_rcode(request->answer->wire,
				                    KNOT_RCODE_FORMERR);
				return KNOT_STATE_FAIL;
			}
		}

		return cookie_answer(request->qsource.addr,
		                     &request->ctx->cookie_ctx.srvr,
		                     &cookies, request->answer);
#else /* !defined(ENABLE_COOKIES) */
		return KNOT_STATE_FAIL;
#endif /* defined(ENABLE_COOKIES) */
	}

	/* Deferred zone cut lookup for this query. */
	qry->flags |= QUERY_AWAIT_CUT;
	/* Want DNSSEC if it's posible to secure this name (e.g. is covered by any TA) */
	map_t *negative_anchors = &request->ctx->negative_anchors;
	map_t *trust_anchors = &request->ctx->trust_anchors;
	if ((knot_wire_get_ad(packet->wire) || knot_pkt_has_dnssec(packet)) &&
	    kr_ta_covers(trust_anchors, qname) && !kr_ta_covers(negative_anchors, qname)) {
		qry->flags |= QUERY_DNSSEC_WANT;
	}

	/* Initialize answer packet */
	knot_pkt_t *answer = request->answer;
	knot_wire_set_qr(answer->wire);
	knot_wire_clear_aa(answer->wire);
	knot_wire_set_ra(answer->wire);
	knot_wire_set_rcode(answer->wire, KNOT_RCODE_NOERROR);
	if (qry->flags & QUERY_DNSSEC_WANT) {
		knot_wire_set_ad(answer->wire);
	}

	/* Expect answer, pop if satisfied immediately */
	request->qsource.packet = packet;
	ITERATE_LAYERS(request, qry, begin, request);
	request->qsource.packet = NULL;
	if (request->state == KNOT_STATE_DONE) {
		kr_rplan_pop(rplan, qry);
	}
	return request->state;
}

int kr_resolve_consume(struct kr_request *request, const struct sockaddr *src, knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;
	struct kr_context *ctx = request->ctx;

	/* Empty resolution plan, push packet as the new query */
	if (packet && kr_rplan_empty(rplan)) {
		if (answer_prepare(request->answer, packet, request) != 0) {
			return KNOT_STATE_FAIL;
		}
		return resolve_query(request, packet);
	}

	/* Different processing for network error */
	struct kr_query *qry = array_tail(rplan->pending);

	bool tried_tcp = (qry->flags & QUERY_TCP);
	if (!packet || packet->size == 0) {
		if (tried_tcp)
			request->state = KNOT_STATE_FAIL;
		else
			qry->flags |= QUERY_TCP;
	} else {
		/* Packet cleared, derandomize QNAME. */
		knot_dname_t *qname_raw = (knot_dname_t *)knot_pkt_qname(packet);
		if (qname_raw && qry->secret != 0) {
			randomized_qname_case(qname_raw, qry->secret);
		}
		request->state = KNOT_STATE_CONSUME;
		if (qry->flags & QUERY_CACHED) {
			ITERATE_LAYERS(request, qry, consume, packet);
		} else {
			struct timeval now;
			gettimeofday(&now, NULL);
			/* Fill in source and latency information. */
			request->upstream.rtt = time_diff(&qry->timestamp, &now);
			request->upstream.addr = src;
			ITERATE_LAYERS(request, qry, consume, packet);
			/* Clear temporary information */
			request->upstream.addr = NULL;
			request->upstream.rtt = 0;
		}
	}

	/* Track RTT for iterative answers */
	if (src && !(qry->flags & QUERY_CACHED)) {
		/* Sucessful answer, track RTT and lift any address resolution requests. */
		if (request->state != KNOT_STATE_FAIL) {
			/* Do not track in safe mode. */
			if (!(qry->flags & QUERY_SAFEMODE)) {
				struct timeval now;
				gettimeofday(&now, NULL);
				kr_nsrep_update_rtt(&qry->ns, src, time_diff(&qry->timestamp, &now), ctx->cache_rtt, KR_NS_UPDATE);
				WITH_DEBUG {
					char addr_str[INET6_ADDRSTRLEN];
					inet_ntop(src->sa_family, kr_inaddr(src), addr_str, sizeof(addr_str));
					DEBUG_MSG(qry, "<= server: '%s' rtt: %ld ms\n", addr_str, time_diff(&qry->timestamp, &now));
				}
			}
			/* Do not complete NS address resolution on soft-fail. */
			const int rcode = packet ? knot_wire_get_rcode(packet->wire) : 0;
			if (rcode != KNOT_RCODE_SERVFAIL && rcode != KNOT_RCODE_REFUSED) {
				qry->flags &= ~(QUERY_AWAIT_IPV6|QUERY_AWAIT_IPV4);
			} else { /* Penalize SERVFAILs. */
				kr_nsrep_update_rtt(&qry->ns, src, KR_NS_PENALTY, ctx->cache_rtt, KR_NS_ADD);
			}
		/* Do not penalize validation timeouts. */
		} else if (!(qry->flags & QUERY_DNSSEC_BOGUS)) {
			kr_nsrep_update_rtt(&qry->ns, src, KR_NS_TIMEOUT, ctx->cache_rtt, KR_NS_RESET);
			WITH_DEBUG {
				char addr_str[INET6_ADDRSTRLEN];
				inet_ntop(src->sa_family, kr_inaddr(src), addr_str, sizeof(addr_str));
				DEBUG_MSG(qry, "=> server: '%s' flagged as 'bad'\n", addr_str);
			}
		}
	}
	/* Resolution failed, invalidate current NS. */
	if (request->state == KNOT_STATE_FAIL) {
		invalidate_ns(rplan, qry);
		qry->flags &= ~QUERY_RESOLVED;
	}

	/* Pop query if resolved. */
	if (request->state == KNOT_STATE_YIELD) {
		return KNOT_STATE_PRODUCE; /* Requery */
	} else if (qry->flags & QUERY_RESOLVED) {
		kr_rplan_pop(rplan, qry);
	} else if (!tried_tcp && (qry->flags & QUERY_TCP)) {
		return KNOT_STATE_PRODUCE; /* Requery over TCP */
	} else { /* Clear query flags for next attempt */
		qry->flags &= ~(QUERY_CACHED|QUERY_TCP);
	}

	ITERATE_LAYERS(request, qry, reset);

	/* Do not finish with bogus answer. */
	if (qry->flags & QUERY_DNSSEC_BOGUS)  {
		return KNOT_STATE_FAIL;
	}

	return kr_rplan_empty(&request->rplan) ? KNOT_STATE_DONE : KNOT_STATE_PRODUCE;
}

/** @internal Spawn subrequest in current zone cut (no minimization or lookup). */
static struct kr_query *zone_cut_subreq(struct kr_rplan *rplan, struct kr_query *parent,
                           const knot_dname_t *qname, uint16_t qtype)
{
	struct kr_query *next = kr_rplan_push(rplan, parent, qname, parent->sclass, qtype);
	if (!next) {
		return NULL;
	}
	kr_zonecut_set(&next->zone_cut, parent->zone_cut.name);
	if (kr_zonecut_copy(&next->zone_cut, &parent->zone_cut) != 0 ||
	    kr_zonecut_copy_trust(&next->zone_cut, &parent->zone_cut) != 0) {
		return NULL;
	}
	next->flags |= QUERY_NO_MINIMIZE;
	if (parent->flags & QUERY_DNSSEC_WANT) {
		next->flags |= QUERY_DNSSEC_WANT;
	}
	return next;
}

/* @todo: Validator refactoring, keep this in driver for now. */
static int trust_chain_check(struct kr_request *request, struct kr_query *qry)
{
	struct kr_rplan *rplan = &request->rplan;
	map_t *trust_anchors = &request->ctx->trust_anchors;
	map_t *negative_anchors = &request->ctx->negative_anchors;

	/* Disable DNSSEC if it enters NTA. */
	if (kr_ta_get(negative_anchors, qry->zone_cut.name)){
		DEBUG_MSG(qry, ">< negative TA, going insecure\n");
		qry->flags &= ~QUERY_DNSSEC_WANT;
	}
	/* Enable DNSSEC if enters a new island of trust. */
	bool want_secured = (qry->flags & QUERY_DNSSEC_WANT);
	if (!want_secured && kr_ta_get(trust_anchors, qry->zone_cut.name)) {
		qry->flags |= QUERY_DNSSEC_WANT;
		want_secured = true;
		WITH_DEBUG {
		char qname_str[KNOT_DNAME_MAXLEN];
		knot_dname_to_str(qname_str, qry->zone_cut.name, sizeof(qname_str));
		DEBUG_MSG(qry, ">< TA: '%s'\n", qname_str);
		}
	}
	if (want_secured && !qry->zone_cut.trust_anchor) {
		knot_rrset_t *ta_rr = kr_ta_get(trust_anchors, qry->zone_cut.name);
		qry->zone_cut.trust_anchor = knot_rrset_copy(ta_rr, qry->zone_cut.pool);
	}
	/* Try to fetch missing DS (from above the cut). */
	const bool has_ta = (qry->zone_cut.trust_anchor != NULL);
	const knot_dname_t *ta_name = (has_ta ? qry->zone_cut.trust_anchor->owner : NULL);
	const bool refetch_ta = !has_ta || !knot_dname_is_equal(qry->zone_cut.name, ta_name);
	if (want_secured && refetch_ta) {
		/* @todo we could fetch the information from the parent cut, but we don't remember that now */
		struct kr_query *next = kr_rplan_push(rplan, qry, qry->zone_cut.name, qry->sclass, KNOT_RRTYPE_DS);
		if (!next) {
			return KNOT_STATE_FAIL;
		}
		next->flags |= QUERY_AWAIT_CUT|QUERY_DNSSEC_WANT;
		return KNOT_STATE_DONE;
	}
	/* Try to fetch missing DNSKEY (either missing or above current cut).
	 * Do not fetch if this is a DNSKEY subrequest to avoid circular dependency. */
	const bool is_dnskey_subreq = kr_rplan_satisfies(qry, ta_name, KNOT_CLASS_IN, KNOT_RRTYPE_DNSKEY);
	const bool refetch_key = has_ta && (!qry->zone_cut.key || !knot_dname_is_equal(ta_name, qry->zone_cut.key->owner));
	if (want_secured && refetch_key && !is_dnskey_subreq) {
		struct kr_query *next = zone_cut_subreq(rplan, qry, ta_name, KNOT_RRTYPE_DNSKEY);
		if (!next) {
			return KNOT_STATE_FAIL;
		}
		return KNOT_STATE_DONE;
	}

	return KNOT_STATE_PRODUCE;
}

/** @internal Check current zone cut status and credibility, spawn subrequests if needed. */
static int zone_cut_check(struct kr_request *request, struct kr_query *qry, knot_pkt_t *packet)
{
	map_t *trust_anchors = &request->ctx->trust_anchors;
	map_t *negative_anchors = &request->ctx->negative_anchors;

	/* Stub mode, just forward and do not solve cut. */
	if (qry->flags & QUERY_STUB) {
		return KNOT_STATE_PRODUCE;
	}

	/* The query wasn't resolved from cache,
	 * now it's the time to look up closest zone cut from cache. */
	if (qry->flags & QUERY_AWAIT_CUT) {
		/* Want DNSSEC if it's posible to secure this name (e.g. is covered by any TA) */
		if (!kr_ta_covers(negative_anchors, qry->zone_cut.name) &&
		    kr_ta_covers(trust_anchors, qry->zone_cut.name)) {
			qry->flags |= QUERY_DNSSEC_WANT;
		} else {
			qry->flags &= ~QUERY_DNSSEC_WANT;
		}
		int ret = ns_fetch_cut(qry, request, packet);
		if (ret != 0) {
			/* No cached cut found, start from SBELT and issue priming query. */
			if (ret == kr_error(ENOENT)) {
				ret = kr_zonecut_set_sbelt(request->ctx, &qry->zone_cut);
				if (ret != 0) {
					return KNOT_STATE_FAIL;
				}
				DEBUG_MSG(qry, "=> using root hints\n");
				qry->flags &= ~QUERY_AWAIT_CUT;
				return KNOT_STATE_DONE;
			} else {
				return KNOT_STATE_FAIL;
			}
		}
		/* Update minimized QNAME if zone cut changed */
		if (qry->zone_cut.name[0] != '\0' && !(qry->flags & QUERY_NO_MINIMIZE)) {
			if (kr_make_query(qry, packet) != 0) {
				return KNOT_STATE_FAIL;
			}
		}
		qry->flags &= ~QUERY_AWAIT_CUT;
	}

	/* Check trust chain */
	return trust_chain_check(request, qry);
}

int kr_resolve_produce(struct kr_request *request, struct sockaddr **dst, int *type, knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;
	unsigned ns_election_iter = 0;

	/* No query left for resolution */
	if (kr_rplan_empty(rplan)) {
		return KNOT_STATE_FAIL;
	}
	/* If we have deferred answers, resume them. */
	struct kr_query *qry = array_tail(rplan->pending);
	if (qry->deferred != NULL) {
		/* @todo: Refactoring validator, check trust chain before resuming. */
		switch(trust_chain_check(request, qry)) {
		case KNOT_STATE_FAIL: return KNOT_STATE_FAIL;
		case KNOT_STATE_DONE: return KNOT_STATE_PRODUCE;
		default: break;
		}
		DEBUG_MSG(qry, "=> resuming yielded answer\n");
		struct kr_layer_pickle *pickle = qry->deferred;
		request->state = KNOT_STATE_YIELD;
		RESUME_LAYERS(layer_id(request, pickle->api), request, qry, consume, pickle->pkt);
		qry->deferred = pickle->next;
	} else {
		/* Caller is interested in always tracking a zone cut, even if the answer is cached
		 * this is normally not required, and incurrs another cache lookups for cached answer. */
		if (qry->flags & QUERY_ALWAYS_CUT) {
			switch(zone_cut_check(request, qry, packet)) {
			case KNOT_STATE_FAIL: return KNOT_STATE_FAIL;
			case KNOT_STATE_DONE: return KNOT_STATE_PRODUCE;
			default: break;
			}
		}
		/* Resolve current query and produce dependent or finish */
		request->state = KNOT_STATE_PRODUCE;
		ITERATE_LAYERS(request, qry, produce, packet);
		if (request->state != KNOT_STATE_FAIL && knot_wire_get_qr(packet->wire)) {
			/* Produced an answer, consume it. */
			qry->secret = 0;
			request->state = KNOT_STATE_CONSUME;
			ITERATE_LAYERS(request, qry, consume, packet);
		}
	}
	switch(request->state) {
	case KNOT_STATE_FAIL: return request->state;
	case KNOT_STATE_CONSUME: break;
	case KNOT_STATE_DONE:
	default: /* Current query is done */
		if (qry->flags & QUERY_RESOLVED && request->state != KNOT_STATE_YIELD) {
			kr_rplan_pop(rplan, qry);
		}
		ITERATE_LAYERS(request, qry, reset);
		return kr_rplan_empty(rplan) ? KNOT_STATE_DONE : KNOT_STATE_PRODUCE;
	}

	/* This query has RD=0 or is ANY, stop here. */
	if (qry->stype == KNOT_RRTYPE_ANY || !knot_wire_get_rd(request->answer->wire)) {
		DEBUG_MSG(qry, "=> qtype is ANY or RD=0, bail out\n");
		return KNOT_STATE_FAIL;
	}

	/* Update zone cut, spawn new subrequests. */
	int state = zone_cut_check(request, qry, packet);
	switch(state) {
	case KNOT_STATE_FAIL: return KNOT_STATE_FAIL;
	case KNOT_STATE_DONE: return KNOT_STATE_PRODUCE;
	default: break;
	}

ns_election:

	/* If the query has got REFUSED & SERVFAIL, retry with current src up to KR_QUERY_NSRETRY_LIMIT.
	 * If the query has already selected a NS and is waiting for IPv4/IPv6 record,
	 * elect best address only, otherwise elect a completely new NS.
	 */
	if(++ns_election_iter >= KR_ITER_LIMIT) {
		DEBUG_MSG(qry, "=> couldn't converge NS selection, bail out\n");
		return KNOT_STATE_FAIL;
	}

	if (qry->flags & (QUERY_AWAIT_IPV4|QUERY_AWAIT_IPV6)) {
		kr_nsrep_elect_addr(qry, request->ctx);
	} else if (!qry->ns.name || !(qry->flags & (QUERY_TCP|QUERY_STUB|QUERY_BADCOOKIE_AGAIN))) { /* Keep NS when requerying/stub/badcookie. */
		/* Root DNSKEY must be fetched from the hints to avoid chicken and egg problem. */
		if (qry->sname[0] == '\0' && qry->stype == KNOT_RRTYPE_DNSKEY) {
			kr_zonecut_set_sbelt(request->ctx, &qry->zone_cut);
			qry->flags |= QUERY_NO_THROTTLE; /* Pick even bad SBELT servers */
		}
		kr_nsrep_elect(qry, request->ctx);
		if (qry->ns.score > KR_NS_MAX_SCORE) {
			DEBUG_MSG(qry, "=> no valid NS left\n");
			ITERATE_LAYERS(request, qry, reset);
			kr_rplan_pop(rplan, qry);
			return KNOT_STATE_PRODUCE;
		}
	}

	/* Resolve address records */
	if (qry->ns.addr[0].ip.sa_family == AF_UNSPEC) {
		int ret = ns_resolve_addr(qry, request);
		if (ret != 0) {
			qry->flags &= ~(QUERY_AWAIT_IPV6|QUERY_AWAIT_IPV4|QUERY_TCP);
			goto ns_election; /* Must try different NS */
		}
		ITERATE_LAYERS(request, qry, reset);
		return KNOT_STATE_PRODUCE;
	}

	/*
	 * Additional query is going to be finalised when calling
	 * kr_resolve_query_finalize().
	 */

	gettimeofday(&qry->timestamp, NULL);
	*dst = &qry->ns.addr[0].ip;
	*type = (qry->flags & QUERY_TCP) ? SOCK_STREAM : SOCK_DGRAM;
	return request->state;
}

#if defined(ENABLE_COOKIES)
/** Update DNS cookie data in packet. */
static bool outbound_request_update_cookies(struct kr_request *req,
                                            const struct sockaddr *dst)
{
	assert(req);

	/* RFC7873 4.1 strongly requires server address. */
	if (!dst) {
		return false;
	}

	struct kr_cookie_settings *clnt_sett = &req->ctx->cookie_ctx.clnt;

	/* Cookies disabled or packet has no ENDS section. */
	if (!clnt_sett->enabled) {
		return true;
	}

	/*
	 * RFC7873 4.1 recommends using also the client address. The matter is
	 * also discussed in section 6.
	 *
	 * Libuv does not offer a convenient way how to obtain a source IP
	 * address from a UDP handle that has been initialised using
	 * uv_udp_init(). The uv_udp_getsockname() fails because of the lazy
	 * socket initialisation.
	 *
	 * @note -- A solution might be opening a separate socket and trying
	 * to obtain the IP address from it.
	 */

	kr_request_put_cookie(&clnt_sett->current, req->ctx->cache_cookie,
	                      NULL, dst, req);

	return true;
}
#endif /* defined(ENABLE_COOKIES) */

int kr_resolve_query_finalize(struct kr_request *request, struct sockaddr *dst, int type, knot_pkt_t *packet)
{
	/* @todo: Update documentation if this function becomes approved. */

	struct kr_rplan *rplan = &request->rplan;

	if (knot_wire_get_qr(packet->wire) != 0) {
		return request->state;
	}

	/* No query left for resolution */
	if (kr_rplan_empty(rplan)) {
		return KNOT_STATE_FAIL;
	}
	/* If we have deferred answers, resume them. */
	struct kr_query *qry = array_tail(rplan->pending);

	/*
	 * @todo: Expose this point into the layers/modules?
	 * pros: Cookie control structure and LRU cache can be stored in module.
	 * cons: Additional stress on API before sending every packet.
	 */

#if defined(ENABLE_COOKIES)
	/* Update DNS cookies in request. */
	if (type == SOCK_DGRAM) { /* @todo: Add cookies also over TCP? */
		/* The actual server IP address is needed before generating the
		 * actual cookie. If we don't know the server address then we
		 * also don't know the actual cookie size.
		 * Also the resolver somehow mangles the query packets before
		 * building the query i.e. the space needed for the cookie
		 * cannot be allocated in the cookie layer. */
		if (!outbound_request_update_cookies(request, dst)) {
			return KNOT_STATE_FAIL;
		}
	}
#endif /* defined(ENABLE_COOKIES) */

	int ret = query_finalize(request, qry, packet);
	if (ret != 0) {
		return KNOT_STATE_FAIL;
	}

	WITH_DEBUG {
	char qname_str[KNOT_DNAME_MAXLEN], zonecut_str[KNOT_DNAME_MAXLEN], ns_str[INET6_ADDRSTRLEN], type_str[16];
	knot_dname_to_str(qname_str, knot_pkt_qname(packet), sizeof(qname_str));
	knot_dname_to_str(zonecut_str, qry->zone_cut.name, sizeof(zonecut_str));
	knot_rrtype_to_string(knot_pkt_qtype(packet), type_str, sizeof(type_str));
	for (size_t i = 0; i < KR_NSREP_MAXADDR; ++i) {
		struct sockaddr *addr = &qry->ns.addr[i].ip;
		if (addr->sa_family == AF_UNSPEC) {
			break;
		}
		inet_ntop(addr->sa_family, kr_nsrep_inaddr(qry->ns.addr[i]), ns_str, sizeof(ns_str));
		DEBUG_MSG(qry, "%s: '%s' score: %u zone cut: '%s' m12n: '%s' type: '%s'\n",
		          i == 0 ? "=> querying" : "   optional",
		          ns_str, qry->ns.score, zonecut_str, qname_str, type_str);
	}
	}

	return request->state;
}

int kr_resolve_finish(struct kr_request *request, int state)
{
#ifndef NDEBUG
	struct kr_rplan *rplan = &request->rplan;
#endif
	/* Finalize answer */
	if (answer_finalize(request, state) != 0) {
		state = KNOT_STATE_FAIL;
	}
	/* Error during procesing, internal failure */
	if (state != KNOT_STATE_DONE) {
		knot_pkt_t *answer = request->answer;
		if (knot_wire_get_rcode(answer->wire) == KNOT_RCODE_NOERROR) {
			knot_wire_set_rcode(answer->wire, KNOT_RCODE_SERVFAIL);
		}
	}

	request->state = state;
	ITERATE_LAYERS(request, NULL, finish);
	DEBUG_MSG(NULL, "finished: %d, queries: %zu, mempool: %zu B\n",
	          request->state, rplan->resolved.len, (size_t) mp_total_size(request->pool.ctx));
	return KNOT_STATE_DONE;
}

struct kr_rplan *kr_resolve_plan(struct kr_request *request)
{
	if (request) {
		return &request->rplan;
	}
	return NULL;
}

knot_mm_t *kr_resolve_pool(struct kr_request *request)
{
	if (request) {
		return &request->pool;
	}
	return NULL;
}

#undef DEBUG_MSG

