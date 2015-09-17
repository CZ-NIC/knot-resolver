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

#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/descriptor.h>
#include <ucw/mempool.h>
#include "lib/resolve.h"
#include "lib/layer.h"
#include "lib/rplan.h"
#include "lib/layer/iterate.h"
#include "lib/dnssec/ta.h"

#define DEBUG_MSG(fmt...) QRDEBUG(kr_rplan_current(rplan), "resl",  fmt)

/** @internal Macro for iterating module layers. */
#define ITERATE_LAYERS(req, func, ...) \
	for (unsigned i = 0; i < (req)->ctx->modules->len; ++i) { \
		struct kr_module *mod = (req)->ctx->modules->at[i]; \
		if (mod->layer ) { \
			struct knot_layer layer = {.state = (req)->state, .api = mod->layer(mod), .data = (req)}; \
			if (layer.api && layer.api->func) { \
				(req)->state = layer.api->func(&layer, ##__VA_ARGS__); \
			} \
		} \
	}

/* Randomize QNAME letter case.
 * This adds 32 bits of randomness at maximum, but that's more than an average domain name length.
 * https://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00
 */
static void randomized_qname_case(knot_dname_t *qname, unsigned secret)
{
	unsigned k = 0;
	while (*qname != '\0') {
		for (unsigned i = *qname; i--;) {
			int chr = qname[i + 1];
			if (isalpha(chr)) {
				if (secret & (1 << k)) {
					qname[i + 1] ^= 0x20;
				}
				k = (k + 1) % (sizeof(secret) * CHAR_BIT);
			}
		}
		qname = (uint8_t *)knot_wire_next_label(qname, NULL);
	}
}

/** Invalidate current NS/addr pair. */
static int invalidate_ns(struct kr_rplan *rplan, struct kr_query *qry)
{
	if (qry->ns.addr.ip.sa_family != AF_UNSPEC) {
		uint8_t *addr = kr_nsrep_inaddr(qry->ns.addr);
		size_t addr_len = kr_nsrep_inaddr_len(qry->ns.addr);
		knot_rdata_t rdata[knot_rdata_array_size(addr_len)];
		knot_rdata_init(rdata, addr_len, addr, 0);
		return kr_zonecut_del(&qry->zone_cut, qry->ns.name, rdata);
	} else {
		return kr_zonecut_del(&qry->zone_cut, qry->ns.name, NULL);
	}
}

static int ns_fetch_cut(struct kr_query *qry, struct kr_request *req, bool secured)
{
	struct kr_cache_txn txn;
	int ret = 0;

	/* If at/subdomain of parent zone cut, start top-down search */
	struct kr_query *parent = qry->parent;
	if (parent && knot_dname_in(parent->zone_cut.name, qry->sname)) {
		return kr_zonecut_set_sbelt(req->ctx, &qry->zone_cut);
	}
	/* Find closest zone cut from cache */
	if (kr_cache_txn_begin(&req->ctx->cache, &txn, NAMEDB_RDONLY) != 0) {
		ret = kr_zonecut_set_sbelt(req->ctx, &qry->zone_cut);
	} else {
		ret = kr_zonecut_find_cached(req->ctx, &qry->zone_cut, qry->sname, &txn, qry->timestamp.tv_sec, secured);
		kr_cache_txn_abort(&txn);
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
		/* No IPv4 nor IPv6, flag server as unuseable. */
		DEBUG_MSG("=> unresolvable NS address, bailing out\n");
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

	next->flags |= QUERY_AWAIT_CUT;
	return kr_ok();
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
	/* Set DO bit if set (DNSSEC requested). */
	if (knot_pkt_has_dnssec(template) || (req->options & QUERY_DNSSEC_WANT)) {
		knot_edns_set_do(pkt->opt_rr);
	}
	return knot_pkt_reserve(pkt, knot_edns_wire_size(pkt->opt_rr));
}

static int answer_prepare(knot_pkt_t *answer, knot_pkt_t *query, struct kr_request *req)
{
	if (!knot_wire_get_rd(query->wire)) {
		return kr_error(ENOSYS); /* Only recursive service */
	}
	if (knot_pkt_init_response(answer, query) != 0) {
		return kr_error(ENOMEM); /* Failed to initialize answer */
	}
	/* Handle EDNS in the query */
	if (knot_pkt_has_edns(query)) {
		int ret = edns_create(answer, query, req);
		if (ret != 0){
			return ret;
		}
	}
	return kr_ok();
}

static int answer_finalize(struct kr_request *request, int state)
{
	/* Write EDNS information */
	knot_pkt_t *answer = request->answer;
	knot_pkt_begin(answer, KNOT_ADDITIONAL);
	if (answer->opt_rr) {
		int ret = edns_put(answer);
		if (ret != 0) {
			return ret;
		}
	}
	/* Set AD=1 if succeeded and requested secured answer. */
	if (state == KNOT_STATE_DONE && (request->options & QUERY_DNSSEC_WANT)) {
		knot_wire_set_ad(answer->wire);
	}
	return kr_ok();
}

static int query_finalize(struct kr_request *request, knot_pkt_t *pkt)
{
	/* Randomize query case (if not in safemode) */
	struct kr_query *qry = kr_rplan_current(&request->rplan);
	qry->secret = (qry->flags & QUERY_SAFEMODE) ? 0 : kr_rand_uint(UINT32_MAX);
	knot_dname_t *qname_raw = (knot_dname_t *)knot_pkt_qname(pkt);
	randomized_qname_case(qname_raw, qry->secret);

	int ret = 0;
	knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	if (!(qry->flags & QUERY_SAFEMODE)) {
		ret = edns_create(pkt, request->answer, request);
		if (ret == 0) {
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

	/* Expect first query */
	kr_rplan_init(&request->rplan, request, &request->pool);
	return KNOT_STATE_CONSUME;
}

int kr_resolve_query(struct kr_request *request, const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	struct kr_rplan *rplan = &request->rplan;
	struct kr_query *qry = kr_rplan_push(rplan, NULL, qname, qclass, qtype);
	if (!qry) {
		return KNOT_STATE_FAIL;
	}

	/* Deferred zone cut lookup for this query. */
	qry->flags |= QUERY_AWAIT_CUT;

	/* Initialize answer packet */
	knot_pkt_t *answer = request->answer;
	knot_wire_set_qr(answer->wire);
	knot_wire_clear_aa(answer->wire);
	knot_wire_set_ra(answer->wire);
	knot_wire_set_rcode(answer->wire, KNOT_RCODE_NOERROR);

	/* Expect answer, pop if satisfied immediately */
	ITERATE_LAYERS(request, begin, request);
	if (request->state == KNOT_STATE_DONE) {
		kr_rplan_pop(rplan, qry);
	}
	return request->state;
}

int kr_resolve_consume(struct kr_request *request, knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;
	struct kr_context *ctx = request->ctx;
	struct kr_query *qry = kr_rplan_current(rplan);

	/* Empty resolution plan, push packet as the new query */
	if (packet && kr_rplan_empty(rplan)) {
		if (answer_prepare(request->answer, packet, request) != 0) {
			return KNOT_STATE_FAIL;
		}
		/* Start query resolution */
		const knot_dname_t *qname = knot_pkt_qname(packet);
		uint16_t qclass = knot_pkt_qclass(packet);
		uint16_t qtype = knot_pkt_qtype(packet);
		return kr_resolve_query(request, qname, qclass, qtype);
	}

	/* Different processing for network error */
	if (!packet || packet->size == 0) {
		/* Network error, retry over TCP. */
		if (!(qry->flags & QUERY_TCP)) {
			DEBUG_MSG("=> NS unreachable, retrying over TCP\n");
			qry->flags |= QUERY_TCP;
			return KNOT_STATE_PRODUCE;
		}
		request->state = KNOT_STATE_FAIL;
	} else {
		/* Packet cleared, derandomize QNAME. */
		knot_dname_t *qname_raw = (knot_dname_t *)knot_pkt_qname(packet);
		if (qname_raw && qry->secret != 0) {
			randomized_qname_case(qname_raw, qry->secret);
		}
		ITERATE_LAYERS(request, consume, packet);
	}

	/* Resolution failed, invalidate current NS. */
	if (request->state == KNOT_STATE_FAIL) {
		kr_nsrep_update_rtt(&qry->ns, KR_NS_TIMEOUT, ctx->cache_rtt);
		invalidate_ns(rplan, qry);
		qry->flags &= ~QUERY_RESOLVED;
	/* Track RTT for iterative answers */
	} else if (!(qry->flags & QUERY_CACHED)) {
		struct timeval now;
		gettimeofday(&now, NULL);
		kr_nsrep_update_rtt(&qry->ns, time_diff(&qry->timestamp, &now), ctx->cache_rtt);
		/* Sucessful answer, lift any address resolution requests. */
		qry->flags &= ~(QUERY_AWAIT_IPV6|QUERY_AWAIT_IPV4);
	}

	/* Pop query if resolved. */
	if (qry->flags & QUERY_RESOLVED) {
		kr_rplan_pop(rplan, qry);
	} else { /* Clear query flags for next attempt */
		qry->flags &= ~(QUERY_CACHED|QUERY_TCP);
	}

	ITERATE_LAYERS(request, reset);

	/* Do not finish with bogus answer. */
	if (qry->flags & QUERY_DNSSEC_BOGUS)  {
		return KNOT_STATE_FAIL;
	}

	return kr_rplan_empty(&request->rplan) ? KNOT_STATE_DONE : KNOT_STATE_PRODUCE;
}

int kr_resolve_produce(struct kr_request *request, struct sockaddr **dst, int *type, knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	unsigned ns_election_iter = 0;
	
	/* No query left for resolution */
	if (kr_rplan_empty(rplan)) {
		return KNOT_STATE_FAIL;
	}

	/* Resolve current query and produce dependent or finish */
	ITERATE_LAYERS(request, produce, packet);
	if (request->state != KNOT_STATE_FAIL && knot_wire_get_qr(packet->wire)) {
		/* Produced an answer, consume it. */
		qry->secret = 0;
		request->state = KNOT_STATE_CONSUME;
		ITERATE_LAYERS(request, consume, packet);
	}
	switch(request->state) {
	case KNOT_STATE_FAIL: return request->state; break;
	case KNOT_STATE_CONSUME: break;
	case KNOT_STATE_DONE:
	default: /* Current query is done */
		if (qry->flags & QUERY_RESOLVED) {
			kr_rplan_pop(rplan, qry);
		}
		ITERATE_LAYERS(request, reset);
		return kr_rplan_empty(rplan) ? KNOT_STATE_DONE : KNOT_STATE_PRODUCE;
	}

	/* The query wasn't resolved from cache,
	 * now it's the time to look up closest zone cut from cache.
	 */
	 /* Always try with DNSSEC if it finds island of trust. */
	 /* @todo this interface is going to change */
	if (kr_ta_contains(&global_trust_anchors, qry->zone_cut.name)) {
		request->options |= QUERY_DNSSEC_WANT;
		DEBUG_MSG(">< entered island of trust\n");
	}
	bool want_secured = (request->options & QUERY_DNSSEC_WANT);
	if (qry->flags & QUERY_AWAIT_CUT) {
		int ret = ns_fetch_cut(qry, request, want_secured);
		if (ret != 0) {
			return KNOT_STATE_FAIL;
		}
		/* Update minimized QNAME if zone cut changed */
		if (qry->zone_cut.name[0] != '\0' && !(qry->flags & QUERY_NO_MINIMIZE)) {
			if (kr_make_query(qry, packet) != 0) {
				return KNOT_STATE_FAIL;
			}
		}
		qry->flags &= ~QUERY_AWAIT_CUT;
	}

	/* fetch missing DS record. */
	if ((qry->flags & QUERY_AWAIT_DS) && (qry->zone_cut.missing_name)) {
		struct kr_query *next = kr_rplan_push(rplan, qry, qry->zone_cut.missing_name, KNOT_CLASS_IN, KNOT_RRTYPE_DS);
		if (!next) {
			return KNOT_STATE_FAIL;
		}
		kr_zonecut_set(&next->zone_cut, qry->zone_cut.parent_name);
		int ret = kr_zonecut_copy(&next->zone_cut, &qry->zone_cut);
		if (ret != 0) {
			return KNOT_STATE_FAIL;
		}
		ret = kr_zonecut_copy_trust(&next->zone_cut, &qry->zone_cut);
		if (ret != 0) {
			return KNOT_STATE_FAIL;
		}
		/* The current trust anchor and keys cannot be used. */
		knot_rrset_free(&qry->zone_cut.key, qry->zone_cut.pool);
		knot_rrset_free(&qry->zone_cut.trust_anchor, qry->zone_cut.pool);
		qry->flags &= ~QUERY_AWAIT_DS;
		return KNOT_STATE_PRODUCE;
	}

	/* Try to fetch missing DNSKEY. */
	if (want_secured && !qry->zone_cut.key && qry->stype != KNOT_RRTYPE_DNSKEY) {
		struct kr_query *next = kr_rplan_push(rplan, qry, qry->zone_cut.name, KNOT_CLASS_IN, KNOT_RRTYPE_DNSKEY);
		if (!next) {
			return KNOT_STATE_FAIL;
		}
		kr_zonecut_set(&next->zone_cut, qry->zone_cut.name);
		int ret = kr_zonecut_copy(&next->zone_cut, &qry->zone_cut);
		if (ret != 0) {
			return KNOT_STATE_FAIL;
		}
		ret = kr_zonecut_copy_trust(&next->zone_cut, &qry->zone_cut);
		if (ret != 0) {
			return KNOT_STATE_FAIL;
		}
		return KNOT_STATE_PRODUCE;
	}
ns_election:

	/* If the query has already selected a NS and is waiting for IPv4/IPv6 record,
	 * elect best address only, otherwise elect a completely new NS.
	 */
	if(++ns_election_iter >= KR_ITER_LIMIT) {
		DEBUG_MSG("=> couldn't agree NS decision, report this\n");
		return KNOT_STATE_FAIL;
	}
	if (qry->flags & (QUERY_AWAIT_IPV4|QUERY_AWAIT_IPV6)) {
		kr_nsrep_elect_addr(qry, request->ctx);
	} else if (!(qry->flags & QUERY_TCP)) { /* Keep address when TCP retransmit. */
		kr_nsrep_elect(qry, request->ctx);
		if (qry->ns.score > KR_NS_MAX_SCORE) {
			DEBUG_MSG("=> no valid NS left\n");
			ITERATE_LAYERS(request, reset);
			kr_rplan_pop(rplan, qry);
			return KNOT_STATE_PRODUCE;
		}
	}

	/* Resolve address records */
	if (qry->ns.addr.ip.sa_family == AF_UNSPEC) {
		if (ns_resolve_addr(qry, request) != 0) {
			qry->flags &= ~(QUERY_AWAIT_IPV6|QUERY_AWAIT_IPV4|QUERY_TCP);
			goto ns_election; /* Must try different NS */
		}
		ITERATE_LAYERS(request, reset);
		return KNOT_STATE_PRODUCE;
	}

	/* Prepare additional query */
	int ret = query_finalize(request, packet);
	if (ret != 0) {
		return KNOT_STATE_FAIL;
	}

	WITH_DEBUG {
	char qname_str[KNOT_DNAME_MAXLEN], zonecut_str[KNOT_DNAME_MAXLEN], ns_str[SOCKADDR_STRLEN], type_str[16];
	knot_dname_to_str(qname_str, knot_pkt_qname(packet), sizeof(qname_str));
	struct sockaddr *addr = &qry->ns.addr.ip;
	inet_ntop(addr->sa_family, kr_nsrep_inaddr(qry->ns.addr), ns_str, sizeof(ns_str));
	knot_dname_to_str(zonecut_str, qry->zone_cut.name, sizeof(zonecut_str));
	knot_rrtype_to_string(knot_pkt_qtype(packet), type_str, sizeof(type_str));
	DEBUG_MSG("=> querying: '%s' score: %u zone cut: '%s' m12n: '%s' type: '%s'\n",
		ns_str, qry->ns.score, zonecut_str, qname_str, type_str);
	}

	gettimeofday(&qry->timestamp, NULL);
	*dst = &qry->ns.addr.ip;
	*type = (qry->flags & QUERY_TCP) ? SOCK_STREAM : SOCK_DGRAM;
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

	ITERATE_LAYERS(request, finish);
	DEBUG_MSG("finished: %d, mempool: %zu B\n", state, (size_t) mp_total_size(request->pool.ctx));
	return KNOT_STATE_DONE;
}

struct kr_rplan *kr_resolve_plan(struct kr_request *request)
{
	if (request) {
		return &request->rplan;
	}
	return NULL;
}
