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
		knot_rdata_t rdata[knot_rdata_array_size(addr_len)];
		knot_rdata_init(rdata, addr_len, addr, 0);
		return kr_zonecut_del(&qry->zone_cut, qry->ns.name, rdata);
	} else {
		return kr_zonecut_del(&qry->zone_cut, qry->ns.name, NULL);
	}
}

/** This turns of QNAME minimisation if there is a non-terminal between current zone cut, and name target.
 *  It save several minimization steps, as the zone cut is likely final one.
 */
static void check_empty_nonterms(struct kr_query *qry, knot_pkt_t *pkt, struct kr_cache_txn *txn, uint32_t timestamp)
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
		int ret = kr_cache_peek(txn, KR_CACHE_PKT, target, KNOT_RRTYPE_NS, &entry, &timestamp);
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
	struct kr_cache_txn txn;
	if (kr_cache_txn_begin(&req->ctx->cache, &txn, NAMEDB_RDONLY) == 0) {
		/* If at/subdomain of parent zone cut, start from its encloser.
		 * This is for case when we get to a dead end (and need glue from parent), or DS refetch. */
		struct kr_query *parent = qry->parent;
		bool secured = (qry->flags & QUERY_DNSSEC_WANT);
		if (parent && parent->zone_cut.name[0] != '\0' && knot_dname_in(parent->zone_cut.name, qry->sname)) {
			const knot_dname_t *encloser = knot_wire_next_label(parent->zone_cut.name, NULL);
			ret = kr_zonecut_find_cached(req->ctx, &qry->zone_cut, encloser, &txn, qry->timestamp.tv_sec, &secured);
		} else {
			ret = kr_zonecut_find_cached(req->ctx, &qry->zone_cut, qry->sname, &txn, qry->timestamp.tv_sec, &secured);
		}
		/* Check if there's a non-terminal between target and current cut. */
		if (ret == 0) {
			check_empty_nonterms(qry, pkt, &txn, qry->timestamp.tv_sec);
			/* Go insecure if the zone cut is provably insecure */
			if ((qry->flags & QUERY_DNSSEC_WANT) && !secured) {
				DEBUG_MSG(qry, "=> NS is provably without DS, going insecure\n");
				qry->flags &= ~QUERY_DNSSEC_WANT;
				qry->flags |= QUERY_DNSSEC_INSECURE;
			}
		}
		kr_cache_txn_abort(&txn);
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
	return knot_pkt_reserve(pkt, knot_edns_wire_size(pkt->opt_rr));
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
	/* Set AD=1 if succeeded and requested secured answer. */
	struct kr_rplan *rplan = &request->rplan;
	if (state == KNOT_STATE_DONE && !EMPTY_LIST(rplan->resolved)) {
		struct kr_query *last = TAIL(rplan->resolved);
		/* Do not set AD for RRSIG query, as we can't validate it. */
		if ((last->flags & QUERY_DNSSEC_WANT) && knot_pkt_has_dnssec(answer) &&
			knot_pkt_qtype(answer) != KNOT_RRTYPE_RRSIG) {
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
	request->qsource.key = NULL;
	request->qsource.addr = NULL;
	array_init(request->authority);
	array_init(request->additional);

	/* Expect first query */
	kr_rplan_init(&request->rplan, request, &request->pool);
	return KNOT_STATE_CONSUME;
}

static int resolve_query(struct kr_request *request, const knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;
	const knot_dname_t *qname = knot_pkt_qname(packet);
	uint16_t qclass = knot_pkt_qclass(packet);
	uint16_t qtype = knot_pkt_qtype(packet);
	struct kr_query *qry = kr_rplan_push(rplan, NULL, qname, qclass, qtype);
	if (!qry) {
		return KNOT_STATE_FAIL;
	}

	/* Deferred zone cut lookup for this query. */
	qry->flags |= QUERY_AWAIT_CUT;
	/* Want DNSSEC if it's posible to secure this name (e.g. is covered by any TA) */
	map_t *negative_anchors = &request->ctx->negative_anchors;
	map_t *trust_anchors = &request->ctx->trust_anchors;
	if (knot_pkt_has_dnssec(packet) &&
	    kr_ta_covers(trust_anchors, qname) && !kr_ta_covers(negative_anchors, qname)) {
		qry->flags |= QUERY_DNSSEC_WANT;
	}

	/* Initialize answer packet */
	knot_pkt_t *answer = request->answer;
	knot_wire_set_qr(answer->wire);
	knot_wire_clear_aa(answer->wire);
	knot_wire_set_ra(answer->wire);
	knot_wire_set_rcode(answer->wire, KNOT_RCODE_NOERROR);

	/* Expect answer, pop if satisfied immediately */
	ITERATE_LAYERS(request, qry, begin, request);
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
	struct kr_query *qry = TAIL(rplan->pending);
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
		ITERATE_LAYERS(request, qry, consume, packet);
	}

	/* Track RTT for iterative answers */
	if (!(qry->flags & QUERY_CACHED)) {
		struct timeval now;
		gettimeofday(&now, NULL);
		kr_nsrep_update_rtt(&qry->ns, src, time_diff(&qry->timestamp, &now), ctx->cache_rtt);
		/* Sucessful answer, lift any address resolution requests. */
		if (request->state != KNOT_STATE_FAIL)
			qry->flags &= ~(QUERY_AWAIT_IPV6|QUERY_AWAIT_IPV4);
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
	struct kr_query *qry = TAIL(rplan->pending);
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

	/* If the query has already selected a NS and is waiting for IPv4/IPv6 record,
	 * elect best address only, otherwise elect a completely new NS.
	 */
	if(++ns_election_iter >= KR_ITER_LIMIT) {
		DEBUG_MSG(qry, "=> couldn't converge NS selection, bail out\n");
		return KNOT_STATE_FAIL;
	}
	if (qry->flags & (QUERY_AWAIT_IPV4|QUERY_AWAIT_IPV6)) {
		kr_nsrep_elect_addr(qry, request->ctx);
	} else if (!qry->ns.name || !(qry->flags & (QUERY_TCP|QUERY_STUB))) { /* Keep NS when requerying/stub. */
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

	/* Prepare additional query */
	int ret = query_finalize(request, qry, packet);
	if (ret != 0) {
		return KNOT_STATE_FAIL;
	}

	WITH_DEBUG {
	char qname_str[KNOT_DNAME_MAXLEN], zonecut_str[KNOT_DNAME_MAXLEN], ns_str[SOCKADDR_STRLEN], type_str[16];
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

	gettimeofday(&qry->timestamp, NULL);
	*dst = &qry->ns.addr[0].ip;
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

	request->state = state;
	ITERATE_LAYERS(request, NULL, finish);
	DEBUG_MSG(NULL, "finished: %d, queries: %zu, mempool: %zu B\n",
	          request->state, list_size(&rplan->resolved), (size_t) mp_total_size(request->pool.ctx));
	return KNOT_STATE_DONE;
}

struct kr_rplan *kr_resolve_plan(struct kr_request *request)
{
	if (request) {
		return &request->rplan;
	}
	return NULL;
}

mm_ctx_t *kr_resolve_pool(struct kr_request *request)
{
	if (request) {
		return &request->pool;
	}
	return NULL;
}

#undef DEBUG_MSG

