/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <inttypes.h>
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
#include "lib/dnssec.h"
#if defined(ENABLE_COOKIES)
#include "lib/cookies/control.h"
#include "lib/cookies/helper.h"
#include "lib/cookies/nonce.h"
#else /* Define compatibility macros */
#define KNOT_EDNS_OPTION_COOKIE 10
#endif /* defined(ENABLE_COOKIES) */

#define VERBOSE_MSG(qry, fmt...) QRVERBOSE((qry), "resl",  fmt)

bool kr_rank_check(uint8_t rank)
{
	switch (rank & ~KR_RANK_AUTH) {
	case KR_RANK_INITIAL:
	case KR_RANK_OMIT:
	case KR_RANK_TRY:
	case KR_RANK_INDET:
	case KR_RANK_BOGUS:
	case KR_RANK_MISMATCH:
	case KR_RANK_MISSING:
	case KR_RANK_INSECURE:
	case KR_RANK_SECURE:
		return true;
	default:
		return false;
	}
}

/** @internal Set @a yielded to all RRs with matching @a qry_uid. */
static void set_yield(ranked_rr_array_t *array, const uint32_t qry_uid, const bool yielded)
{
	for (unsigned i = 0; i < array->len; ++i) {
		ranked_rr_array_entry_t *entry = array->at[i];
		if (entry->qry_uid == qry_uid) {
			entry->yielded = yielded;
		}
	}
}

/**
 * @internal Defer execution of current query.
 * The current layer state and input will be pushed to a stack and resumed on next iteration.
 */
static int consume_yield(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	knot_pkt_t *pkt_copy = knot_pkt_new(NULL, pkt->size, &req->pool);
	struct kr_layer_pickle *pickle = mm_alloc(&req->pool, sizeof(*pickle));
	if (pickle && pkt_copy && knot_pkt_copy(pkt_copy, pkt) == 0) {
		struct kr_query *qry = req->current_query;
		pickle->api = ctx->api;
		pickle->state = ctx->state;
		pickle->pkt = pkt_copy;
		pickle->next = qry->deferred;
		qry->deferred = pickle;
		set_yield(&req->answ_selected, qry->uid, true);
		set_yield(&req->auth_selected, qry->uid, true);
		return kr_ok();
	}
	return kr_error(ENOMEM);
}
static int begin_yield(kr_layer_t *ctx) { return kr_ok(); }
static int reset_yield(kr_layer_t *ctx) { return kr_ok(); }
static int finish_yield(kr_layer_t *ctx) { return kr_ok(); }
static int produce_yield(kr_layer_t *ctx, knot_pkt_t *pkt) { return kr_ok(); }

/** @internal Macro for iterating module layers. */
#define RESUME_LAYERS(from, r, qry, func, ...) \
    (r)->current_query = (qry); \
	for (size_t i = (from); i < (r)->ctx->modules->len; ++i) { \
		struct kr_module *mod = (r)->ctx->modules->at[i]; \
		if (mod->layer) { \
			struct kr_layer layer = {.state = (r)->state, .api = mod->layer(mod), .req = (r)}; \
			if (layer.api && layer.api->func) { \
				(r)->state = layer.api->func(&layer, ##__VA_ARGS__); \
				if ((r)->state == KR_STATE_YIELD) { \
					func ## _yield(&layer, ##__VA_ARGS__); \
					break; \
				} \
			} \
		} \
	} /* Invalidate current query. */ \
	(r)->current_query = NULL

/** @internal Macro for starting module iteration. */
#define ITERATE_LAYERS(req, qry, func, ...) RESUME_LAYERS(0, req, qry, func, ##__VA_ARGS__)

/** @internal Find layer id matching API. */
static inline size_t layer_id(struct kr_request *req, const struct kr_layer_api *api) {
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
		const char *addr = kr_inaddr(&qry->ns.addr[0].ip);
		size_t addr_len = kr_inaddr_len(&qry->ns.addr[0].ip);
		/* @warning _NOT_ thread-safe */
		static knot_rdata_t rdata_arr[RDATA_ARR_MAX];
		knot_rdata_init(rdata_arr, addr_len, (const uint8_t *)addr, 0);
		return kr_zonecut_del(&qry->zone_cut, qry->ns.name, rdata_arr);
	} else {
		return kr_zonecut_del_all(&qry->zone_cut, qry->ns.name);
	}
}

/** This turns of QNAME minimisation if there is a non-terminal between current zone cut, and name target.
 *  It save several minimization steps, as the zone cut is likely final one.
 */
static void check_empty_nonterms(struct kr_query *qry, knot_pkt_t *pkt, struct kr_cache *cache, uint32_t timestamp)
{
	// FIXME cleanup, etc.
#if 0
	if (qry->flags.NO_MINIMIZE) {
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
			qry->flags.NO_MINIMIZE = true;
			kr_make_query(qry, pkt);
			break;
		}
		assert(target[0]);
		target = knot_wire_next_label(target, NULL);
	}
	kr_cache_sync(cache);
#endif
}

static int ns_fetch_cut(struct kr_query *qry, const knot_dname_t *requested_name,
			struct kr_request *req, knot_pkt_t *pkt)
{
	/* It can occur that here parent query already have
	 * provably insecured zonecut which not in the cache yet. */
	struct kr_qflags pflags;
	if (qry->parent) {
		pflags = qry->parent->flags;
	}
	const bool is_insecured = qry->parent != NULL
		&& !(pflags.AWAIT_IPV4 || pflags.AWAIT_IPV6)
		&& (pflags.DNSSEC_INSECURE || pflags.DNSSEC_NODS);

	/* Want DNSSEC if it's possible to secure this name
	 * (e.g. is covered by any TA) */
	if (is_insecured) {
		/* If parent is unsecured we don't want DNSSEC
		 * even if cut name is covered by TA. */
		qry->flags.DNSSEC_WANT = false;
		qry->flags.DNSSEC_INSECURE = true;
	} else if (kr_ta_covers_qry(req->ctx, qry->zone_cut.name, KNOT_RRTYPE_NS)) {
		qry->flags.DNSSEC_WANT = true;
	} else {
		qry->flags.DNSSEC_WANT = false;
	}

	struct kr_zonecut cut_found;
	kr_zonecut_init(&cut_found, requested_name, req->rplan.pool);
	/* Cut that has been found can differs from cut that has been requested.
	 * So if not already insecured,
	 * try to fetch ta & keys even if initial cut name not covered by TA */
	bool secured = !is_insecured;
	int ret = kr_zonecut_find_cached(req->ctx, &cut_found, requested_name,
					 qry, &secured);
	if (ret == kr_error(ENOENT)) {
		/* No cached cut found, start from SBELT
		 * and issue priming query. */
		ret = kr_zonecut_set_sbelt(req->ctx, &qry->zone_cut);
		if (ret != 0) {
			return KR_STATE_FAIL;
		}
		VERBOSE_MSG(qry, "=> using root hints\n");
		qry->flags.AWAIT_CUT = false;
		kr_zonecut_deinit(&cut_found);
		return KR_STATE_DONE;
	} else if (ret != kr_ok()) {
		kr_zonecut_deinit(&cut_found);
		return KR_STATE_FAIL;
	}

	/* Find out security status.
	 * Go insecure if the zone cut is provably insecure */
	if ((qry->flags.DNSSEC_WANT) && !secured) {
		VERBOSE_MSG(qry, "=> NS is provably without DS, going insecure\n");
		qry->flags.DNSSEC_WANT = false;
		qry->flags.DNSSEC_INSECURE = true;
	}
	/* Zonecut name can change, check it again
	 * to prevent unnecessary DS & DNSKEY queries */
	if (!(qry->flags.DNSSEC_INSECURE) &&
	    kr_ta_covers_qry(req->ctx, cut_found.name, KNOT_RRTYPE_NS)) {
		qry->flags.DNSSEC_WANT = true;
	} else {
		qry->flags.DNSSEC_WANT = false;
	}
	/* Check if any DNSKEY found for cached cut */
	if (qry->flags.DNSSEC_WANT && cut_found.key == NULL &&
	    kr_zonecut_is_empty(&cut_found)) {
		/* Cut found and there are no proofs of zone insecurity.
		 * But no DNSKEY found and no glue fetched.
		 * We have got circular dependency - must fetch A\AAAA
		 * from authoritative, but we have no key to verify it. */
		kr_zonecut_deinit(&cut_found);
		if (requested_name[0] != '\0' ) {
			/* If not root - try next label */
			return KR_STATE_CONSUME;
		}
		/* No cached cut & keys found, start from SBELT */
		ret = kr_zonecut_set_sbelt(req->ctx, &qry->zone_cut);
		if (ret != 0) {
			return KR_STATE_FAIL;
		}
		VERBOSE_MSG(qry, "=> using root hints\n");
		qry->flags.AWAIT_CUT = false;
		return KR_STATE_DONE;
	}
	/* Copy fetched name */
	qry->zone_cut.name = knot_dname_copy(cut_found.name, qry->zone_cut.pool);
	/* Copy fetched address set */
	kr_zonecut_copy(&qry->zone_cut, &cut_found);
	/* Copy fetched ta & keys */
	kr_zonecut_copy_trust(&qry->zone_cut, &cut_found);
	/* Check if there's a non-terminal between target and current cut. */
	struct kr_cache *cache = &req->ctx->cache;
	check_empty_nonterms(qry, pkt, cache, qry->timestamp.tv_sec);
	/* Cut found */
	return KR_STATE_PRODUCE;
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
	if (!(qry->flags.AWAIT_IPV6) &&
	    !(ctx->options.NO_IPV6)) {
		next_type = KNOT_RRTYPE_AAAA;
		qry->flags.AWAIT_IPV6 = true;
	} else if (!(qry->flags.AWAIT_IPV4) &&
		   !(ctx->options.NO_IPV4)) {
		next_type = KNOT_RRTYPE_A;
		qry->flags.AWAIT_IPV4 = true;
		/* Hmm, no useable IPv6 then. */
		qry->ns.reputation |= KR_NS_NOIP6;
		kr_nsrep_update_rep(&qry->ns, qry->ns.reputation, ctx->cache_rep);
	}
	/* Bail out if the query is already pending or dependency loop. */
	if (!next_type || kr_rplan_satisfies(qry->parent, qry->ns.name, KNOT_CLASS_IN, next_type)) {
		/* Fall back to SBELT if root server query fails. */
		if (!next_type && qry->zone_cut.name[0] == '\0') {
			VERBOSE_MSG(qry, "=> fallback to root hints\n");
			kr_zonecut_set_sbelt(ctx, &qry->zone_cut);
			qry->flags.NO_THROTTLE = true; /* Pick even bad SBELT servers */
			return kr_error(EAGAIN);
		}
		/* No IPv4 nor IPv6, flag server as unusable. */
		VERBOSE_MSG(qry, "=> unresolvable NS address, bailing out\n");
		qry->ns.reputation |= KR_NS_NOIP4 | KR_NS_NOIP6;
		kr_nsrep_update_rep(&qry->ns, qry->ns.reputation, ctx->cache_rep);
		invalidate_ns(rplan, qry);
		return kr_error(EHOSTUNREACH);
	}
	struct kr_query *next = qry;
	if (knot_dname_is_equal(qry->ns.name, qry->sname) &&
	    qry->stype == next_type) {
		if (!(qry->flags.NO_MINIMIZE)) {
			qry->flags.NO_MINIMIZE = true;
			qry->flags.AWAIT_IPV6 = false;
			qry->flags.AWAIT_IPV4 = false;
			VERBOSE_MSG(qry, "=> circular dependepcy, retrying with non-minimized name\n");
		} else {
			qry->ns.reputation |= KR_NS_NOIP4 | KR_NS_NOIP6;
			kr_nsrep_update_rep(&qry->ns, qry->ns.reputation, ctx->cache_rep);
			invalidate_ns(rplan, qry);
			VERBOSE_MSG(qry, "=> unresolvable NS address, bailing out\n");
			return kr_error(EHOSTUNREACH);
		}
	} else {
		/* Push new query to the resolution plan */
		next = kr_rplan_push(rplan, qry, qry->ns.name, KNOT_CLASS_IN, next_type);
		if (!next) {
			return kr_error(ENOMEM);
		}
		next->flags.NONAUTH = true;
	}
	/* At the root level with no NS addresses, add SBELT subrequest. */
	int ret = 0;
	if (qry->zone_cut.name[0] == '\0') {
		ret = kr_zonecut_set_sbelt(ctx, &next->zone_cut);
		if (ret == 0) { /* Copy TA and key since it's the same cut to avoid lookup. */
			kr_zonecut_copy_trust(&next->zone_cut, &qry->zone_cut);
			kr_zonecut_set_sbelt(ctx, &qry->zone_cut); /* Add SBELT to parent in case query fails. */
			qry->flags.NO_THROTTLE = true; /* Pick even bad SBELT servers */
		}
	} else {
		next->flags.AWAIT_CUT = true;
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

/** Removes last EDNS OPT RR written to the packet. */
static int edns_erase_and_reserve(knot_pkt_t *pkt)
{
	/* Nothing to be done. */
	if (!pkt || !pkt->opt_rr) {
		return 0;
	}

	/* Fail if the data are located elsewhere than at the end of packet. */
	if (pkt->current != KNOT_ADDITIONAL ||
	    pkt->opt_rr != &pkt->rr[pkt->rrset_count - 1]) {
		return -1;
	}

	size_t len = knot_rrset_size(pkt->opt_rr);
	int16_t rr_removed = pkt->opt_rr->rrs.rr_count;
	/* Decrease rrset counters. */
	pkt->rrset_count -= 1;
	pkt->sections[pkt->current].count -= 1;
	pkt->size -= len;
	knot_wire_add_arcount(pkt->wire, -rr_removed); /* ADDITIONAL */

	pkt->opt_rr = NULL;

	/* Reserve the freed space. */
	return knot_pkt_reserve(pkt, len);
}

static int edns_create(knot_pkt_t *pkt, knot_pkt_t *template, struct kr_request *req)
{
	pkt->opt_rr = knot_rrset_copy(req->ctx->opt_rr, &pkt->mm);
	size_t wire_size = knot_edns_wire_size(pkt->opt_rr);
#if defined(ENABLE_COOKIES)
	if (req->ctx->cookie_ctx.clnt.enabled ||
	    req->ctx->cookie_ctx.srvr.enabled) {
		wire_size += KR_COOKIE_OPT_MAX_LEN;
	}
#endif /* defined(ENABLE_COOKIES) */
	if (req->has_tls) {
		if (req->ctx->tls_padding == -1)
			/* FIXME: we do not know how to reserve space for the
			 * default padding policy, since we can't predict what
			 * it will select. So i'm just guessing :/ */
			wire_size += KNOT_EDNS_OPTION_HDRLEN + 512;
		if (req->ctx->tls_padding >= 2)
			wire_size += KNOT_EDNS_OPTION_HDRLEN + req->ctx->tls_padding;
	}
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

/** @return error code, ignoring if forced to truncate the packet. */
static int write_extra_records(const rr_array_t *arr, knot_pkt_t *answer)
{
	for (size_t i = 0; i < arr->len; ++i) {
		int err = knot_pkt_put(answer, 0, arr->at[i], 0);
		if (err != KNOT_EOK) {
			return err == KNOT_ESPACE ? kr_ok() : kr_error(err);
		}
	}
	return kr_ok();
}

/**
 * @param all_secure optionally &&-combine security of written RRs into its value.
 *		     (i.e. if you pass a pointer to false, it will always remain)
 * @param all_cname optionally output if all written RRs are CNAMEs and RRSIGs of CNAMEs
 * @return error code, ignoring if forced to truncate the packet.
 */
static int write_extra_ranked_records(const ranked_rr_array_t *arr, knot_pkt_t *answer,
				      bool *all_secure, bool *all_cname)
{
	const bool has_dnssec = knot_pkt_has_dnssec(answer);
	bool all_sec = true;
	bool all_cn = (all_cname != NULL); /* optim.: init as false if not needed */
	int err = kr_ok();

	for (size_t i = 0; i < arr->len; ++i) {
		ranked_rr_array_entry_t * entry = arr->at[i];
		if (!entry->to_wire) {
			continue;
		}
		knot_rrset_t *rr = entry->rr;
		if (!has_dnssec) {
			if (rr->type != knot_pkt_qtype(answer) && knot_rrtype_is_dnssec(rr->type)) {
				continue;
			}
		}
		err = knot_pkt_put(answer, 0, rr, 0);
		if (err != KNOT_EOK) {
			if (err == KNOT_ESPACE) {
				err = kr_ok();
			}
			break;
		}

		if (rr->type != KNOT_RRTYPE_RRSIG) {
			all_sec = all_sec && kr_rank_test(entry->rank, KR_RANK_SECURE);
		}
		all_cn = all_cn && kr_rrset_type_maysig(entry->rr) == KNOT_RRTYPE_CNAME;
	}

	if (all_secure) {
		*all_secure = *all_secure && all_sec;
	}
	if (all_cname) {
		*all_cname = all_cn;
	}
	return err;
}

/** @internal Add an EDNS padding RR into the answer if requested and required. */
static int answer_padding(struct kr_request *request)
{
	if (!request || !request->answer || !request->ctx) {
		assert(false);
		return kr_error(EINVAL);
	}
	int32_t padding = request->ctx->tls_padding;
	knot_pkt_t *answer = request->answer;
	knot_rrset_t *opt_rr = answer->opt_rr;
	int32_t pad_bytes = -1;

	if (padding == -1) { /* use the default padding policy from libknot */
#if KNOT_VERSION_HEX < ((2 << 16) | (4 << 8) | 3)
		/* no knot_edns_default_padding_size available in libknot */
		padding = KR_DEFAULT_TLS_PADDING;
#else
		pad_bytes =  knot_edns_default_padding_size(answer, opt_rr);
#endif
	}
	if (padding >= 2) {
		int32_t max_pad_bytes = knot_edns_get_payload(opt_rr) - (answer->size + knot_rrset_size(opt_rr));
		pad_bytes = MIN(knot_edns_alignment_size(answer->size, knot_rrset_size(opt_rr), padding),
				max_pad_bytes);
	}

	if (pad_bytes >= 0) {
		uint8_t zeros[MAX(1, pad_bytes)];
		memset(zeros, 0, sizeof(zeros));
		int r = knot_edns_add_option(opt_rr, KNOT_EDNS_OPTION_PADDING,
					     pad_bytes, zeros, &answer->mm);
		if (r != KNOT_EOK) {
			knot_rrset_clear(opt_rr, &answer->mm);
			return kr_error(r);
		}
	}
	return kr_ok();
}

static int answer_fail(struct kr_request *request)
{
	knot_pkt_t *answer = request->answer;
	int ret = kr_pkt_clear_payload(answer);
	knot_wire_clear_ad(answer->wire);
	knot_wire_clear_aa(answer->wire);
	knot_wire_set_rcode(answer->wire, KNOT_RCODE_SERVFAIL);
	if (ret == 0 && answer->opt_rr) {
		/* OPT in SERVFAIL response is still useful for cookies/additional info. */
		knot_pkt_begin(answer, KNOT_ADDITIONAL);
		answer_padding(request); /* Ignore failed padding in SERVFAIL answer. */
		ret = edns_put(answer);
	}
	return ret;
}

static int answer_finalize(struct kr_request *request, int state)
{
	struct kr_rplan *rplan = &request->rplan;
	knot_pkt_t *answer = request->answer;

	/* Always set SERVFAIL for bogus answers. */
	if (state == KR_STATE_FAIL && rplan->pending.len > 0) {
		struct kr_query *last = array_tail(rplan->pending);
		if ((last->flags.DNSSEC_WANT) && (last->flags.DNSSEC_BOGUS)) {
			return answer_fail(request);
		}
	}

	struct kr_query *last = rplan->resolved.len > 0 ? array_tail(rplan->resolved) : NULL;
		/* TODO  ^^^^ this is slightly fragile */

	/* AD flag.  We can only change `secure` from true to false.
	 * Be conservative.  Primary approach: check ranks of all RRs in wire.
	 * Only "negative answers" need special handling. */
	bool secure = (last != NULL); /* suspicious otherwise */
	VERBOSE_MSG(NULL, "AD: secure (start)\n");
	if (last && (last->flags.STUB)) {
		secure = false; /* don't trust forwarding for now */
	}
	if (last && (last->flags.DNSSEC_OPTOUT)) {
		VERBOSE_MSG(NULL, "AD: opt-out\n");
		secure = false; /* the last answer is insecure due to opt-out */
	}

	bool answ_all_cnames = false/*arbitrary*/;
	if (request->answ_selected.len > 0) {
		assert(answer->current <= KNOT_ANSWER);
		/* Write answer records. */
		if (answer->current < KNOT_ANSWER) {
			knot_pkt_begin(answer, KNOT_ANSWER);
		}
		if (write_extra_ranked_records(&request->answ_selected, answer,
						&secure, &answ_all_cnames))
		{
			return answer_fail(request);
		}
	}

	VERBOSE_MSG(NULL, "AD: secure (between ANS and AUTH)\n");
	/* Write authority records. */
	if (answer->current < KNOT_AUTHORITY) {
		knot_pkt_begin(answer, KNOT_AUTHORITY);
	}
	if (write_extra_ranked_records(&request->auth_selected, answer, &secure, NULL)) {
		return answer_fail(request);
	}
	/* Write additional records. */
	knot_pkt_begin(answer, KNOT_ADDITIONAL);
	if (write_extra_records(&request->additional, answer)) {
		return answer_fail(request);
	}
	/* Write EDNS information */
	int ret = 0;
	if (answer->opt_rr) {
		if (request->has_tls) {
			if (answer_padding(request) != kr_ok()) {
				return answer_fail(request);
			}
		}
		knot_pkt_begin(answer, KNOT_ADDITIONAL);
		ret = edns_put(answer);
	}

	/* AD: "negative answers" need more handling. */
	if (last && secure) {
		VERBOSE_MSG(NULL, "AD: secure (1)\n");
		if (kr_response_classify(answer) != PKT_NOERROR
		    /* Additionally check for CNAME chains that "end in NODATA",
		     * as those would also be PKT_NOERROR. */
		    || (answ_all_cnames && knot_pkt_qtype(answer) != KNOT_RRTYPE_CNAME))
		{
			secure = secure && last->flags.DNSSEC_WANT
				&& !last->flags.DNSSEC_BOGUS && !last->flags.DNSSEC_INSECURE;
		}
	}
	/* Clear AD if not secure.  ATM answer has AD=1 if requested secured answer. */
	if (!secure || state != KR_STATE_DONE
	    || knot_pkt_qtype(answer) == KNOT_RRTYPE_RRSIG) {
		knot_wire_clear_ad(answer->wire);
	}

	if (last) {
		struct kr_query *cname_parent = last->cname_parent;
		while (cname_parent != NULL) {
			if (cname_parent->flags.DNSSEC_OPTOUT) {
				knot_wire_clear_ad(answer->wire);
				break;
			}
			cname_parent = cname_parent->cname_parent;
		}
	}

	return ret;
}

static int query_finalize(struct kr_request *request, struct kr_query *qry, knot_pkt_t *pkt)
{
	int ret = 0;
	knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	if (!(qry->flags.SAFEMODE)) {
		/* Remove any EDNS records from any previous iteration. */
		ret = edns_erase_and_reserve(pkt);
		if (ret == 0) {
			ret = edns_create(pkt, request->answer, request);
		}
		if (ret == 0) {
			/* Stub resolution (ask for +rd and +do) */
			if (qry->flags.STUB) {
				knot_wire_set_rd(pkt->wire);
				if (knot_pkt_has_dnssec(request->answer)) {
					knot_edns_set_do(pkt->opt_rr);
				}
				if (knot_wire_get_cd(request->answer->wire)) {
					knot_wire_set_cd(pkt->wire);
				}
			/* Full resolution (ask for +cd and +do) */
			} else if (qry->flags.FORWARD) {
				knot_wire_set_rd(pkt->wire);
				knot_edns_set_do(pkt->opt_rr);
				knot_wire_set_cd(pkt->wire);
			} else if (qry->flags.DNSSEC_WANT) {
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
	request->state = KR_STATE_CONSUME;
	request->current_query = NULL;
	array_init(request->additional);
	array_init(request->answ_selected);
	array_init(request->auth_selected);
	array_init(request->add_selected);
	request->answ_validated = false;
	request->auth_validated = false;
	request->trace_log = NULL;
	request->trace_finish = NULL;

	/* Expect first query */
	kr_rplan_init(&request->rplan, request, &request->pool);
	return KR_STATE_CONSUME;
}

static int resolve_query(struct kr_request *request, const knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;
	const knot_dname_t *qname = knot_pkt_qname(packet);
	uint16_t qclass = knot_pkt_qclass(packet);
	uint16_t qtype = knot_pkt_qtype(packet);
	bool cd_is_set = knot_wire_get_cd(packet->wire);
	struct kr_query *qry = NULL;

	if (qname != NULL) {
		qry = kr_rplan_push(rplan, NULL, qname, qclass, qtype);
	} else if (knot_wire_get_qdcount(packet->wire) == 0 &&
                   knot_pkt_has_edns(packet) &&
                   knot_edns_has_option(packet->opt_rr, KNOT_EDNS_OPTION_COOKIE)) {
		/* Plan empty query only for cookies. */
		qry = kr_rplan_push_empty(rplan, NULL);
	}
	if (!qry) {
		return KR_STATE_FAIL;
	}

	/* Deferred zone cut lookup for this query. */
	qry->flags.AWAIT_CUT = true;
	/* Want DNSSEC if it's posible to secure this name (e.g. is covered by any TA) */
	if ((knot_wire_get_ad(packet->wire) || knot_pkt_has_dnssec(packet)) &&
	    kr_ta_covers_qry(request->ctx, qname, qtype)) {
		qry->flags.DNSSEC_WANT = true;
	}

	/* Initialize answer packet */
	knot_pkt_t *answer = request->answer;
	knot_wire_set_qr(answer->wire);
	knot_wire_clear_aa(answer->wire);
	knot_wire_set_ra(answer->wire);
	knot_wire_set_rcode(answer->wire, KNOT_RCODE_NOERROR);

	if (cd_is_set) {
		knot_wire_set_cd(answer->wire);
	} else if (qry->flags.DNSSEC_WANT) {
		knot_wire_set_ad(answer->wire);
	}

	/* Expect answer, pop if satisfied immediately */
	request->qsource.packet = packet;
	ITERATE_LAYERS(request, qry, begin);
	request->qsource.packet = NULL;
	if (request->state == KR_STATE_DONE) {
		kr_rplan_pop(rplan, qry);
	}
	return request->state;
}

KR_PURE static bool kr_inaddr_equal(const struct sockaddr *a, const struct sockaddr *b)
{
	const int a_len = kr_inaddr_len(a);
	const int b_len = kr_inaddr_len(b);
	return a_len == b_len && memcmp(kr_inaddr(a), kr_inaddr(b), a_len) == 0;
}

static void update_nslist_rtt(struct kr_context *ctx, struct kr_query *qry, const struct sockaddr *src)
{
	/* Do not track in safe mode. */
	if (qry->flags.SAFEMODE) {
		return;
	}

	/* Calculate total resolution time from the time the query was generated. */
	uint64_t elapsed = kr_now() - qry->timestamp_mono;
	elapsed = elapsed > UINT_MAX ? UINT_MAX : elapsed;
 
	/* NSs in the preference list prior to the one who responded will be penalised
	 * with the RETRY timer interval. This is because we know they didn't respond
	 * for N retries, so their RTT must be at least N * RETRY.
	 * The NS in the preference list that responded will have RTT relative to the
	 * time when the query was sent out, not when it was originated.
	 */
	for (size_t i = 0; i < KR_NSREP_MAXADDR; ++i) {
		const struct sockaddr *addr = &qry->ns.addr[i].ip;
		if (addr->sa_family == AF_UNSPEC) {
			break;
		}
		/* If this address is the source of the answer, update its RTT */
		if (kr_inaddr_equal(src, addr)) {
			kr_nsrep_update_rtt(&qry->ns, addr, elapsed, ctx->cache_rtt, KR_NS_UPDATE);
			WITH_VERBOSE(qry) {
				char addr_str[INET6_ADDRSTRLEN];
				inet_ntop(addr->sa_family, kr_inaddr(addr), addr_str, sizeof(addr_str));
				VERBOSE_MSG(qry, "<= server: '%s' rtt: %"PRIu64" ms\n",
						addr_str, elapsed);
			}
		} else {
			/* Response didn't come from this IP, but we know the RTT must be at least
			 * several RETRY timer tries, e.g. if we have addresses [a, b, c] and we have
			 * tried [a, b] when the answer from 'a' came after 350ms, then we know
			 * that 'b' didn't respond for at least 350 - (1 * 300) ms. We can't say that
			 * its RTT is 50ms, but we can say that its score shouldn't be less than 50. */
			 kr_nsrep_update_rtt(&qry->ns, addr, elapsed, ctx->cache_rtt, KR_NS_MAX);
			 WITH_VERBOSE(qry) {
			 	char addr_str[INET6_ADDRSTRLEN];
			 	inet_ntop(addr->sa_family, kr_inaddr(addr), addr_str, sizeof(addr_str));
				VERBOSE_MSG(qry, "<= server: '%s' rtt: >= %"PRIu64" ms\n",
						addr_str, elapsed);
			 }
		}
		/* Subtract query start time from elapsed time */
		if (elapsed < KR_CONN_RETRY) {
			break;
		}
		elapsed = elapsed - KR_CONN_RETRY;
	}
}

static void update_nslist_score(struct kr_request *request, struct kr_query *qry, const struct sockaddr *src, knot_pkt_t *packet)
{
	struct kr_context *ctx = request->ctx;
	/* On successful answer, update preference list RTT and penalise timer  */
	if (request->state != KR_STATE_FAIL) {
		/* Update RTT information for preference list */
		update_nslist_rtt(ctx, qry, src);
		/* Do not complete NS address resolution on soft-fail. */
		const int rcode = packet ? knot_wire_get_rcode(packet->wire) : 0;
		if (rcode != KNOT_RCODE_SERVFAIL && rcode != KNOT_RCODE_REFUSED) {
			qry->flags.AWAIT_IPV6 = false;
			qry->flags.AWAIT_IPV4 = false;
		} else { /* Penalize SERVFAILs. */
			kr_nsrep_update_rtt(&qry->ns, src, KR_NS_PENALTY, ctx->cache_rtt, KR_NS_ADD);
		}
	/* Penalise resolution failures except validation failures. */
	} else if (!(qry->flags.DNSSEC_BOGUS)) {
		kr_nsrep_update_rtt(&qry->ns, src, KR_NS_TIMEOUT, ctx->cache_rtt, KR_NS_UPDATE);
		WITH_VERBOSE(qry) {
			char addr_str[INET6_ADDRSTRLEN];
			inet_ntop(src->sa_family, kr_inaddr(src), addr_str, sizeof(addr_str));
			VERBOSE_MSG(qry, "=> server: '%s' flagged as 'bad'\n", addr_str);
		}
	}
}

static bool resolution_time_exceeded(struct kr_query *qry, uint64_t now)
{
	uint64_t resolving_time = now - qry->creation_time_mono;
	if (resolving_time > KR_RESOLVE_TIME_LIMIT) {
		WITH_VERBOSE(qry) {
			VERBOSE_MSG(qry, "query resolution time limit exceeded\n");
		}
		return true;
	}
	return false;
}

int kr_resolve_consume(struct kr_request *request, const struct sockaddr *src, knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;

	/* Empty resolution plan, push packet as the new query */
	if (packet && kr_rplan_empty(rplan)) {
		if (answer_prepare(request->answer, packet, request) != 0) {
			return KR_STATE_FAIL;
		}
		return resolve_query(request, packet);
	}

	/* Different processing for network error */
	struct kr_query *qry = array_tail(rplan->pending);
	/* Check overall resolution time */
	if (resolution_time_exceeded(qry, kr_now())) {
		return KR_STATE_FAIL;
	}
	bool tried_tcp = (qry->flags.TCP);
	if (!packet || packet->size == 0) {
		if (tried_tcp) {
			request->state = KR_STATE_FAIL;
		} else {
			qry->flags.TCP = true;
		}
	} else {
		/* Packet cleared, derandomize QNAME. */
		knot_dname_t *qname_raw = (knot_dname_t *)knot_pkt_qname(packet);
		if (qname_raw && qry->secret != 0) {
			randomized_qname_case(qname_raw, qry->secret);
		}
		request->state = KR_STATE_CONSUME;
		if (qry->flags.CACHED) {
			ITERATE_LAYERS(request, qry, consume, packet);
		} else {
			/* Fill in source and latency information. */
			request->upstream.rtt = kr_now() - qry->timestamp_mono;
			request->upstream.addr = src;
			ITERATE_LAYERS(request, qry, consume, packet);
			/* Clear temporary information */
			request->upstream.addr = NULL;
			request->upstream.rtt = 0;
		}
	}

	/* Track RTT for iterative answers */
	if (src && !(qry->flags.CACHED)) {
		update_nslist_score(request, qry, src, packet);
	}
	/* Resolution failed, invalidate current NS. */
	if (request->state == KR_STATE_FAIL) {
		invalidate_ns(rplan, qry);
		qry->flags.RESOLVED = false;
	}

	/* Pop query if resolved. */
	if (request->state == KR_STATE_YIELD) {
		return KR_STATE_PRODUCE; /* Requery */
	} else if (qry->flags.RESOLVED) {
		kr_rplan_pop(rplan, qry);
	} else if (!tried_tcp && (qry->flags.TCP)) {
		return KR_STATE_PRODUCE; /* Requery over TCP */
	} else { /* Clear query flags for next attempt */
		qry->flags.CACHED = false;
		if (!request->options.TCP) {
			qry->flags.TCP = false;
		}
	}

	ITERATE_LAYERS(request, qry, reset);

	/* Do not finish with bogus answer. */
	if (qry->flags.DNSSEC_BOGUS)  {
		return KR_STATE_FAIL;
	}

	return kr_rplan_empty(&request->rplan) ? KR_STATE_DONE : KR_STATE_PRODUCE;
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
	next->flags.NO_MINIMIZE = true;
	if (parent->flags.DNSSEC_WANT) {
		next->flags.DNSSEC_WANT = true;
	}
	return next;
}

static int forward_trust_chain_check(struct kr_request *request, struct kr_query *qry, bool resume)
{
	struct kr_rplan *rplan = &request->rplan;
	map_t *trust_anchors = &request->ctx->trust_anchors;
	map_t *negative_anchors = &request->ctx->negative_anchors;

	if (qry->parent != NULL &&
	    !(qry->forward_flags.CNAME) &&
	    !(qry->flags.DNS64_MARK) &&
	    knot_dname_in(qry->parent->zone_cut.name, qry->zone_cut.name)) {
		return KR_STATE_PRODUCE;
	}

	assert(qry->flags.FORWARD);

	if (!trust_anchors) {
		qry->flags.AWAIT_CUT = false;
		return KR_STATE_PRODUCE;
	}

	if (qry->flags.DNSSEC_INSECURE) {
		qry->flags.AWAIT_CUT = false;
		return KR_STATE_PRODUCE;
	}

	if (qry->forward_flags.NO_MINIMIZE) {
		qry->flags.AWAIT_CUT = false;
		return KR_STATE_PRODUCE;
	}

	const knot_dname_t *wanted_name = qry->sname;
	const knot_dname_t *start_name = qry->sname;
	if ((qry->flags.AWAIT_CUT) && !resume) {
		qry->flags.AWAIT_CUT = false;
		const knot_dname_t *longest_ta = kr_ta_get_longest_name(trust_anchors, qry->sname);
		if (longest_ta) {
			start_name = longest_ta;
			qry->zone_cut.name = knot_dname_copy(start_name, qry->zone_cut.pool);
			qry->flags.DNSSEC_WANT = true;
		} else {
			qry->flags.DNSSEC_WANT = false;
			return KR_STATE_PRODUCE;
		}
	}

	bool has_ta = (qry->zone_cut.trust_anchor != NULL);
	knot_dname_t *ta_name = (has_ta ? qry->zone_cut.trust_anchor->owner : NULL);
	bool refetch_ta = (!has_ta || !knot_dname_is_equal(qry->zone_cut.name, ta_name));
	bool is_dnskey_subreq = kr_rplan_satisfies(qry, ta_name, KNOT_CLASS_IN, KNOT_RRTYPE_DNSKEY);
	bool refetch_key = has_ta && (!qry->zone_cut.key || !knot_dname_is_equal(ta_name, qry->zone_cut.key->owner));
	if (refetch_key && !is_dnskey_subreq) {
		struct kr_query *next = zone_cut_subreq(rplan, qry, ta_name, KNOT_RRTYPE_DNSKEY);
		if (!next) {
			return KR_STATE_FAIL;
		}
		return KR_STATE_DONE;
	}

	bool nods = false;
	bool ds_req = false;
	bool ns_req = false;
	bool ns_exist = true;
	bool minimized = false;
	int name_offset = 1;
	do {
		wanted_name = start_name;
		nods = false;
		ds_req = false;
		ns_req = false;
		minimized = false;
		ns_exist = true;

		int cut_labels = knot_dname_labels(qry->zone_cut.name, NULL);
		int wanted_name_labels = knot_dname_labels(wanted_name, NULL);
		while (wanted_name[0] && wanted_name_labels > cut_labels + name_offset) {
			wanted_name = knot_wire_next_label(wanted_name, NULL);
			wanted_name_labels -= 1;
		}
		minimized = (wanted_name != qry->sname);

		for (int i = 0; i < request->rplan.resolved.len; ++i) {
			struct kr_query *q = request->rplan.resolved.at[i];
			if (q->parent == qry &&
			    q->sclass == qry->sclass &&
			    (q->stype == KNOT_RRTYPE_DS || q->stype == KNOT_RRTYPE_NS) &&
			    knot_dname_is_equal(q->sname, wanted_name)) {
				if (q->stype == KNOT_RRTYPE_DS) {
					ds_req = true;
					if (q->flags.DNSSEC_NODS) {
						nods = true;
					}
					if (q->flags.CNAME) {
						nods = true;
						ns_exist = false;
					} else if (!(q->flags.DNSSEC_OPTOUT)) {
						int ret = kr_dnssec_matches_name_and_type(&request->auth_selected, q->uid,
											  wanted_name, KNOT_RRTYPE_NS);
						ns_exist = (ret == kr_ok());
					}
				} else {
					if (q->flags.CNAME) {
						nods = true;
						ns_exist = false;
					}
					ns_req = true;
				}
			}
		}

		if (ds_req && ns_exist && !ns_req && (minimized || resume)) {
			struct kr_query *next = zone_cut_subreq(rplan, qry, wanted_name,
								KNOT_RRTYPE_NS);
			if (!next) {
				return KR_STATE_FAIL;
			}
			return KR_STATE_DONE;
		}

		if (qry->parent == NULL && (qry->flags.CNAME) &&
		    ds_req && ns_req) {
			return KR_STATE_PRODUCE;
		}

		if ((qry->stype == KNOT_RRTYPE_DS) &&
	            knot_dname_is_equal(wanted_name, qry->sname)) {
			nods = true;
		} else if (resume && !ds_req) {
			nods = false;
		} else if (!minimized && qry->stype != KNOT_RRTYPE_DNSKEY) {
			nods = true;
		} else {
			nods = ds_req;
		}
		name_offset += 1;
	} while (ds_req && (ns_req || !ns_exist) && minimized);

	/* Disable DNSSEC if it enters NTA. */
	if (kr_ta_get(negative_anchors, wanted_name)){
		VERBOSE_MSG(qry, ">< negative TA, going insecure\n");
		qry->flags.DNSSEC_WANT = false;
	}

	/* Enable DNSSEC if enters a new island of trust. */
	bool want_secured = (qry->flags.DNSSEC_WANT) &&
			    !knot_wire_get_cd(request->answer->wire);
	if (!(qry->flags.DNSSEC_WANT) &&
	    !knot_wire_get_cd(request->answer->wire) &&
	    kr_ta_get(trust_anchors, wanted_name)) {
		qry->flags.DNSSEC_WANT = true;
		want_secured = true;
		WITH_VERBOSE(qry) {
		char qname_str[KNOT_DNAME_MAXLEN];
		knot_dname_to_str(qname_str, wanted_name, sizeof(qname_str));
		VERBOSE_MSG(qry, ">< TA: '%s'\n", qname_str);
		}
	}

	if (want_secured && !qry->zone_cut.trust_anchor) {
		knot_rrset_t *ta_rr = kr_ta_get(trust_anchors, wanted_name);
		if (!ta_rr) {
			char name[] = "\0";
			ta_rr = kr_ta_get(trust_anchors, (knot_dname_t*)name);
		}
		if (ta_rr) {
			qry->zone_cut.trust_anchor = knot_rrset_copy(ta_rr, qry->zone_cut.pool);
		}
	}

	has_ta = (qry->zone_cut.trust_anchor != NULL);
	ta_name = (has_ta ? qry->zone_cut.trust_anchor->owner : NULL);
	refetch_ta = (!has_ta || !knot_dname_is_equal(wanted_name, ta_name));
	if (!nods && want_secured && refetch_ta) {
		struct kr_query *next = zone_cut_subreq(rplan, qry, wanted_name,
							KNOT_RRTYPE_DS);
		if (!next) {
			return KR_STATE_FAIL;
		}
		return KR_STATE_DONE;
	}

	/* Try to fetch missing DNSKEY.
	 * Do not fetch if this is a DNSKEY subrequest to avoid circular dependency. */
	is_dnskey_subreq = kr_rplan_satisfies(qry, ta_name, KNOT_CLASS_IN, KNOT_RRTYPE_DNSKEY);
	refetch_key = has_ta && (!qry->zone_cut.key || !knot_dname_is_equal(ta_name, qry->zone_cut.key->owner));
	if (want_secured && refetch_key && !is_dnskey_subreq) {
		struct kr_query *next = zone_cut_subreq(rplan, qry, ta_name, KNOT_RRTYPE_DNSKEY);
		if (!next) {
			return KR_STATE_FAIL;
		}
		return KR_STATE_DONE;
	}

	return KR_STATE_PRODUCE;
}

/* @todo: Validator refactoring, keep this in driver for now. */
static int trust_chain_check(struct kr_request *request, struct kr_query *qry)
{
	struct kr_rplan *rplan = &request->rplan;
	map_t *trust_anchors = &request->ctx->trust_anchors;
	map_t *negative_anchors = &request->ctx->negative_anchors;

	/* Disable DNSSEC if it enters NTA. */
	if (kr_ta_get(negative_anchors, qry->zone_cut.name)){
		VERBOSE_MSG(qry, ">< negative TA, going insecure\n");
		qry->flags.DNSSEC_WANT = false;
		qry->flags.DNSSEC_INSECURE = true;
	}
	if (qry->flags.DNSSEC_NODS) {
		/* This is the next query iteration with minimized qname.
		 * At previous iteration DS non-existance has been proven */
		qry->flags.DNSSEC_NODS = false;
		qry->flags.DNSSEC_WANT = false;
		qry->flags.DNSSEC_INSECURE = true;
	}
	/* Enable DNSSEC if entering a new (or different) island of trust,
	 * and update the TA RRset if required. */
	bool want_secured = (qry->flags.DNSSEC_WANT) &&
			    !knot_wire_get_cd(request->answer->wire);
	knot_rrset_t *ta_rr = kr_ta_get(trust_anchors, qry->zone_cut.name);
	if (!knot_wire_get_cd(request->answer->wire) && ta_rr) {
		qry->flags.DNSSEC_WANT = true;
		want_secured = true;

		if (qry->zone_cut.trust_anchor == NULL
		    || !knot_dname_is_equal(qry->zone_cut.trust_anchor->owner, qry->zone_cut.name)) {
			mm_free(qry->zone_cut.pool, qry->zone_cut.trust_anchor);
			qry->zone_cut.trust_anchor = knot_rrset_copy(ta_rr, qry->zone_cut.pool);

			WITH_VERBOSE(qry) {
			char qname_str[KNOT_DNAME_MAXLEN];
			knot_dname_to_str(qname_str, ta_rr->owner, sizeof(qname_str));
			VERBOSE_MSG(qry, ">< TA: '%s'\n", qname_str);
			}
		}
	}

	/* Try to fetch missing DS (from above the cut). */
	const bool has_ta = (qry->zone_cut.trust_anchor != NULL);
	const knot_dname_t *ta_name = (has_ta ? qry->zone_cut.trust_anchor->owner : NULL);
	const bool refetch_ta = !has_ta || !knot_dname_is_equal(qry->zone_cut.name, ta_name);
	if (want_secured && refetch_ta) {
		/* @todo we could fetch the information from the parent cut, but we don't remember that now */
		struct kr_query *next = kr_rplan_push(rplan, qry, qry->zone_cut.name, qry->sclass, KNOT_RRTYPE_DS);
		if (!next) {
			return KR_STATE_FAIL;
		}
		next->flags.AWAIT_CUT = true;
		next->flags.DNSSEC_WANT = true;
		return KR_STATE_DONE;
	}
	/* Try to fetch missing DNSKEY (either missing or above current cut).
	 * Do not fetch if this is a DNSKEY subrequest to avoid circular dependency. */
	const bool is_dnskey_subreq = kr_rplan_satisfies(qry, ta_name, KNOT_CLASS_IN, KNOT_RRTYPE_DNSKEY);
	const bool refetch_key = has_ta && (!qry->zone_cut.key || !knot_dname_is_equal(ta_name, qry->zone_cut.key->owner));
	if (want_secured && refetch_key && !is_dnskey_subreq) {
		struct kr_query *next = zone_cut_subreq(rplan, qry, ta_name, KNOT_RRTYPE_DNSKEY);
		if (!next) {
			return KR_STATE_FAIL;
		}
		return KR_STATE_DONE;
	}

	return KR_STATE_PRODUCE;
}

/** @internal Check current zone cut status and credibility, spawn subrequests if needed. */
static int zone_cut_check(struct kr_request *request, struct kr_query *qry, knot_pkt_t *packet)
/* TODO: using cache on this point in this way just isn't nice; remove in time */
{
	/* Stub mode, just forward and do not solve cut. */
	if (qry->flags.STUB) {
		return KR_STATE_PRODUCE;
	}

	/* Forwarding to upstream resolver mode.
	 * Since forwarding targets already are in qry->ns -
	 * cut fetching is not needed. */
	if (qry->flags.FORWARD) {
		return forward_trust_chain_check(request, qry, false);
	}
	if (!(qry->flags.AWAIT_CUT)) {
		/* The query was resolved from cache.
		 * Spawn DS \ DNSKEY requests if needed and exit */
		return trust_chain_check(request, qry);
	}

	/* The query wasn't resolved from cache,
	 * now it's the time to look up closest zone cut from cache. */
	struct kr_cache *cache = &request->ctx->cache;
	if (!kr_cache_is_open(cache)) {
		int ret = kr_zonecut_set_sbelt(request->ctx, &qry->zone_cut);
		if (ret != 0) {
			return KR_STATE_FAIL;
		}
		VERBOSE_MSG(qry, "=> no cache open, using root hints\n");
		qry->flags.AWAIT_CUT = false;
		return KR_STATE_DONE;
	}

	const knot_dname_t *requested_name = qry->sname;
	/* If at/subdomain of parent zone cut, start from its encloser.
	 * This is for case when we get to a dead end
	 * (and need glue from parent), or DS refetch. */
	if (qry->parent) {
		const knot_dname_t *parent = qry->parent->zone_cut.name;
		if (parent[0] != '\0' && knot_dname_in(parent, qry->sname)) {
			requested_name = knot_wire_next_label(parent, NULL);
		}
	} else if ((qry->stype == KNOT_RRTYPE_DS) && (qry->sname[0] != '\0')) {
		/* If this is explicit DS query, start from encloser too. */
		requested_name = knot_wire_next_label(requested_name, NULL);
	}

	int state = KR_STATE_FAIL;
	do {
		state = ns_fetch_cut(qry, requested_name, request, packet);
		if (state == KR_STATE_DONE || state == KR_STATE_FAIL) {
			return state;
		} else if (state == KR_STATE_CONSUME) {
			requested_name = knot_wire_next_label(requested_name, NULL);
		}
	} while (state == KR_STATE_CONSUME);

	/* Update minimized QNAME if zone cut changed */
	if (qry->zone_cut.name && qry->zone_cut.name[0] != '\0' && !(qry->flags.NO_MINIMIZE)) {
		if (kr_make_query(qry, packet) != 0) {
			return KR_STATE_FAIL;
		}
	}
	qry->flags.AWAIT_CUT = false;

	/* Check trust chain */
	return trust_chain_check(request, qry);
}

int kr_resolve_produce(struct kr_request *request, struct sockaddr **dst, int *type, knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;
	unsigned ns_election_iter = 0;

	/* No query left for resolution */
	if (kr_rplan_empty(rplan)) {
		return KR_STATE_FAIL;
	}
	/* If we have deferred answers, resume them. */
	struct kr_query *qry = array_tail(rplan->pending);
	if (qry->deferred != NULL) {
		/* @todo: Refactoring validator, check trust chain before resuming. */
		int state = 0;
		if (((qry->flags.FORWARD) == 0) ||
		    ((qry->stype == KNOT_RRTYPE_DS) && (qry->flags.CNAME))) {
			state = trust_chain_check(request, qry);
		} else {
			state = forward_trust_chain_check(request, qry, true);
		}

		switch(state) {
		case KR_STATE_FAIL: return KR_STATE_FAIL;
		case KR_STATE_DONE: return KR_STATE_PRODUCE;
		default: break;
		}
		VERBOSE_MSG(qry, "=> resuming yielded answer\n");
		struct kr_layer_pickle *pickle = qry->deferred;
		request->state = KR_STATE_YIELD;
		set_yield(&request->answ_selected, qry->uid, false);
		set_yield(&request->auth_selected, qry->uid, false);
		RESUME_LAYERS(layer_id(request, pickle->api), request, qry, consume, pickle->pkt);
		if (request->state != KR_STATE_YIELD) {
			/* No new deferred answers, take the next */
			qry->deferred = pickle->next;
		}
	} else {
		/* Caller is interested in always tracking a zone cut, even if the answer is cached
		 * this is normally not required, and incurrs another cache lookups for cached answer. */
		if (qry->flags.ALWAYS_CUT) {
			switch(zone_cut_check(request, qry, packet)) {
			case KR_STATE_FAIL: return KR_STATE_FAIL;
			case KR_STATE_DONE: return KR_STATE_PRODUCE;
			default: break;
			}
		}
		/* Resolve current query and produce dependent or finish */
		request->state = KR_STATE_PRODUCE;
		ITERATE_LAYERS(request, qry, produce, packet);
		if (request->state != KR_STATE_FAIL && knot_wire_get_qr(packet->wire)) {
			/* Produced an answer from cache, consume it. */
			qry->secret = 0;
			request->state = KR_STATE_CONSUME;
			ITERATE_LAYERS(request, qry, consume, packet);
		}
	}
	switch(request->state) {
	case KR_STATE_FAIL: return request->state;
	case KR_STATE_CONSUME: break;
	case KR_STATE_DONE:
	default: /* Current query is done */
		if (qry->flags.RESOLVED && request->state != KR_STATE_YIELD) {
			kr_rplan_pop(rplan, qry);
		}
		ITERATE_LAYERS(request, qry, reset);
		return kr_rplan_empty(rplan) ? KR_STATE_DONE : KR_STATE_PRODUCE;
	}
	

	/* This query has RD=0 or is ANY, stop here. */
	if (qry->stype == KNOT_RRTYPE_ANY || !knot_wire_get_rd(request->answer->wire)) {
		VERBOSE_MSG(qry, "=> qtype is ANY or RD=0, bail out\n");
		return KR_STATE_FAIL;
	}

	/* Update zone cut, spawn new subrequests. */
	if (!(qry->flags.STUB)) {
		int state = zone_cut_check(request, qry, packet);
		switch(state) {
		case KR_STATE_FAIL: return KR_STATE_FAIL;
		case KR_STATE_DONE: return KR_STATE_PRODUCE;
		default: break;
		}
	}

ns_election:

	/* If the query has already selected a NS and is waiting for IPv4/IPv6 record,
	 * elect best address only, otherwise elect a completely new NS.
	 */
	if(++ns_election_iter >= KR_ITER_LIMIT) {
		VERBOSE_MSG(qry, "=> couldn't converge NS selection, bail out\n");
		return KR_STATE_FAIL;
	}

	const struct kr_qflags qflg = qry->flags;
	const bool retry = qflg.TCP || qflg.BADCOOKIE_AGAIN;
	if (qflg.AWAIT_IPV4 || qflg.AWAIT_IPV6) {
		kr_nsrep_elect_addr(qry, request->ctx);
	} else if (qflg.FORWARD || qflg.STUB) {
		kr_nsrep_sort(&qry->ns, request->ctx->cache_rtt);
	} else if (!qry->ns.name || !retry) { /* Keep NS when requerying/stub/badcookie. */
		/* Root DNSKEY must be fetched from the hints to avoid chicken and egg problem. */
		if (qry->sname[0] == '\0' && qry->stype == KNOT_RRTYPE_DNSKEY) {
			kr_zonecut_set_sbelt(request->ctx, &qry->zone_cut);
			qry->flags.NO_THROTTLE = true; /* Pick even bad SBELT servers */
		}
		kr_nsrep_elect(qry, request->ctx);
		if (qry->ns.score > KR_NS_MAX_SCORE) {
			if (kr_zonecut_is_empty(&qry->zone_cut)) {
				VERBOSE_MSG(qry, "=> no NS with an address\n");
			} else {
				VERBOSE_MSG(qry, "=> no valid NS left\n");
			}
			if (!qry->flags.NO_NS_FOUND) {
				qry->flags.NO_NS_FOUND = true;
			} else {
				ITERATE_LAYERS(request, qry, reset);
				kr_rplan_pop(rplan, qry);
			}
			return KR_STATE_PRODUCE;
		}
	}

	/* Resolve address records */
	if (qry->ns.addr[0].ip.sa_family == AF_UNSPEC) {
		int ret = ns_resolve_addr(qry, request);
		if (ret != 0) {
			qry->flags.AWAIT_IPV6 = false;
			qry->flags.AWAIT_IPV4 = false;
			qry->flags.TCP = false;
			qry->ns.name = NULL;
			goto ns_election; /* Must try different NS */
		}
		ITERATE_LAYERS(request, qry, reset);
		return KR_STATE_PRODUCE;
	}

	/* Randomize query case (if not in safemode or turned off) */
	qry->secret = (qry->flags.SAFEMODE || qry->flags.NO_0X20)
			? 0 : kr_rand_uint(0);
	knot_dname_t *qname_raw = (knot_dname_t *)knot_pkt_qname(packet);
	randomized_qname_case(qname_raw, qry->secret);

	/*
	 * Additional query is going to be finalised when calling
	 * kr_resolve_checkout().
	 */
	qry->timestamp_mono = kr_now();
	*dst = &qry->ns.addr[0].ip;
	*type = (qry->flags.TCP) ? SOCK_STREAM : SOCK_DGRAM;
	return request->state;
}

#if defined(ENABLE_COOKIES)
/** Update DNS cookie data in packet. */
static bool outbound_request_update_cookies(struct kr_request *req,
                                            const struct sockaddr *src,
                                            const struct sockaddr *dst)
{
	assert(req);

	/* RFC7873 4.1 strongly requires server address. */
	if (!dst) {
		return false;
	}

	struct kr_cookie_settings *clnt_sett = &req->ctx->cookie_ctx.clnt;

	/* Cookies disabled or packet has no EDNS section. */
	if (!clnt_sett->enabled) {
		return true;
	}

	/*
	 * RFC7873 4.1 recommends using also the client address. The matter is
	 * also discussed in section 6.
	 */

	kr_request_put_cookie(&clnt_sett->current, req->ctx->cache_cookie,
	                      src, dst, req);

	return true;
}
#endif /* defined(ENABLE_COOKIES) */

int kr_resolve_checkout(struct kr_request *request, struct sockaddr *src,
                        struct sockaddr *dst, int type, knot_pkt_t *packet)
{
	/* @todo: Update documentation if this function becomes approved. */

	struct kr_rplan *rplan = &request->rplan;

	if (knot_wire_get_qr(packet->wire) != 0) {
		return kr_ok();
	}

	/* No query left for resolution */
	if (kr_rplan_empty(rplan)) {
		return kr_error(EINVAL);
	}
	struct kr_query *qry = array_tail(rplan->pending);

#if defined(ENABLE_COOKIES)
	/* Update DNS cookies in request. */
	if (type == SOCK_DGRAM) { /* @todo: Add cookies also over TCP? */
		/*
		 * The actual server IP address is needed before generating the
		 * actual cookie. If we don't know the server address then we
		 * also don't know the actual cookie size.
		 */
		if (!outbound_request_update_cookies(request, src, dst)) {
			return kr_error(EINVAL);
		}
	}
#endif /* defined(ENABLE_COOKIES) */

	int ret = query_finalize(request, qry, packet);
	if (ret != 0) {
		return kr_error(EINVAL);
	}

	WITH_VERBOSE(qry) {
	char qname_str[KNOT_DNAME_MAXLEN], zonecut_str[KNOT_DNAME_MAXLEN], ns_str[INET6_ADDRSTRLEN], type_str[16];
	knot_dname_to_str(qname_str, knot_pkt_qname(packet), sizeof(qname_str));
	knot_dname_to_str(zonecut_str, qry->zone_cut.name, sizeof(zonecut_str));
	knot_rrtype_to_string(knot_pkt_qtype(packet), type_str, sizeof(type_str));
	for (size_t i = 0; i < KR_NSREP_MAXADDR; ++i) {
		struct sockaddr *addr = &qry->ns.addr[i].ip;
		if (addr->sa_family == AF_UNSPEC) {
			break;
		}
		if (!kr_inaddr_equal(dst, addr)) {
			continue;
		}
		inet_ntop(addr->sa_family, kr_inaddr(&qry->ns.addr[i].ip), ns_str, sizeof(ns_str));
		VERBOSE_MSG(qry,
			"=> querying: '%s' score: %u zone cut: '%s' qname: '%s' qtype: '%s' proto: '%s'\n",
			ns_str, qry->ns.score, zonecut_str, qname_str, type_str, (qry->flags.TCP) ? "tcp" : "udp");
		break;
	}}

	return kr_ok();
}

int kr_resolve_finish(struct kr_request *request, int state)
{
#ifndef NOVERBOSELOG
	struct kr_rplan *rplan = &request->rplan;
#endif
	/* Finalize answer */
	if (answer_finalize(request, state) != 0) {
		state = KR_STATE_FAIL;
	}
	/* Error during procesing, internal failure */
	if (state != KR_STATE_DONE) {
		knot_pkt_t *answer = request->answer;
		if (knot_wire_get_rcode(answer->wire) == KNOT_RCODE_NOERROR) {
			knot_wire_set_rcode(answer->wire, KNOT_RCODE_SERVFAIL);
		}
	}

	request->state = state;
	ITERATE_LAYERS(request, NULL, finish);

	struct kr_query *last = kr_rplan_last(rplan);
	VERBOSE_MSG(last, "finished: %d, queries: %zu, mempool: %zu B\n",
	          request->state, rplan->resolved.len, (size_t) mp_total_size(request->pool.ctx));

	/* Trace request finish */
	if (request->trace_finish) {
		request->trace_finish(request);
	}

	/* Uninstall all tracepoints */
	request->trace_finish = NULL;
	request->trace_log = NULL;

	return KR_STATE_DONE;
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

#undef VERBOSE_MSG
