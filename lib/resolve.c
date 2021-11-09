/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/descriptor.h>
#include <ucw/mempool.h>
#include <sys/socket.h>
#include "kresconfig.h"
#include "lib/resolve.h"
#include "lib/layer.h"
#include "lib/rplan.h"
#include "lib/layer/iterate.h"
#include "lib/dnssec/ta.h"
#include "lib/dnssec.h"
#if ENABLE_COOKIES
#include "lib/cookies/control.h"
#include "lib/cookies/helper.h"
#include "lib/cookies/nonce.h"
#else /* Define compatibility macros */
#define KNOT_EDNS_OPTION_COOKIE 10
#endif /* ENABLE_COOKIES */

#define VERBOSE_MSG(qry, ...) kr_log_q((qry), RESOLVER,  __VA_ARGS__)

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

bool kr_rank_test(uint8_t rank, uint8_t kr_flag)
{
	if (kr_fails_assert(kr_rank_check(rank) && kr_rank_check(kr_flag)))
		return false;
	if (kr_flag == KR_RANK_AUTH) {
		return rank & KR_RANK_AUTH;
	}
	if (kr_fails_assert(!(kr_flag & KR_RANK_AUTH)))
		return false;
	/* The rest are exclusive values - exactly one has to be set. */
	return (rank & ~KR_RANK_AUTH) == kr_flag;
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
	size_t pkt_size = pkt->size;
	if (knot_pkt_has_tsig(pkt)) {
		pkt_size += pkt->tsig_wire.len;
	}
	knot_pkt_t *pkt_copy = knot_pkt_new(NULL, pkt_size, &req->pool);
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
static int checkout_yield(kr_layer_t *ctx, knot_pkt_t *packet, struct sockaddr *dst, int type) { return kr_ok(); }
static int answer_finalize_yield(kr_layer_t *ctx) { return kr_ok(); }

/** @internal Macro for iterating module layers. */
#define RESUME_LAYERS(from, r, qry, func, ...) \
    (r)->current_query = (qry); \
	for (size_t i = (from); i < (r)->ctx->modules->len; ++i) { \
		struct kr_module *mod = (r)->ctx->modules->at[i]; \
		if (mod->layer) { \
			struct kr_layer layer = {.state = (r)->state, .api = mod->layer, .req = (r)}; \
			if (layer.api && layer.api->func) { \
				(r)->state = layer.api->func(&layer, ##__VA_ARGS__); \
				/* It's an easy mistake to return error code, for example. */ \
				/* (though we could allow such an overload later) */ \
				if (kr_fails_assert(kr_state_consistent((r)->state))) { \
					(r)->state = KR_STATE_FAIL; \
				} else \
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
		if (modules->at[i]->layer == api) {
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
	if (secret == 0)
		return;
	if (kr_fails_assert(qname))
		return;
	const int len = knot_dname_size(qname) - 2; /* Skip first, last label. First is length, last is always root */
	for (int i = 0; i < len; ++i) {
		/* Note: this relies on the fact that correct label lengths
		 * can't pass the isletter() test (by "luck"). */
		if (isletter(*++qname)) {
				*qname ^= ((secret >> (i & 31)) & 1) * 0x20;
		}
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
		kr_assert(target[0]);
		target = knot_wire_next_label(target, NULL);
	}
	kr_cache_commit(cache);
#endif
}

static int ns_fetch_cut(struct kr_query *qry, const knot_dname_t *requested_name,
			struct kr_request *req, knot_pkt_t *pkt)
{
	/* It can occur that here parent query already have
	 * provably insecure zonecut which not in the cache yet. */
	struct kr_qflags pflags;
	if (qry->parent) {
		pflags = qry->parent->flags;
	}
	const bool is_insecure = qry->parent != NULL
		&& !(pflags.AWAIT_IPV4 || pflags.AWAIT_IPV6)
		&& (pflags.DNSSEC_INSECURE || pflags.DNSSEC_NODS);

	/* Want DNSSEC if it's possible to secure this name
	 * (e.g. is covered by any TA) */
	if (is_insecure) {
		/* If parent is insecure we don't want DNSSEC
		 * even if cut name is covered by TA. */
		qry->flags.DNSSEC_WANT = false;
		qry->flags.DNSSEC_INSECURE = true;
		VERBOSE_MSG(qry, "=> going insecure because parent query is insecure\n");
	} else if (kr_ta_closest(req->ctx, qry->zone_cut.name, KNOT_RRTYPE_NS)) {
		qry->flags.DNSSEC_WANT = true;
	} else {
		qry->flags.DNSSEC_WANT = false;
		VERBOSE_MSG(qry, "=> going insecure because there's no covering TA\n");
	}

	struct kr_zonecut cut_found;
	kr_zonecut_init(&cut_found, requested_name, req->rplan.pool);
	/* Cut that has been found can differs from cut that has been requested.
	 * So if not already insecure,
	 * try to fetch ta & keys even if initial cut name not covered by TA */
	bool secure = !is_insecure;
	int ret = kr_zonecut_find_cached(req->ctx, &cut_found, requested_name,
					 qry, &secure);
	if (ret == kr_error(ENOENT)) {
		/* No cached cut found, start from SBELT
		 * and issue priming query. */
		kr_zonecut_deinit(&cut_found);
		ret = kr_zonecut_set_sbelt(req->ctx, &qry->zone_cut);
		if (ret != 0) {
			return KR_STATE_FAIL;
		}
		VERBOSE_MSG(qry, "=> using root hints\n");
		qry->flags.AWAIT_CUT = false;
		return KR_STATE_DONE;
	} else if (ret != kr_ok()) {
		kr_zonecut_deinit(&cut_found);
		return KR_STATE_FAIL;
	}

	/* Find out security status.
	 * Go insecure if the zone cut is provably insecure */
	if ((qry->flags.DNSSEC_WANT) && !secure) {
		VERBOSE_MSG(qry, "=> NS is provably without DS, going insecure\n");
		qry->flags.DNSSEC_WANT = false;
		qry->flags.DNSSEC_INSECURE = true;
	}
	/* Zonecut name can change, check it again
	 * to prevent unnecessary DS & DNSKEY queries */
	if (!(qry->flags.DNSSEC_INSECURE) &&
	    kr_ta_closest(req->ctx, cut_found.name, KNOT_RRTYPE_NS)) {
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
	/* Use the found zone cut. */
	kr_zonecut_move(&qry->zone_cut, &cut_found);
	/* Check if there's a non-terminal between target and current cut. */
	struct kr_cache *cache = &req->ctx->cache;
	check_empty_nonterms(qry, pkt, cache, qry->timestamp.tv_sec);
	/* Cut found */
	return KR_STATE_PRODUCE;
}

static int edns_put(knot_pkt_t *pkt, bool reclaim)
{
	if (!pkt->opt_rr) {
		return kr_ok();
	}
	if (reclaim) {
		/* Reclaim reserved size. */
		int ret = knot_pkt_reclaim(pkt, knot_edns_wire_size(pkt->opt_rr));
		if (ret != 0) {
			return ret;
		}
	}
	/* Write to packet. */
	if (kr_fails_assert(pkt->current == KNOT_ADDITIONAL))
		return kr_error(EINVAL);
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
	int16_t rr_removed = pkt->opt_rr->rrs.count;
	/* Decrease rrset counters. */
	pkt->rrset_count -= 1;
	pkt->sections[pkt->current].count -= 1;
	pkt->size -= len;
	knot_wire_add_arcount(pkt->wire, -rr_removed); /* ADDITIONAL */

	pkt->opt_rr = NULL;

	/* Reserve the freed space. */
	return knot_pkt_reserve(pkt, len);
}

static int edns_create(knot_pkt_t *pkt, const struct kr_request *req)
{
	pkt->opt_rr = knot_rrset_copy(req->ctx->upstream_opt_rr, &pkt->mm);
	size_t wire_size = knot_edns_wire_size(pkt->opt_rr);
#if ENABLE_COOKIES
	if (req->ctx->cookie_ctx.clnt.enabled ||
	    req->ctx->cookie_ctx.srvr.enabled) {
		wire_size += KR_COOKIE_OPT_MAX_LEN;
	}
#endif /* ENABLE_COOKIES */
	if (req->qsource.flags.tls) {
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

/**
 * @param all_secure optionally &&-combine security of written RRs into its value.
 *		     (i.e. if you pass a pointer to false, it will always remain)
 * @param all_cname optionally output if all written RRs are CNAMEs and RRSIGs of CNAMEs
 * @return error code, ignoring if forced to truncate the packet.
 */
static int write_extra_ranked_records(const ranked_rr_array_t *arr, uint16_t reorder,
				      knot_pkt_t *answer, bool *all_secure, bool *all_cname)
{
	const bool has_dnssec = knot_pkt_has_dnssec(answer);
	bool all_sec = true;
	bool all_cn = (all_cname != NULL); /* optim.: init as false if not needed */
	int err = kr_ok();

	for (size_t i = 0; i < arr->len; ++i) {
		ranked_rr_array_entry_t * entry = arr->at[i];
		kr_assert(!entry->in_progress);
		if (!entry->to_wire) {
			continue;
		}
		knot_rrset_t *rr = entry->rr;
		if (!has_dnssec) {
			if (rr->type != knot_pkt_qtype(answer) && knot_rrtype_is_dnssec(rr->type)) {
				continue;
			}
		}
		err = knot_pkt_put_rotate(answer, 0, rr, reorder, 0);
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
	if (kr_fails_assert(request && request->answer && request->ctx))
		return kr_error(EINVAL);
	if (!request->qsource.flags.tls) {
		/* Not meaningful to pad without encryption. */
		return kr_ok();
	}
	int32_t padding = request->ctx->tls_padding;
	knot_pkt_t *answer = request->answer;
	knot_rrset_t *opt_rr = answer->opt_rr;
	int32_t pad_bytes = -1;

	if (padding == -1) { /* use the default padding policy from libknot */
		pad_bytes =  knot_pkt_default_padding_size(answer, opt_rr);
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

/* Make a clean SERVFAIL answer. */
static void answer_fail(struct kr_request *request)
{
	/* Note: OPT in SERVFAIL response is still useful for cookies/additional info. */
	if (kr_log_is_debug(RESOLVER, request))  /* logging optimization */
		kr_log_req(request, 0, 0, RESOLVER,
			"request failed, answering with empty SERVFAIL\n");
	knot_pkt_t *answer = request->answer;
	knot_rrset_t *opt_rr = answer->opt_rr; /* it gets NULLed below */
	int ret = kr_pkt_clear_payload(answer);
	knot_wire_clear_ad(answer->wire);
	knot_wire_clear_aa(answer->wire);
	knot_wire_set_rcode(answer->wire, KNOT_RCODE_SERVFAIL);
	if (ret == 0 && opt_rr) {
		knot_pkt_begin(answer, KNOT_ADDITIONAL);
		answer->opt_rr = opt_rr;
		answer_padding(request); /* Ignore failed padding in SERVFAIL answer. */
		edns_put(answer, false);
	}
}

/* Append EDNS records into the answer. */
static int answer_append_edns(struct kr_request *request)
{
	knot_pkt_t *answer = request->answer;
	if (!answer->opt_rr)
		return kr_ok();
	int ret = answer_padding(request);
	if (!ret) ret = knot_pkt_begin(answer, KNOT_ADDITIONAL);
	if (!ret) ret = knot_pkt_put(answer, KNOT_COMPR_HINT_NONE,
				     answer->opt_rr, KNOT_PF_FREE);
	return ret;
}

static void answer_finalize(struct kr_request *request)
{
	struct kr_rplan *rplan = &request->rplan;
	knot_pkt_t *answer = request->answer;
	const uint8_t *q_wire = request->qsource.packet->wire;

	if (answer->rrset_count != 0) {
		/* Non-standard: we assume the answer had been constructed.
		 * Let's check we don't have a "collision". */
		const ranked_rr_array_t *selected[] = kr_request_selected(request);
		for (int psec = KNOT_ANSWER; psec <= KNOT_ADDITIONAL; ++psec) {
			const ranked_rr_array_t *arr = selected[psec];
			for (ssize_t i = 0; i < arr->len; ++i) {
				if (kr_fails_assert(!arr->at[i]->to_wire)) {
					answer_fail(request);
					return;
				}
			}
		}
		/* We only add EDNS, and we even assume AD bit was correct. */
		if (answer_append_edns(request)) {
			answer_fail(request);
			return;
		}
		return;
	}

	struct kr_query *const last =
		rplan->resolved.len > 0 ? array_tail(rplan->resolved) : NULL;
		/* TODO  ^^^^ this is slightly fragile */

	if (!last) {
		/* Suspicious: no kr_query got resolved (not even from cache),
		 * so let's (defensively) SERVFAIL the request.
		 * ATM many checks below depend on `last` anyway,
		 * so this helps to avoid surprises. */
		answer_fail(request);
		return;
	}
	/* TODO: clean this up in !660 or followup, and it isn't foolproof anyway. */
	if (last->flags.DNSSEC_BOGUS
	    || (rplan->pending.len > 0 && array_tail(rplan->pending)->flags.DNSSEC_BOGUS)) {
		if (!knot_wire_get_cd(q_wire)) {
			answer_fail(request);
			return;
		}
	}

	/* AD flag.  We can only change `secure` from true to false.
	 * Be conservative.  Primary approach: check ranks of all RRs in wire.
	 * Only "negative answers" need special handling. */
	bool secure = last != NULL && request->state == KR_STATE_DONE /*< suspicious otherwise */
		&& knot_pkt_qtype(answer) != KNOT_RRTYPE_RRSIG;
	if (last && (last->flags.STUB)) {
		secure = false; /* don't trust forwarding for now */
	}
	if (last && (last->flags.DNSSEC_OPTOUT)) {
		VERBOSE_MSG(last, "insecure because of opt-out\n");
		secure = false; /* the last answer is insecure due to opt-out */
	}

	/* Write all RRsets meant for the answer. */
	const uint16_t reorder = last ? last->reorder : 0;
	bool answ_all_cnames = false/*arbitrary*/;
	if (knot_pkt_begin(answer, KNOT_ANSWER)
	    || write_extra_ranked_records(&request->answ_selected, reorder,
					answer, &secure, &answ_all_cnames)
	    || knot_pkt_begin(answer, KNOT_AUTHORITY)
	    || write_extra_ranked_records(&request->auth_selected, reorder,
					answer, &secure, NULL)
	    || knot_pkt_begin(answer, KNOT_ADDITIONAL)
	    || write_extra_ranked_records(&request->add_selected, reorder,
					answer, NULL/*not relevant to AD*/, NULL)
	    || answer_append_edns(request)
	   )
	{
		answer_fail(request);
		return;
	}

	if (!last) secure = false; /*< should be no-op, mostly documentation */
	/* AD: "negative answers" need more handling. */
	if (kr_response_classify(answer) != PKT_NOERROR
	    /* Additionally check for CNAME chains that "end in NODATA",
	     * as those would also be PKT_NOERROR. */
	    || (answ_all_cnames && knot_pkt_qtype(answer) != KNOT_RRTYPE_CNAME)) {

		secure = secure && last->flags.DNSSEC_WANT
			&& !last->flags.DNSSEC_BOGUS && !last->flags.DNSSEC_INSECURE;
	}

	if (secure) {
		struct kr_query *cname_parent = last->cname_parent;
		while (cname_parent != NULL) {
			if (cname_parent->flags.DNSSEC_OPTOUT) {
				secure = false;
				break;
			}
			cname_parent = cname_parent->cname_parent;
		}
	}

	/* No detailed analysis ATM, just _SECURE or not.
	 * LATER: request->rank might better be computed in validator's finish phase. */
	VERBOSE_MSG(last, "AD: request%s classified as SECURE\n", secure ? "" : " NOT");
	request->rank = secure ? KR_RANK_SECURE : KR_RANK_INITIAL;

	/* Set AD if secure and AD bit "was requested". */
	if (secure && !knot_wire_get_cd(q_wire)
	    && (knot_pkt_has_dnssec(answer) || knot_wire_get_ad(q_wire))) {
		knot_wire_set_ad(answer->wire);
	}
}

static int query_finalize(struct kr_request *request, struct kr_query *qry, knot_pkt_t *pkt)
{
	knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	if (qry->flags.NO_EDNS)
		return kr_ok();
	/* Remove any EDNS records from any previous iteration. */
	int ret = edns_erase_and_reserve(pkt);
	if (ret) return ret;
	ret = edns_create(pkt, request);
	if (ret) return ret;
	if (qry->flags.STUB) {
		/* Stub resolution (ask for +rd and +do) */
		knot_wire_set_rd(pkt->wire);
		if (knot_pkt_has_dnssec(request->qsource.packet)) {
			knot_edns_set_do(pkt->opt_rr);
		}
		if (knot_wire_get_cd(request->qsource.packet->wire)) {
			knot_wire_set_cd(pkt->wire);
		}
	} else {
		/* Full resolution (ask for +cd and +do) */
		knot_edns_set_do(pkt->opt_rr);
		knot_wire_set_cd(pkt->wire);
		if (qry->flags.FORWARD) {
			knot_wire_set_rd(pkt->wire);
		}
	}
	return kr_ok();
}

int kr_resolve_begin(struct kr_request *request, struct kr_context *ctx)
{
	/* Initialize request */
	request->ctx = ctx;
	request->answer = NULL;
	request->options = ctx->options;
	request->state = KR_STATE_CONSUME;
	request->current_query = NULL;
	array_init(request->answ_selected);
	array_init(request->auth_selected);
	array_init(request->add_selected);
	request->answ_validated = false;
	request->auth_validated = false;
	request->rank = KR_RANK_INITIAL;
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
	struct kr_query *qry = NULL;
	struct kr_context *ctx = request->ctx;
	struct kr_cookie_ctx *cookie_ctx = ctx ? &ctx->cookie_ctx : NULL;

	if (qname != NULL) {
		qry = kr_rplan_push(rplan, NULL, qname, qclass, qtype);
	} else if (cookie_ctx && cookie_ctx->srvr.enabled &&
		   knot_wire_get_qdcount(packet->wire) == 0 &&
		   knot_pkt_has_edns(packet) &&
		   knot_pkt_edns_option(packet, KNOT_EDNS_OPTION_COOKIE)) {
		/* Plan empty query only for cookies. */
		qry = kr_rplan_push_empty(rplan, NULL);
	}
	if (!qry) {
		return KR_STATE_FAIL;
	}

	if (qname != NULL) {
		/* Deferred zone cut lookup for this query. */
		qry->flags.AWAIT_CUT = true;
		/* Want DNSSEC if it's possible to secure this name (e.g. is covered by any TA) */
		if ((knot_wire_get_ad(packet->wire) || knot_pkt_has_dnssec(packet)) &&
		    kr_ta_closest(request->ctx, qry->sname, qtype)) {
			qry->flags.DNSSEC_WANT = true;
		}
	}

	/* Expect answer, pop if satisfied immediately */
	ITERATE_LAYERS(request, qry, begin);
	if ((request->state & KR_STATE_DONE) != 0) {
		kr_rplan_pop(rplan, qry);
	} else if (qname == NULL) {
		/* it is an empty query which must be resolved by
		   `begin` layer of cookie module.
		   If query isn't resolved, fail. */
		request->state = KR_STATE_FAIL;
	}
	return request->state;
}

knot_rrset_t* kr_request_ensure_edns(struct kr_request *request)
{
	kr_require(request && request->answer && request->qsource.packet && request->ctx);
	knot_pkt_t* answer = request->answer;
	bool want_edns = knot_pkt_has_edns(request->qsource.packet);
	if (!want_edns) {
		kr_assert(!answer->opt_rr);
		return answer->opt_rr;
	} else if (answer->opt_rr) {
		return answer->opt_rr;
	}

	kr_assert(request->ctx->downstream_opt_rr);
	answer->opt_rr = knot_rrset_copy(request->ctx->downstream_opt_rr, &answer->mm);
	if (!answer->opt_rr)
		return NULL;
	if (knot_pkt_has_dnssec(request->qsource.packet))
		knot_edns_set_do(answer->opt_rr);
	return answer->opt_rr;
}

knot_pkt_t *kr_request_ensure_answer(struct kr_request *request)
{
	if (request->answer)
		return request->answer;

	const knot_pkt_t *qs_pkt = request->qsource.packet;
	if (kr_fails_assert(qs_pkt))
		goto fail;
	// Find answer_max: limit on DNS wire length.
	uint16_t answer_max;
	const struct kr_request_qsource_flags *qs_flags = &request->qsource.flags;
	if (kr_fails_assert((qs_flags->tls || qs_flags->http) ? qs_flags->tcp : true))
		goto fail;
	if (!request->qsource.addr || qs_flags->tcp) {
		// not on UDP
		answer_max = KNOT_WIRE_MAX_PKTSIZE;
	} else if (knot_pkt_has_edns(qs_pkt)) {
		// UDP with EDNS
		answer_max = MIN(knot_edns_get_payload(qs_pkt->opt_rr),
				 knot_edns_get_payload(request->ctx->downstream_opt_rr));
		answer_max = MAX(answer_max, KNOT_WIRE_MIN_PKTSIZE);
	} else {
		// UDP without EDNS
		answer_max = KNOT_WIRE_MIN_PKTSIZE;
	}

	// Allocate the packet.
	uint8_t *wire = NULL;
	if (request->alloc_wire_cb) {
		wire = request->alloc_wire_cb(request, &answer_max);
		if (!wire)
			goto enomem;
	}
	knot_pkt_t *answer = request->answer =
		knot_pkt_new(wire, answer_max, &request->pool);
	if (!answer || knot_pkt_init_response(answer, qs_pkt) != 0) {
		kr_assert(!answer); // otherwise we messed something up
		goto enomem;
	}
	if (!wire)
		wire = answer->wire;

	// Much was done by knot_pkt_init_response()
	knot_wire_set_ra(wire);
	knot_wire_set_rcode(wire, KNOT_RCODE_NOERROR);
	if (knot_wire_get_cd(qs_pkt->wire)) {
		knot_wire_set_cd(wire);
	}

	// Prepare EDNS if required.
	if (knot_pkt_has_edns(qs_pkt) && kr_fails_assert(kr_request_ensure_edns(request)))
		goto enomem; // answer is on mempool, so "leak" is OK

	return request->answer;
enomem:
fail:
	request->state = KR_STATE_FAIL; // TODO: really combine with another flag?
	return request->answer = NULL;
}

static bool resolution_time_exceeded(struct kr_query *qry, uint64_t now)
{
	uint64_t resolving_time = now - qry->creation_time_mono;
	if (resolving_time > KR_RESOLVE_TIME_LIMIT) {
		VERBOSE_MSG(qry, "query resolution time limit exceeded\n");
		return true;
	}
	return false;
}

int kr_resolve_consume(struct kr_request *request, struct kr_transport **transport, knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;

	/* Empty resolution plan, push packet as the new query */
	if (packet && kr_rplan_empty(rplan)) {
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
		return KR_STATE_PRODUCE;
	} else {
		/* Packet cleared, derandomize QNAME. */
		knot_dname_t *qname_raw = knot_pkt_qname(packet);
		if (qname_raw && qry->secret != 0) {
			randomized_qname_case(qname_raw, qry->secret);
		}
		request->state = KR_STATE_CONSUME;
		if (qry->flags.CACHED) {
			ITERATE_LAYERS(request, qry, consume, packet);
		} else {
			/* Fill in source and latency information. */
			request->upstream.rtt = kr_now() - qry->timestamp_mono;
			request->upstream.transport = transport ? *transport : NULL;
			ITERATE_LAYERS(request, qry, consume, packet);
			/* Clear temporary information */
			request->upstream.transport = NULL;
			request->upstream.rtt = 0;
		}
	}

	if (transport && !qry->flags.CACHED) {
		if (!(request->state & KR_STATE_FAIL)) {
			/* Do not complete NS address resolution on soft-fail. */
			const int rcode = packet ? knot_wire_get_rcode(packet->wire) : 0;
			if (rcode != KNOT_RCODE_SERVFAIL && rcode != KNOT_RCODE_REFUSED) {
				qry->flags.AWAIT_IPV6 = false;
				qry->flags.AWAIT_IPV4 = false;
			}
		}
	}

	if (request->state & KR_STATE_FAIL) {
		qry->flags.RESOLVED = false;
	}

	if (!qry->flags.CACHED) {
		if (request->state & KR_STATE_FAIL) {
			if (++request->count_fail_row > KR_CONSUME_FAIL_ROW_LIMIT) {
				if (kr_log_is_debug(RESOLVER, request)) {  /* logging optimization */
					kr_log_req(request, 0, 2, RESOLVER,
						"=> too many failures in a row, "
						"bail out (mitigation for NXNSAttack "
						"CVE-2020-12667)\n");
				}
				if (!qry->flags.NO_NS_FOUND) {
					qry->flags.NO_NS_FOUND = true;
					return KR_STATE_PRODUCE;
				}
				return KR_STATE_FAIL;
			}
		} else {
			request->count_fail_row = 0;
		}
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
		if (qry->flags.FORWARD || qry->flags.STUB) {
			return KR_STATE_FAIL;
		}
		/* Other servers might not have broken DNSSEC. */
		qry->flags.DNSSEC_BOGUS = false;
		return KR_STATE_PRODUCE;
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
	    knot_dname_in_bailiwick(qry->zone_cut.name, qry->parent->zone_cut.name) >= 0) {
		return KR_STATE_PRODUCE;
	}

	if (kr_fails_assert(qry->flags.FORWARD))
		return KR_STATE_FAIL;

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

	const knot_dname_t *start_name = qry->sname;
	if ((qry->flags.AWAIT_CUT) && !resume) {
		qry->flags.AWAIT_CUT = false;
		const knot_dname_t *longest_ta = kr_ta_closest(request->ctx, qry->sname, qry->stype);
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

	int name_offset = 1;
	const knot_dname_t *wanted_name;
	bool nods, ds_req, ns_req, minimized, ns_exist;
	do {
		wanted_name = start_name;
		ds_req = false;
		ns_req = false;
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
					if (q->flags.CNAME) {
						ns_exist = false;
					} else if (!(q->flags.DNSSEC_OPTOUT)) {
						int ret = kr_dnssec_matches_name_and_type(&request->auth_selected, q->uid,
											  wanted_name, KNOT_RRTYPE_NS);
						ns_exist = (ret == kr_ok());
					}
				} else {
					if (q->flags.CNAME) {
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

		/* set `nods` */
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
	bool want_secure = (qry->flags.DNSSEC_WANT) &&
			    !knot_wire_get_cd(request->qsource.packet->wire);
	if (!(qry->flags.DNSSEC_WANT) &&
	    !knot_wire_get_cd(request->qsource.packet->wire) &&
	    kr_ta_get(trust_anchors, wanted_name)) {
		qry->flags.DNSSEC_WANT = true;
		want_secure = true;
		if (kr_log_is_debug_qry(RESOLVER, qry)) {
			KR_DNAME_GET_STR(qname_str, wanted_name);
			VERBOSE_MSG(qry, ">< TA: '%s'\n", qname_str);
		}
	}

	if (want_secure && !qry->zone_cut.trust_anchor) {
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
	if (!nods && want_secure && refetch_ta) {
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
	if (want_secure && refetch_key && !is_dnskey_subreq) {
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
		 * At previous iteration DS non-existence has been proven */
		VERBOSE_MSG(qry, "<= DS doesn't exist, going insecure\n");
		qry->flags.DNSSEC_NODS = false;
		qry->flags.DNSSEC_WANT = false;
		qry->flags.DNSSEC_INSECURE = true;
	}
	/* Enable DNSSEC if entering a new (or different) island of trust,
	 * and update the TA RRset if required. */
	const bool has_cd = knot_wire_get_cd(request->qsource.packet->wire);
	knot_rrset_t *ta_rr = kr_ta_get(trust_anchors, qry->zone_cut.name);
	if (!has_cd && ta_rr) {
		qry->flags.DNSSEC_WANT = true;
		if (qry->zone_cut.trust_anchor == NULL
		    || !knot_dname_is_equal(qry->zone_cut.trust_anchor->owner, qry->zone_cut.name)) {
			mm_free(qry->zone_cut.pool, qry->zone_cut.trust_anchor);
			qry->zone_cut.trust_anchor = knot_rrset_copy(ta_rr, qry->zone_cut.pool);

			if (kr_log_is_debug_qry(RESOLVER, qry)) {
				KR_DNAME_GET_STR(qname_str, ta_rr->owner);
				VERBOSE_MSG(qry, ">< TA: '%s'\n", qname_str);
			}
		}
	}

	/* Try to fetch missing DS (from above the cut). */
	const bool has_ta = (qry->zone_cut.trust_anchor != NULL);
	const knot_dname_t *ta_name = (has_ta ? qry->zone_cut.trust_anchor->owner : NULL);
	const bool refetch_ta = !has_ta || !knot_dname_is_equal(qry->zone_cut.name, ta_name);
	const bool want_secure = qry->flags.DNSSEC_WANT && !has_cd;
	if (want_secure && refetch_ta) {
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
	if (want_secure && refetch_key && !is_dnskey_subreq) {
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
		if (parent[0] != '\0'
		    && knot_dname_in_bailiwick(qry->sname, parent) >= 0) {
			requested_name = knot_wire_next_label(parent, NULL);
		}
	} else if ((qry->stype == KNOT_RRTYPE_DS) && (qry->sname[0] != '\0')) {
		/* If this is explicit DS query, start from encloser too. */
		requested_name = knot_wire_next_label(requested_name, NULL);
	}

	int state = KR_STATE_FAIL;
	do {
		state = ns_fetch_cut(qry, requested_name, request, packet);
		if (state == KR_STATE_DONE || (state & KR_STATE_FAIL)) {
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


static int ns_resolve_addr(struct kr_query *qry, struct kr_request *param, struct kr_transport *transport, uint16_t next_type)
{
	struct kr_rplan *rplan = &param->rplan;
	struct kr_context *ctx = param->ctx;


	/* Start NS queries from root, to avoid certain cases
	 * where a NS drops out of cache and the rest is unavailable,
	 * this would lead to dependency loop in current zone cut.
	 */

	/* Bail out if the query is already pending or dependency loop. */
	if (!next_type || kr_rplan_satisfies(qry->parent, transport->ns_name, KNOT_CLASS_IN, next_type)) {
		/* Fall back to SBELT if root server query fails. */
		if (!next_type && qry->zone_cut.name[0] == '\0') {
			VERBOSE_MSG(qry, "=> fallback to root hints\n");
			kr_zonecut_set_sbelt(ctx, &qry->zone_cut);
			return kr_error(EAGAIN);
		}
		/* No IPv4 nor IPv6, flag server as unusable. */
		VERBOSE_MSG(qry, "=> unresolvable NS address, bailing out\n");
		kr_zonecut_del_all(&qry->zone_cut, transport->ns_name);
		return kr_error(EHOSTUNREACH);
	}
	/* Push new query to the resolution plan */
	struct kr_query *next =
		kr_rplan_push(rplan, qry, transport->ns_name, KNOT_CLASS_IN, next_type);
	if (!next) {
		return kr_error(ENOMEM);
	}
	next->flags.NONAUTH = true;

	/* At the root level with no NS addresses, add SBELT subrequest. */
	int ret = 0;
	if (qry->zone_cut.name[0] == '\0') {
		ret = kr_zonecut_set_sbelt(ctx, &next->zone_cut);
		if (ret == 0) { /* Copy TA and key since it's the same cut to avoid lookup. */
			kr_zonecut_copy_trust(&next->zone_cut, &qry->zone_cut);
			kr_zonecut_set_sbelt(ctx, &qry->zone_cut); /* Add SBELT to parent in case query fails. */
		}
	} else {
		next->flags.AWAIT_CUT = true;
	}

	if (ret == 0) {
		if (next_type == KNOT_RRTYPE_AAAA) {
			qry->flags.AWAIT_IPV6 = true;
		} else {
			qry->flags.AWAIT_IPV4 = true;
		}
	}

	return ret;
}

int kr_resolve_produce(struct kr_request *request, struct kr_transport **transport, knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;

	/* No query left for resolution */
	if (kr_rplan_empty(rplan)) {
		return KR_STATE_FAIL;
	}

	struct kr_query *qry = array_tail(rplan->pending);

	/* Initialize server selection */
	if (!qry->server_selection.initialized) {
		kr_server_selection_init(qry);
	}

	/* If we have deferred answers, resume them. */
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
		 * this is normally not required, and incurs another cache lookups for cached answer. */
		if (qry->flags.ALWAYS_CUT) {
			if (!(qry->flags.STUB)) {
				switch(zone_cut_check(request, qry, packet)) {
				case KR_STATE_FAIL: return KR_STATE_FAIL;
				case KR_STATE_DONE: return KR_STATE_PRODUCE;
				default: break;
				}
			}
		}
		/* Resolve current query and produce dependent or finish */
		request->state = KR_STATE_PRODUCE;
		ITERATE_LAYERS(request, qry, produce, packet);
		if (!(request->state & KR_STATE_FAIL) && knot_wire_get_qr(packet->wire)) {
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
	if (qry->stype == KNOT_RRTYPE_ANY ||
	    !knot_wire_get_rd(request->qsource.packet->wire)) {
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


	const struct kr_qflags qflg = qry->flags;
	const bool retry = qflg.TCP || qflg.BADCOOKIE_AGAIN;
	if (!qflg.FORWARD && !qflg.STUB && !retry) { /* Keep NS when requerying/stub/badcookie. */
		/* Root DNSKEY must be fetched from the hints to avoid chicken and egg problem. */
		if (qry->sname[0] == '\0' && qry->stype == KNOT_RRTYPE_DNSKEY) {
			kr_zonecut_set_sbelt(request->ctx, &qry->zone_cut);
		}
	}

	qry->server_selection.choose_transport(qry, transport);

	if (*transport == NULL) {
		/* Properly signal to serve_stale module. */
		if (qry->flags.NO_NS_FOUND) {
			ITERATE_LAYERS(request, qry, reset);
			kr_rplan_pop(rplan, qry);
			return KR_STATE_FAIL;
		} else {
			/* FIXME: This is probably quite inefficient:
			* we go through the whole qr_task_step loop just because of the serve_stale
			* module which might not even be loaded. */
			qry->flags.NO_NS_FOUND = true;
			return KR_STATE_PRODUCE;
		}
	}

	if ((*transport)->protocol == KR_TRANSPORT_RESOLVE_A || (*transport)->protocol == KR_TRANSPORT_RESOLVE_AAAA) {
		uint16_t type = (*transport)->protocol == KR_TRANSPORT_RESOLVE_A ? KNOT_RRTYPE_A : KNOT_RRTYPE_AAAA;
		ns_resolve_addr(qry, qry->request, *transport, type);
		ITERATE_LAYERS(request, qry, reset);
		return KR_STATE_PRODUCE;
	}

	/* Randomize query case (if not in not turned off) */
	qry->secret = qry->flags.NO_0X20 ? 0 : kr_rand_bytes(sizeof(qry->secret));
	knot_dname_t *qname_raw = knot_pkt_qname(packet);
	randomized_qname_case(qname_raw, qry->secret);

	/*
	 * Additional query is going to be finalized when calling
	 * kr_resolve_checkout().
	 */
	qry->timestamp_mono = kr_now();
	return request->state;
}

#if ENABLE_COOKIES
/** Update DNS cookie data in packet. */
static bool outbound_request_update_cookies(struct kr_request *req,
                                            const struct sockaddr *src,
                                            const struct sockaddr *dst)
{
	if (kr_fails_assert(req))
		return false;

	/* RFC7873 4.1 strongly requires server address. */
	if (!dst)
		return false;

	struct kr_cookie_settings *clnt_sett = &req->ctx->cookie_ctx.clnt;

	/* Cookies disabled or packet has no EDNS section. */
	if (!clnt_sett->enabled)
		return true;

	/*
	 * RFC7873 4.1 recommends using also the client address. The matter is
	 * also discussed in section 6.
	 */

	kr_request_put_cookie(&clnt_sett->current, req->ctx->cache_cookie,
	                      src, dst, req);

	return true;
}
#endif /* ENABLE_COOKIES */

int kr_resolve_checkout(struct kr_request *request, const struct sockaddr *src,
                        struct kr_transport *transport, knot_pkt_t *packet)
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

#if ENABLE_COOKIES
	/* Update DNS cookies in request. */
	if (type == SOCK_DGRAM) { /* @todo: Add cookies also over TCP? */
		/*
		 * The actual server IP address is needed before generating the
		 * actual cookie. If we don't know the server address then we
		 * also don't know the actual cookie size.
		 */
		if (!outbound_request_update_cookies(request, src, &transport->address.ip)) {
			return kr_error(EINVAL);
		}
	}
#endif /* ENABLE_COOKIES */

	int ret = query_finalize(request, qry, packet);
	if (ret != 0) {
		return kr_error(EINVAL);
	}

	/* Track changes in minimization secret to enable/disable minimization */
	uint32_t old_minimization_secret = qry->secret;

	/* Run the checkout layers and cancel on failure.
	 * The checkout layer doesn't persist the state, so canceled subrequests
	 * don't affect the resolution or rest of the processing. */
	int type = -1;
	switch(transport->protocol) {
	case KR_TRANSPORT_UDP:
		type = SOCK_DGRAM;
		break;
	case KR_TRANSPORT_TCP:
	case KR_TRANSPORT_TLS:
		type = SOCK_STREAM;
		break;
	default:
		kr_assert(false);
	}
	int state = request->state;
	ITERATE_LAYERS(request, qry, checkout, packet, &transport->address.ip, type);
	if (request->state & KR_STATE_FAIL) {
		request->state = state; /* Restore */
		return kr_error(ECANCELED);
	}

	/* Randomize query case (if secret changed) */
	knot_dname_t *qname = knot_pkt_qname(packet);
	if (qry->secret != old_minimization_secret) {
		randomized_qname_case(qname, qry->secret);
	}

	/* Write down OPT unless in safemode */
	if (!(qry->flags.NO_EDNS)) {
		ret = edns_put(packet, true);
		if (ret != 0) {
			return kr_error(EINVAL);
		}
	}

	if (kr_log_is_debug_qry(RESOLVER, qry)) {
		KR_DNAME_GET_STR(qname_str, knot_pkt_qname(packet));
		KR_DNAME_GET_STR(ns_name, transport->ns_name);
		KR_DNAME_GET_STR(zonecut_str, qry->zone_cut.name);
		KR_RRTYPE_GET_STR(type_str, knot_pkt_qtype(packet));
		const char *ns_str = kr_straddr(&transport->address.ip);

		VERBOSE_MSG(qry,
			"=> id: '%05u' querying: '%s'@'%s' zone cut: '%s' "
			"qname: '%s' qtype: '%s' proto: '%s'\n",
			qry->id, ns_name, ns_str ? ns_str : "", zonecut_str,
			qname_str, type_str, (qry->flags.TCP) ? "tcp" : "udp");
	}

	return kr_ok();
}

int kr_resolve_finish(struct kr_request *request, int state)
{
	request->state = state;
	/* Finalize answer and construct whole wire-format (unless dropping). */
	knot_pkt_t *answer = kr_request_ensure_answer(request);
	if (answer) {
		ITERATE_LAYERS(request, NULL, answer_finalize);
		answer_finalize(request);

		/* Defensive style, in case someone has forgotten.
		 * Beware: non-empty answers do make sense even with SERVFAIL case, etc. */
		if (request->state != KR_STATE_DONE) {
			uint8_t *wire = answer->wire;
			switch (knot_wire_get_rcode(wire)) {
			case KNOT_RCODE_NOERROR:
			case KNOT_RCODE_NXDOMAIN:
				knot_wire_clear_ad(wire);
				knot_wire_clear_aa(wire);
				knot_wire_set_rcode(wire, KNOT_RCODE_SERVFAIL);
			}
		}
	}

	ITERATE_LAYERS(request, NULL, finish);

	struct kr_rplan *rplan = &request->rplan;
	struct kr_query *last = kr_rplan_last(rplan);
	VERBOSE_MSG(last, "finished in state: %d, queries: %zu, mempool: %zu B\n",
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

static int ede_priority(int info_code)
{
	switch(info_code) {
	case KNOT_EDNS_EDE_DNSKEY_BIT:
	case KNOT_EDNS_EDE_DNSKEY_MISS:
	case KNOT_EDNS_EDE_SIG_EXPIRED:
	case KNOT_EDNS_EDE_SIG_NOTYET:
	case KNOT_EDNS_EDE_RRSIG_MISS:
	case KNOT_EDNS_EDE_NSEC_MISS:
		return 900;  /* Specific DNSSEC failures */
	case KNOT_EDNS_EDE_BOGUS:
		return 800;  /* Generic DNSSEC failure */
	case KNOT_EDNS_EDE_FORGED:
	case KNOT_EDNS_EDE_FILTERED:
		return 700;  /* Considered hard fail by firefox */
	case KNOT_EDNS_EDE_PROHIBITED:
	case KNOT_EDNS_EDE_BLOCKED:
	case KNOT_EDNS_EDE_CENSORED:
		return 600;  /* Policy related */
	case KNOT_EDNS_EDE_DNSKEY_ALG:
	case KNOT_EDNS_EDE_DS_DIGEST:
		return 500;  /* Non-critical DNSSEC issues */
	case KNOT_EDNS_EDE_STALE:
	case KNOT_EDNS_EDE_INDETERMINATE:
	case KNOT_EDNS_EDE_CACHED_ERR:
	case KNOT_EDNS_EDE_NOT_READY:
	case KNOT_EDNS_EDE_STALE_NXD:
	case KNOT_EDNS_EDE_NOTAUTH:
	case KNOT_EDNS_EDE_NOTSUP:
	case KNOT_EDNS_EDE_NREACH_AUTH:
	case KNOT_EDNS_EDE_NETWORK:
	case KNOT_EDNS_EDE_INV_DATA:
		return 200;  /* Assorted codes */
	case KNOT_EDNS_EDE_OTHER:
		return 100;  /* Most generic catch-all error */
	case KNOT_EDNS_EDE_NONE:
		return 0;  /* No error - allow overriding */
	default:
		kr_assert(false);  /* Unknown info_code */
		return 50;
	}
}

int kr_request_set_extended_error(struct kr_request *request, int info_code, const char *extra_text)
{
	if (kr_fails_assert(request))
		return KNOT_EDNS_EDE_NONE;

	struct kr_extended_error *ede = &request->extended_error;

	/* Clear any previously set error. */
	if (info_code == KNOT_EDNS_EDE_NONE) {
		kr_assert(extra_text == NULL);
		ede->info_code = KNOT_EDNS_EDE_NONE;
		ede->extra_text = NULL;
		return KNOT_EDNS_EDE_NONE;
	}

	if (ede_priority(info_code) >= ede_priority(ede->info_code)) {
		ede->info_code = info_code;
		ede->extra_text = extra_text;
	}

	return ede->info_code;
}

#undef VERBOSE_MSG
