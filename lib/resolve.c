/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/resolve-impl.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/descriptor.h>
#include <ucw/mempool.h>
#include <sys/socket.h>
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

/** Magic defaults */
#ifndef LRU_RTT_SIZE
#define LRU_RTT_SIZE 65536 /**< NS RTT cache size */
#endif
#ifndef LRU_REP_SIZE
#define LRU_REP_SIZE (LRU_RTT_SIZE / 4) /**< NS reputation cache size */
#endif
#ifndef LRU_COOKIES_SIZE
	#if ENABLE_COOKIES
	#define LRU_COOKIES_SIZE LRU_RTT_SIZE /**< DNS cookies cache size. */
	#else
	#define LRU_COOKIES_SIZE LRU_ASSOC /* simpler than guards everywhere */
	#endif
#endif

static struct kr_context the_resolver_value = {{0}};
struct kr_context *the_resolver = NULL;

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
void set_yield(ranked_rr_array_t *array, const uint32_t qry_uid, const bool yielded)
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
int consume_yield(kr_layer_t *ctx, knot_pkt_t *pkt)
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

static inline size_t edns_padding_option_size(int32_t tls_padding)
{
	if (tls_padding == -1)
		/* FIXME: we do not know how to reserve space for the
		 * default padding policy, since we can't predict what
		 * it will select. So i'm just guessing :/ */
		return KNOT_EDNS_OPTION_HDRLEN + 512;
	if (tls_padding >= 2)
		return KNOT_EDNS_OPTION_HDRLEN + tls_padding;

	return 0;
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
	if (req->qsource.flags.tls || req->qsource.comm_flags.tls) {
		wire_size += edns_padding_option_size(req->ctx->tls_padding);
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

static int pkt_padding(knot_pkt_t *packet, int32_t padding)
{
	knot_rrset_t *opt_rr = packet->opt_rr;
	int32_t pad_bytes = -1;

	if (padding == -1) { /* use the default padding policy from libknot */
		const size_t block_size = knot_wire_get_qr(packet->wire)
					? KNOT_EDNS_ALIGNMENT_RESPONSE_DEFAULT
					: KNOT_EDNS_ALIGNMENT_QUERY_DEFAULT;
		pad_bytes = knot_edns_alignment_size(packet->size, knot_rrset_size(opt_rr),
							block_size);
	}
	if (padding >= 2) {
		int32_t max_pad_bytes = knot_edns_get_payload(opt_rr) - (packet->size + knot_rrset_size(opt_rr));
		pad_bytes = MIN(knot_edns_alignment_size(packet->size, knot_rrset_size(opt_rr), padding),
				max_pad_bytes);
	}

	if (pad_bytes >= 0) {
		uint8_t zeros[MAX(1, pad_bytes)];
		memset(zeros, 0, sizeof(zeros));
		int r = knot_edns_add_option(opt_rr, KNOT_EDNS_OPTION_PADDING,
					     pad_bytes, zeros, &packet->mm);
		if (r != KNOT_EOK) {
			knot_rrset_clear(opt_rr, &packet->mm);
			return kr_error(r);
		}
	}
	return kr_ok();
}

/** @internal Add an EDNS padding RR into the answer if requested and required. */
static int answer_padding(struct kr_request *request)
{
	if (kr_fails_assert(request && request->answer && request->ctx))
		return kr_error(EINVAL);
	if (!request->qsource.flags.tls && !request->qsource.comm_flags.tls) {
		/* Not meaningful to pad without encryption. */
		return kr_ok();
	}
	return pkt_padding(request->answer, request->ctx->tls_padding);
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
	bool secure = request->state == KR_STATE_DONE /*< suspicious otherwise */
		&& knot_pkt_qtype(answer) != KNOT_RRTYPE_RRSIG;
	if (last->flags.STUB) {
		secure = false; /* don't trust forwarding for now */
	}
	if (last->flags.DNSSEC_OPTOUT) {
		VERBOSE_MSG(last, "insecure because of opt-out\n");
		secure = false; /* the last answer is insecure due to opt-out */
	}

	/* Write all RRsets meant for the answer. */
	bool answ_all_cnames = false/*arbitrary*/;
	if (knot_pkt_begin(answer, KNOT_ANSWER)
	    || write_extra_ranked_records(&request->answ_selected, last->reorder,
					answer, &secure, &answ_all_cnames)
	    || knot_pkt_begin(answer, KNOT_AUTHORITY)
	    || write_extra_ranked_records(&request->auth_selected, last->reorder,
					answer, &secure, NULL)
	    || knot_pkt_begin(answer, KNOT_ADDITIONAL)
	    || write_extra_ranked_records(&request->add_selected, last->reorder,
					answer, NULL/*not relevant to AD*/, NULL)
	    || answer_append_edns(request)
	   )
	{
		answer_fail(request);
		return;
	}

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
	const bool is_iter = !(qry->flags.STUB || qry->flags.FORWARD);
	if (!is_iter)
		knot_wire_set_rd(pkt->wire);
	// The rest of this function is all about EDNS.
	if (qry->flags.NO_EDNS)
		return kr_ok();
	// Replace any EDNS records from any previous iteration.
	int ret = edns_erase_and_reserve(pkt);
	if (ret == 0) ret = edns_create(pkt, request);
	if (ret) return ret;

	if (!qry->flags.STUB)
		knot_edns_set_do(pkt->opt_rr);

	// CD flag is a bit controversial for .FORWARD:
	//  The original DNSSEC RFCs assume that if someone is validating,
	//  they will use CD=1 in requests to upstream.  The intention was that
	//  this way both sides could use independent sets of trust anchors.
	//
	//  However, in practice the trust anchor differences seem rather rare/small.
	//  And some of the normal use cases get harmed.  With CD=1, the upstream
	//  (e.g. 1.1.1.1) can keep returning a cached bogus answer, even though they could
	//  instead retry with a different authoritative server and get a good one.
	//
	//  Therefore if we want validaton (CD from client, negative trust anchors),
	//  we send CD=0 and then propagate returned SERVFAIL (but some retry logic remains).
	//
	//  Theoretically it might be best to use both CD=0 and CD=1, with either of them
	//  in some kind of DNSSEC fallback, but I see bad complexity/improvement ratio.
	if (is_iter) {
		knot_wire_set_cd(pkt->wire);
	} else {
		if (knot_wire_get_cd(request->qsource.packet->wire) || !qry->flags.DNSSEC_WANT)
			knot_wire_set_cd(pkt->wire);
	}

	return kr_ok();
}

int kr_resolver_init(module_array_t *modules, knot_mm_t *pool)
{
	the_resolver = &the_resolver_value;

	/* Default options (request flags). */
	the_resolver->options.REORDER_RR = true;
	the_resolver->vld_limit_crypto = KR_VLD_LIMIT_CRYPTO_DEFAULT;

	/* Open resolution context */
	the_resolver->trust_anchors = trie_create(NULL);
	the_resolver->negative_anchors = trie_create(NULL);
	the_resolver->pool = pool;
	the_resolver->modules = modules;
	the_resolver->cache_rtt_tout_retry_interval = KR_NS_TIMEOUT_RETRY_INTERVAL;
	/* Create OPT RR */
	the_resolver->downstream_opt_rr = mm_alloc(pool, sizeof(knot_rrset_t));
	the_resolver->upstream_opt_rr = mm_alloc(pool, sizeof(knot_rrset_t));
	if (!the_resolver->downstream_opt_rr || !the_resolver->upstream_opt_rr) {
		return kr_error(ENOMEM);
	}
	knot_edns_init(the_resolver->downstream_opt_rr, KR_EDNS_PAYLOAD, 0, KR_EDNS_VERSION, pool);
	knot_edns_init(the_resolver->upstream_opt_rr, KR_EDNS_PAYLOAD, 0, KR_EDNS_VERSION, pool);
	/* Use default TLS padding */
	the_resolver->tls_padding = -1;
	/* Empty init; filled via ./lua/postconfig.lua */
	kr_zonecut_init(&the_resolver->root_hints, (const uint8_t *)"", pool);
	lru_create(&the_resolver->cache_cookie, LRU_COOKIES_SIZE, NULL, NULL);

	return kr_ok();
}

void kr_resolver_deinit(void)
{
	kr_zonecut_deinit(&the_resolver->root_hints);
	kr_cache_close(&the_resolver->cache);

	/* The LRUs are currently malloc-ated and need to be freed. */
	lru_free(the_resolver->cache_cookie);

	kr_ta_clear(the_resolver->trust_anchors);
	trie_free(the_resolver->trust_anchors);
	kr_ta_clear(the_resolver->negative_anchors);
	trie_free(the_resolver->negative_anchors);

	the_resolver = NULL;
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
	if (request->options.NO_ANSWER) {
		kr_assert(request->state & KR_STATE_FAIL);
		return NULL;
	}
	if (request->answer)
		return request->answer;

	const knot_pkt_t *qs_pkt = request->qsource.packet;
	if (kr_fails_assert(qs_pkt))
		goto fail;
	// Find answer_max: limit on DNS wire length.
	uint16_t answer_max;
	const struct kr_request_qsource_flags *qs_flags = &request->qsource.flags;
	const struct kr_request_qsource_flags *qs_cflags = &request->qsource.comm_flags;
	if (kr_fails_assert(!(qs_flags->tls || qs_cflags->tls) || qs_flags->tcp || qs_cflags->http))
		goto fail;
	if (!request->qsource.addr || qs_flags->tcp || qs_cflags->tcp) {
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
	if (kr_now() - qry->creation_time_mono >= KR_RESOLVE_TIME_LIMIT) {
		kr_query_inform_timeout(request, qry);
		return KR_STATE_FAIL;
	}
	bool tried_tcp = (qry->flags.TCP);
	if (!packet || packet->size == 0)
		return KR_STATE_PRODUCE;

	/* Packet cleared, derandomize QNAME. */
	knot_dname_t *qname_raw = kr_pkt_qname_raw(packet);
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

	if (transport && !qry->flags.CACHED) {
		if (!(request->state & KR_STATE_FAIL)) {
			/* Do not complete NS address resolution on soft-fail. */
			if (kr_fails_assert(packet->wire))
				return KR_STATE_FAIL;
			const int rcode = knot_wire_get_rcode(packet->wire);
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

				/* Construct EDE message.  We need it on mempool. */
				char cut_buf[KR_DNAME_STR_MAXLEN];
				char *msg = knot_dname_to_str(cut_buf, qry->zone_cut.name, sizeof(cut_buf));
				if (!kr_fails_assert(msg)) {
					if (*qry->zone_cut.name != '\0') /* Strip trailing dot. */
						cut_buf[strlen(cut_buf) - 1] = '\0';
					msg = kr_strcatdup_pool(&request->pool, 2,
							"OLX2: delegation ", cut_buf);
				}
				kr_request_set_extended_error(request, KNOT_EDNS_EDE_NREACH_AUTH, msg);
				return KR_STATE_FAIL;
			}
		} else {
			request->count_fail_row = 0;
		}
	}

	/* Pop query if resolved. */
	if (request->state == KR_STATE_YIELD) { // NOLINT(bugprone-branch-clone)
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
		if (qry->flags.FORWARD || qry->flags.STUB
				/* Probably CPU exhaustion attempt, so do not retry. */
				|| qry->vld_limit_crypto_remains <= 0) {
			return KR_STATE_FAIL;
		}
		/* Other servers might not have broken DNSSEC. */
		qry->flags.DNSSEC_BOGUS = false;
		return KR_STATE_PRODUCE;
	}

	return kr_rplan_empty(&request->rplan) ? KR_STATE_DONE : KR_STATE_PRODUCE;
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
	knot_dname_t *qname_raw = kr_pkt_qname_raw(packet);
	if (qry->secret != old_minimization_secret) {
		randomized_qname_case(qname_raw, qry->secret);
	}

	/* Write down OPT unless in safemode */
	if (!(qry->flags.NO_EDNS)) {
		/* TLS padding */
		if (transport->protocol == KR_TRANSPORT_TLS) {
			size_t padding_size = edns_padding_option_size(request->ctx->tls_padding);
			ret = knot_pkt_reserve(packet, padding_size);
			if (ret)
				return kr_error(EINVAL);
			ret = pkt_padding(packet, request->ctx->tls_padding);
			if (ret)
				return kr_error(EINVAL);
		}

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
			default:; // Do nothing
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
	case KNOT_EDNS_EDE_TOO_EARLY:
		return 910;
	case KNOT_EDNS_EDE_DNSKEY_BIT:
	case KNOT_EDNS_EDE_DNSKEY_MISS:
	case KNOT_EDNS_EDE_SIG_EXPIRED:
	case KNOT_EDNS_EDE_SIG_NOTYET:
	case KNOT_EDNS_EDE_RRSIG_MISS:
	case KNOT_EDNS_EDE_NSEC_MISS:
	case KNOT_EDNS_EDE_EXPIRED_INV:
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
	case KNOT_EDNS_EDE_NSEC3_ITERS:
		return 500;  /* Non-critical DNSSEC issues */
	case KNOT_EDNS_EDE_STALE:
	case KNOT_EDNS_EDE_STALE_NXD:
		return 300;  /* Serve-stale answers. */
	case KNOT_EDNS_EDE_INDETERMINATE:
	case KNOT_EDNS_EDE_CACHED_ERR:
	case KNOT_EDNS_EDE_NOT_READY:
	case KNOT_EDNS_EDE_NOTAUTH:
	case KNOT_EDNS_EDE_NOTSUP:
	case KNOT_EDNS_EDE_NREACH_AUTH:
	case KNOT_EDNS_EDE_NETWORK:
	case KNOT_EDNS_EDE_INV_DATA:
	case KNOT_EDNS_EDE_SYNTHESIZED:
		return 200;  /* Assorted codes */
	case KNOT_EDNS_EDE_OTHER:
		return 100;  /* Most generic catch-all error */
	case KNOT_EDNS_EDE_NONE:
	case KNOT_EDNS_EDE_NONCONF_POLICY:  /* Defined by an expired Internet Draft */
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

	if (ede_priority(info_code) > ede_priority(ede->info_code)) {
		ede->info_code = info_code;
		ede->extra_text = extra_text;
	}

	return ede->info_code;
}

#undef VERBOSE_MSG
