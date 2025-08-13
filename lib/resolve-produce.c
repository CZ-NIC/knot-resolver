/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
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
#include "lib/resolve.h"
#include "lib/layer.h"
#include "lib/rplan.h"
#include "lib/layer/iterate.h"
#include "lib/dnssec/ta.h"
#include "lib/dnssec.h"

#include "lib/resolve-impl.h"

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

void randomized_qname_case(knot_dname_t * restrict qname, uint32_t secret)
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

/** This turns off QNAME minimisation if there is a non-terminal between current zone cut, and name target.
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
		target = knot_dname_next_label(target);
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
		target = knot_dname_next_label(target);
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
	trie_t *trust_anchors = request->ctx->trust_anchors;
	trie_t *negative_anchors = request->ctx->negative_anchors;

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
			wanted_name = knot_dname_next_label(wanted_name);
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
	trie_t *trust_anchors = request->ctx->trust_anchors;
	trie_t *negative_anchors = request->ctx->negative_anchors;

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

/// Check current zone cut status and credibility, spawn subrequests if needed.
/// \return KR_STATE_FAIL, KR_STATE_DONE, kr_ok()
/// TODO: careful review might be nice
static int zone_cut_check(struct kr_request *request, struct kr_query *qry, knot_pkt_t *packet)
{
	// Set up nameserver+cut if overridden by policy.
	int ret = kr_rule_data_src_check(qry, packet);
	if (ret) return KR_STATE_FAIL;

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
		ret = kr_zonecut_set_sbelt(request->ctx, &qry->zone_cut);
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
			requested_name = knot_dname_next_label(parent);
		}
	} else if ((qry->stype == KNOT_RRTYPE_DS) && (requested_name[0] != '\0')) {
		/* If this is explicit DS query, start from encloser too. */
		requested_name = knot_dname_next_label(requested_name);
	}

	int state = KR_STATE_FAIL;
	do {
		state = ns_fetch_cut(qry, requested_name, request, packet);
		if (state == KR_STATE_DONE || (state & KR_STATE_FAIL)) {
			return state;
		} else if (state == KR_STATE_CONSUME) {
			kr_require(requested_name[0] != '\0');
			requested_name = knot_dname_next_label(requested_name);
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
	kr_require(request && transport && packet);
	struct kr_rplan *rplan = &request->rplan;

	/* No query left for resolution */
	if (kr_rplan_empty(rplan)) {
		return KR_STATE_FAIL;
	}

	struct kr_query *qry = array_tail(rplan->pending);

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
		if (qry->flags.ALWAYS_CUT) { // LATER: maybe the flag doesn't work well anymore
			switch(zone_cut_check(request, qry, packet)) {
			case KR_STATE_FAIL: return KR_STATE_FAIL;
			case KR_STATE_DONE: return KR_STATE_PRODUCE;
			default: break;
			}
		}
		/* Resolve current query and produce dependent or finish */
		request->state = KR_STATE_PRODUCE;
		ITERATE_LAYERS(request, qry, produce, packet);
		if (!(request->state & KR_STATE_FAIL) && knot_wire_get_qr(packet->wire)) {
			/* Produced an answer from cache, consume it. */
			kr_server_selection_cached(qry);
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
	/* At this point we need to send a query upstream to proceed towards success. */

	/* This query has RD=0 or is ANY, stop here. */
	if (qry->stype == KNOT_RRTYPE_ANY ||
	    !knot_wire_get_rd(request->qsource.packet->wire)) {
		VERBOSE_MSG(qry, "=> qtype is ANY or RD=0, bail out\n");
		return KR_STATE_FAIL;
	}

	/* Update zone cut, spawn new subrequests. */
	int state = zone_cut_check(request, qry, packet);
	switch(state) {
	case KR_STATE_FAIL: return KR_STATE_FAIL;
	case KR_STATE_DONE: return KR_STATE_PRODUCE;
	default: break;
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

			/* Construct EDE message.  We need it on mempool. */
			char cut_buf[KR_DNAME_STR_MAXLEN];
			char *msg = knot_dname_to_str(cut_buf, qry->zone_cut.name, sizeof(cut_buf));
			if (!kr_fails_assert(msg)) {
				if (*qry->zone_cut.name != '\0') /* Strip trailing dot. */
					cut_buf[strlen(cut_buf) - 1] = '\0';
				msg = kr_strcatdup_pool(&request->pool, 2,
						"P3CD: delegation ", cut_buf);
			}
			kr_request_set_extended_error(request, KNOT_EDNS_EDE_NREACH_AUTH, msg);

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
	knot_dname_t *qname_raw = kr_pkt_qname_raw(packet);
	randomized_qname_case(qname_raw, qry->secret);

	/*
	 * Additional query is going to be finalized when calling
	 * kr_resolve_checkout().
	 */
	qry->timestamp_mono = kr_now();
	return request->state;
}

