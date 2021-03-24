/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/cache/impl.h"

#include "lib/dnssec/ta.h"
#include "lib/layer/iterate.h"

/* The whole file only exports peek_nosync().
 * Forwards for larger chunks of code: */

static int found_exact_hit(kr_layer_t *ctx, knot_pkt_t *pkt, knot_db_val_t val,
			   uint8_t lowest_rank);
static int closest_NS(struct kr_cache *cache, struct key *k, entry_list_t el,
			struct kr_query *qry, bool only_NS, bool is_DS);
static int answer_simple_hit(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl);
static int answer_dname_hit(kr_layer_t *ctx, knot_pkt_t *pkt, const knot_dname_t *dname_owner,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl);
static int try_wild(struct key *k, struct answer *ans, const knot_dname_t *clencl_name,
		    uint16_t type, uint8_t lowest_rank,
		    const struct kr_query *qry, struct kr_cache *cache);

static int peek_encloser(
	struct key *k, struct answer *ans, int sname_labels,
	uint8_t lowest_rank, const struct kr_query *qry, struct kr_cache *cache);


static int nsec_p_init(struct nsec_p *nsec_p, knot_db_val_t nsec_p_entry, bool with_knot)
{
	const size_t stamp_len = sizeof(uint32_t);
	if (nsec_p_entry.len <= stamp_len) { /* plain NSEC if equal */
		nsec_p->raw = NULL;
		nsec_p->hash = 0;
		return kr_ok();
	}
	nsec_p->raw = (uint8_t *)nsec_p_entry.data + stamp_len;
	nsec_p->hash = nsec_p_mkHash(nsec_p->raw);
	if (!with_knot) return kr_ok();
	/* Convert NSEC3 params to another format. */
	const dnssec_binary_t rdata = {
		.size = nsec_p_rdlen(nsec_p->raw),
		.data = (uint8_t *)/*const-cast*/nsec_p->raw,
	};
	int ret = dnssec_nsec3_params_from_rdata(&nsec_p->libknot, &rdata);
	return ret == DNSSEC_EOK ? kr_ok() : kr_error(ret);
}

static void nsec_p_cleanup(struct nsec_p *nsec_p)
{
	dnssec_binary_free(&nsec_p->libknot.salt);
	/* We don't really need to clear it, but it's not large. (`salt` zeroed above) */
	memset(nsec_p, 0, sizeof(*nsec_p));
}

/** Compute new TTL for nsec_p entry, using SOA serial arith.
 * \param new_ttl (optionally) write the new TTL (even if negative)
 * \return error code, e.g. kr_error(ESTALE) */
static int nsec_p_ttl(knot_db_val_t entry, const uint32_t timestamp, int32_t *new_ttl)
{
	if (!kr_assume(entry.data))
		return kr_error(EINVAL);
	uint32_t stamp;
	if (!entry.len)
		return kr_error(ENOENT);
	if (!kr_assume(entry.len >= sizeof(stamp)))
		return kr_error(EILSEQ);
	memcpy(&stamp, entry.data, sizeof(stamp));
	int32_t newttl = stamp - timestamp;
	if (new_ttl) *new_ttl = newttl;
	return newttl < 0 ? kr_error(ESTALE) : kr_ok();
}

static uint8_t get_lowest_rank(const struct kr_query *qry, const knot_dname_t *name, const uint16_t type)
{
	/* Shut up linters. */
	if (unlikely(!qry || !qry->request)) abort();
	/* TODO: move rank handling into the iterator (DNSSEC_* flags)? */
	const bool allow_unverified =
		knot_wire_get_cd(qry->request->qsource.packet->wire) || qry->flags.STUB;
		/* in stub mode we don't trust RRs anyway ^^ */
	if (qry->flags.NONAUTH) {
		return KR_RANK_INITIAL;
		/* Note: there's little sense in validation status for non-auth records.
		 * In case of using NONAUTH to get NS IPs, knowing that you ask correct
		 * IP doesn't matter much for security; it matters whether you can
		 * validate the answers from the NS.
		 */
	} else if (!allow_unverified) {
		/* Records not present under any TA don't have their security
		 * verified at all, so we also accept low ranks in that case. */
		const bool ta_covers = kr_ta_closest(qry->request->ctx, name, type);
		/* ^ TODO: performance?  TODO: stype - call sites */
		if (ta_covers) {
			return KR_RANK_INSECURE | KR_RANK_AUTH;
		} /* else falltrhough */
	}
	return KR_RANK_INITIAL | KR_RANK_AUTH;
}


/** Almost whole .produce phase for the cache module.
 * \note we don't transition to KR_STATE_FAIL even in case of "unexpected errors".
 */
int peek_nosync(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	struct key k_storage, *k = &k_storage;
	int ret = kr_dname_lf(k->buf, qry->sname, false);
	if (!kr_assume(ret == 0))
		return ctx->state;

	const uint8_t lowest_rank = get_lowest_rank(qry, qry->sname, qry->stype);

	/**** 1. find the name or the closest (available) zone, not considering wildcards
	 **** 1a. exact name+type match (can be negative, mainly in insecure zones) */
	{
		knot_db_val_t key = key_exact_type_maypkt(k, qry->stype);
		knot_db_val_t val = { NULL, 0 };
		ret = cache_op(cache, read, &key, &val, 1);
		if (!ret) {
			/* found an entry: test conditions, materialize into pkt, etc. */
			ret = found_exact_hit(ctx, pkt, val, lowest_rank);
		}
	}
	if (!ret) {
		return KR_STATE_DONE;
	} else if (!kr_assume(ret == kr_error(ENOENT))) {
		VERBOSE_MSG(qry, "=> exact hit error: %d %s\n", ret, kr_strerror(ret));
		return ctx->state;
	}

	/**** 1b. otherwise, find the longest prefix zone/xNAME (with OK time+rank). [...] */
	k->zname = qry->sname;
	ret = kr_dname_lf(k->buf, k->zname, false); /* LATER(optim.): probably remove */
	if (!kr_assume(ret == 0))
		return ctx->state;
	entry_list_t el;
	ret = closest_NS(cache, k, el, qry, false, qry->stype == KNOT_RRTYPE_DS);
	if (ret) {
		if (!kr_assume(ret == kr_error(ENOENT)) || !el[0].len) {
			return ctx->state;
		}
	}
	switch (k->type) {
	case KNOT_RRTYPE_CNAME: {
		const knot_db_val_t v = el[EL_CNAME];
		if (!kr_assume(v.data && v.len))
			return ctx->state;
		const int32_t new_ttl = get_new_ttl(v.data, qry, qry->sname,
						KNOT_RRTYPE_CNAME, qry->timestamp.tv_sec);
		ret = answer_simple_hit(ctx, pkt, KNOT_RRTYPE_CNAME, v.data,
					knot_db_val_bound(v), new_ttl);
		return ret == kr_ok() ? KR_STATE_DONE : ctx->state;
		}
	case KNOT_RRTYPE_DNAME: {
		const knot_db_val_t v = el[EL_DNAME];
		if (!kr_assume(v.data && v.len))
			return ctx->state;
		/* TTL: for simplicity, we just ask for TTL of the generated CNAME. */
		const int32_t new_ttl = get_new_ttl(v.data, qry, qry->sname,
						KNOT_RRTYPE_CNAME, qry->timestamp.tv_sec);
		ret = answer_dname_hit(ctx, pkt, k->zname, v.data,
					knot_db_val_bound(v), new_ttl);
		return ret == kr_ok() ? KR_STATE_DONE : ctx->state;
		}
	}

	/* We have to try proving from NSEC*. */
	auto_free char *log_zname = NULL;
	WITH_VERBOSE(qry) {
		log_zname = kr_dname_text(k->zname);
		if (!el[0].len) {
			VERBOSE_MSG(qry, "=> no NSEC* cached for zone: %s\n", log_zname);
		}
	}

#if 0
	if (!eh) { /* fall back to root hints? */
		ret = kr_zonecut_set_sbelt(req->ctx, &qry->zone_cut);
		if (ret) return ctx->state;
		(void)!kr_assume(!qry->zone_cut.parent);

		//VERBOSE_MSG(qry, "=> using root hints\n");
		//qry->flags.AWAIT_CUT = false;
		return ctx->state;
	}

	/* Now `eh` points to the closest NS record that we've found,
	 * and that's the only place to start - we may either find
	 * a negative proof or we may query upstream from that point. */
	kr_zonecut_set(&qry->zone_cut, k->zname);
	ret = kr_make_query(qry, pkt); // TODO: probably not yet - qname minimization
	if (ret) return ctx->state;
#endif

	/** Structure for collecting multiple NSEC* + RRSIG records,
	 * in preparation for the answer, and for tracking the progress. */
	struct answer ans;
	memset(&ans, 0, sizeof(ans));
	ans.mm = &pkt->mm;
	const int sname_labels = knot_dname_labels(qry->sname, NULL);

	/* Try the NSEC* parameters in order, until success.
	 * Let's not mix different parameters for NSEC* RRs in a single proof. */
	for (int i = 0; ;) {
		int32_t log_new_ttl = -123456789; /* visually recognizable value */
		ret = nsec_p_ttl(el[i], qry->timestamp.tv_sec, &log_new_ttl);
		if (!ret || VERBOSE_STATUS) {
			nsec_p_init(&ans.nsec_p, el[i], !ret);
		}
		if (ret) {
			VERBOSE_MSG(qry, "=> skipping zone: %s, %s, hash %x;"
				"new TTL %d, ret %d\n",
				log_zname, (ans.nsec_p.raw ? "NSEC3" : "NSEC"),
				(unsigned)ans.nsec_p.hash, (int)log_new_ttl, ret);
			/* no need for nsec_p_cleanup() in this case */
			goto cont;
		}
		VERBOSE_MSG(qry, "=> trying zone: %s, %s, hash %x\n",
				log_zname, (ans.nsec_p.raw ? "NSEC3" : "NSEC"),
				(unsigned)ans.nsec_p.hash);
		/**** 2. and 3. inside */
		ret = peek_encloser(k, &ans, sname_labels,
					lowest_rank, qry, cache);
		nsec_p_cleanup(&ans.nsec_p);
		if (!ret) break;
		if (ret < 0) return ctx->state;
	cont:
		/* Otherwise we try another nsec_p, if available. */
		if (++i == ENTRY_APEX_NSECS_CNT) return ctx->state;
		/* clear possible partial answers in `ans` (no need to deallocate) */
		ans.rcode = 0;
		memset(&ans.rrsets, 0, sizeof(ans.rrsets));
	}

	/**** 4. add SOA iff needed */
	if (ans.rcode != PKT_NOERROR) {
		/* Assuming k->buf still starts with zone's prefix,
		 * look up the SOA in cache. */
		k->buf[0] = k->zlf_len;
		knot_db_val_t key = key_exact_type(k, KNOT_RRTYPE_SOA);
		knot_db_val_t val = { NULL, 0 };
		ret = cache_op(cache, read, &key, &val, 1);
		const struct entry_h *eh;
		if (ret || !(eh = entry_h_consistent_E(val, KNOT_RRTYPE_SOA))) {
			(void)!kr_assume(ret); /* only want to catch `eh` failures */
			VERBOSE_MSG(qry, "=> SOA missed\n");
			return ctx->state;
		}
		/* Check if the record is OK. */
		int32_t new_ttl = get_new_ttl(eh, qry, k->zname, KNOT_RRTYPE_SOA,
						qry->timestamp.tv_sec);
		if (new_ttl < 0 || eh->rank < lowest_rank || eh->is_packet) {
			VERBOSE_MSG(qry, "=> SOA unfit %s: rank 0%.2o, new TTL %d\n",
					(eh->is_packet ? "packet" : "RR"),
					eh->rank, new_ttl);
			return ctx->state;
		}
		/* Add the SOA into the answer. */
		ret = entry2answer(&ans, AR_SOA, eh, knot_db_val_bound(val),
				   k->zname, KNOT_RRTYPE_SOA, new_ttl);
		if (ret) return ctx->state;
	}

	/* Find our target RCODE. */
	int real_rcode;
	switch (ans.rcode) {
	case PKT_NODATA:
	case PKT_NOERROR: /* positive wildcarded response */
		real_rcode = KNOT_RCODE_NOERROR;
		break;
	case PKT_NXDOMAIN:
		real_rcode = KNOT_RCODE_NXDOMAIN;
		break;
	default:
		(void)!kr_assume(false);
	case 0: /* i.e. nothing was found */
		/* LATER(optim.): zone cut? */
		VERBOSE_MSG(qry, "=> cache miss\n");
		return ctx->state;
	}

	if (pkt_renew(pkt, qry->sname, qry->stype)
	    || knot_pkt_begin(pkt, KNOT_ANSWER)
	   ) {
		(void)!kr_assume(false);
		return ctx->state;
	}
	knot_wire_set_rcode(pkt->wire, real_rcode);

	bool expiring = false; // TODO
	for (int i = 0; i < sizeof(ans.rrsets) / sizeof(ans.rrsets[0]); ++i) {
		if (i == 1) knot_pkt_begin(pkt, KNOT_AUTHORITY);
		if (!ans.rrsets[i].set.rr) continue;
		expiring = expiring || ans.rrsets[i].set.expiring;
		ret = pkt_append(pkt, &ans.rrsets[i], ans.rrsets[i].set.rank);
		if (!kr_assume(ret == 0))
			return ctx->state;
	}

	/* Finishing touches. */
	struct kr_qflags * const qf = &qry->flags;
	qf->EXPIRING = expiring;
	qf->CACHED = true;
	qf->NO_MINIMIZE = true;

	return KR_STATE_DONE;
}

/**
 * This is where the high-level "business logic" of aggressive cache is.
 * \return 0: success (may need SOA);  >0: try other nsec_p;  <0: exit cache immediately.
 */
static int peek_encloser(
	struct key *k, struct answer *ans, const int sname_labels,
	uint8_t lowest_rank, const struct kr_query *qry, struct kr_cache *cache)
{
	/** Start of NSEC* covering the sname;
	 * it's part of key - the one within zone (read only) */
	knot_db_val_t cover_low_kwz = { NULL, 0 };
	knot_dname_t cover_hi_storage[KNOT_DNAME_MAXLEN];
	/** End of NSEC* covering the sname. */
	knot_db_val_t cover_hi_kwz = {
		.data = cover_hi_storage,
		.len = sizeof(cover_hi_storage),
	};

	/**** 2. Find a closest (provable) encloser (of sname). */
	int clencl_labels = -1;
	bool clencl_is_tentative = false;
	if (!ans->nsec_p.raw) { /* NSEC */
		int ret = nsec1_encloser(k, ans, sname_labels, &clencl_labels,
					 &cover_low_kwz, &cover_hi_kwz, qry, cache);
		if (ret) return ret;
	} else {
		int ret = nsec3_encloser(k, ans, sname_labels, &clencl_labels,
					 qry, cache);
		clencl_is_tentative = ret == ABS(ENOENT) && clencl_labels >= 0;
		/* ^^ Last chance: *positive* wildcard record under this clencl. */
		if (ret && !clencl_is_tentative) return ret;
	}

	/* We should have either a match or a cover at this point. */
	if (!kr_assume(ans->rcode == PKT_NODATA || ans->rcode == PKT_NXDOMAIN))
		return kr_error(EINVAL);
	const bool ncloser_covered = ans->rcode == PKT_NXDOMAIN;

	/** Name of the closest (provable) encloser. */
	const knot_dname_t *clencl_name = qry->sname;
	for (int l = sname_labels; l > clencl_labels; --l)
		clencl_name = knot_wire_next_label(clencl_name, NULL);

	/**** 3. source of synthesis checks, in case the next closer name was covered.
	 **** 3a. We want to query for NSEC* of source of synthesis (SS) or its
	 * predecessor, providing us with a proof of its existence or non-existence. */
	if (ncloser_covered && !ans->nsec_p.raw) {
		int ret = nsec1_src_synth(k, ans, clencl_name,
					  cover_low_kwz, cover_hi_kwz, qry, cache);
		if (ret == AR_SOA) return 0;
		(void)!kr_assume(ret <= 0);
		if (ret) return ret;

	} else if (ncloser_covered && ans->nsec_p.raw && !clencl_is_tentative) {
		int ret = nsec3_src_synth(k, ans, clencl_name, qry, cache);
		if (ret == AR_SOA) return 0;
		(void)!kr_assume(ret <= 0);
		if (ret) return ret;

	} /* else (!ncloser_covered) so no wildcard checks needed,
	   * as we proved that sname exists. */

	/**** 3b. find wildcarded answer, if next closer name was covered
	 * and we don't have a full proof yet.  (common for NSEC*) */
	if (!ncloser_covered)
		return kr_ok(); /* decrease indentation */
	/* Construct key for exact qry->stype + source of synthesis. */
	int ret = kr_dname_lf(k->buf, clencl_name, true);
	if (!kr_assume(ret == 0))
		return kr_error(ret);
	const uint16_t types[] = { qry->stype, KNOT_RRTYPE_CNAME };
	for (int i = 0; i < (2 - (qry->stype == KNOT_RRTYPE_CNAME)); ++i) {
		ret = try_wild(k, ans, clencl_name, types[i],
				lowest_rank, qry, cache);
		if (ret == kr_ok()) {
			return kr_ok();
		} else if (!kr_assume(ret == kr_error(ENOENT) || ret == kr_error(ESTALE))) {
			return kr_error(ret);
		}
		/* else continue */
	}
	/* Neither attempt succeeded, but the NSEC* proofs were found,
	 * so skip trying other parameters, as it seems very unlikely
	 * to turn out differently than by the same wildcard search. */
	return kr_error(ENOENT);
}

static void answer_simple_qflags(struct kr_qflags *qf, const struct entry_h *eh,
				 uint32_t new_ttl)
{
	/* Finishing touches. */
	qf->EXPIRING = is_expiring(eh->ttl, new_ttl);
	qf->CACHED = true;
	qf->NO_MINIMIZE = true;
	qf->DNSSEC_INSECURE = kr_rank_test(eh->rank, KR_RANK_INSECURE);
	if (qf->DNSSEC_INSECURE) {
		qf->DNSSEC_WANT = false;
	}
}

#define CHECK_RET(ret) do { \
	if (!kr_assume((ret) >= 0)) return kr_error((ret)); \
} while (false)

static int answer_simple_hit(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	/* All OK, so start constructing the (pseudo-)packet. */
	int ret = pkt_renew(pkt, qry->sname, qry->stype);
	CHECK_RET(ret);

	/* Materialize the sets for the answer in (pseudo-)packet. */
	struct answer ans;
	memset(&ans, 0, sizeof(ans));
	ans.mm = &pkt->mm;
	ret = entry2answer(&ans, AR_ANSWER, eh, eh_bound,
			   qry->sname, type, new_ttl);
	CHECK_RET(ret);
	/* Put links to the materialized data into the pkt. */
	ret = pkt_append(pkt, &ans.rrsets[AR_ANSWER], eh->rank);
	CHECK_RET(ret);

	answer_simple_qflags(&qry->flags, eh, new_ttl);

	VERBOSE_MSG(qry, "=> satisfied by exact %s: rank 0%.2o, new TTL %d\n",
			(type == KNOT_RRTYPE_CNAME ? "CNAME" : "RRset"),
			eh->rank, new_ttl);
	return kr_ok();
}

static int answer_dname_hit(kr_layer_t *ctx, knot_pkt_t *pkt, const knot_dname_t *dname_owner,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	/* All OK, so start constructing the (pseudo-)packet. */
	int ret = pkt_renew(pkt, qry->sname, qry->stype);
	CHECK_RET(ret);

	/* Materialize the DNAME for the answer in (pseudo-)packet. */
	struct answer ans;
	memset(&ans, 0, sizeof(ans));
	ans.mm = &pkt->mm;
	ret = entry2answer(&ans, AR_ANSWER, eh, eh_bound,
			   dname_owner, KNOT_RRTYPE_DNAME, new_ttl);
	CHECK_RET(ret);
	/* Put link to the RRset into the pkt. */
	ret = pkt_append(pkt, &ans.rrsets[AR_ANSWER], eh->rank);
	CHECK_RET(ret);
	const knot_dname_t *dname_target =
		knot_dname_target(ans.rrsets[AR_ANSWER].set.rr->rrs.rdata);

	/* Generate CNAME RRset for the answer in (pseudo-)packet. */
	const int AR_CNAME = AR_SOA;
	knot_rrset_t *rr = ans.rrsets[AR_CNAME].set.rr
		= knot_rrset_new(qry->sname, KNOT_RRTYPE_CNAME, KNOT_CLASS_IN,
				 new_ttl, ans.mm);
	CHECK_RET(rr ? kr_ok() : -ENOMEM);
	const knot_dname_t *cname_target = knot_dname_replace_suffix(qry->sname,
			knot_dname_labels(dname_owner, NULL), dname_target, ans.mm);
	CHECK_RET(cname_target ? kr_ok() : -ENOMEM);
	const int rdata_len = knot_dname_size(cname_target);

	if (rdata_len <= KNOT_DNAME_MAXLEN
	    && knot_dname_labels(cname_target, NULL) <= KNOT_DNAME_MAXLABELS) {
		/* Normal case: the target name fits. */
		rr->rrs.count = 1;
		rr->rrs.size = knot_rdata_size(rdata_len);
		rr->rrs.rdata = mm_alloc(ans.mm, rr->rrs.size);
		CHECK_RET(rr->rrs.rdata ? kr_ok() : -ENOMEM);
		knot_rdata_init(rr->rrs.rdata, rdata_len, cname_target);
		/* Put link to the RRset into the pkt. */
		ret = pkt_append(pkt, &ans.rrsets[AR_CNAME], eh->rank);
		CHECK_RET(ret);
	} else {
		/* Note that it's basically a successful answer; name just doesn't fit. */
		knot_wire_set_rcode(pkt->wire, KNOT_RCODE_YXDOMAIN);
	}

	answer_simple_qflags(&qry->flags, eh, new_ttl);
	VERBOSE_MSG(qry, "=> satisfied by DNAME+CNAME: rank 0%.2o, new TTL %d\n",
			eh->rank, new_ttl);
	return kr_ok();
}

#undef CHECK_RET

/** TODO: description; see the single call site for now. */
static int found_exact_hit(kr_layer_t *ctx, knot_pkt_t *pkt, knot_db_val_t val,
			   uint8_t lowest_rank)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	int ret = entry_h_seek(&val, qry->stype);
	if (ret) return ret;
	const struct entry_h *eh = entry_h_consistent_E(val, qry->stype);
	if (!kr_assume(eh))
		return kr_error(ENOENT);
		// LATER: recovery in case of error, perhaps via removing the entry?
		// LATER(optim): pehaps optimize the zone cut search

	int32_t new_ttl = get_new_ttl(eh, qry, qry->sname, qry->stype,
					qry->timestamp.tv_sec);
	if (new_ttl < 0 || eh->rank < lowest_rank) {
		/* Positive record with stale TTL or bad rank.
		 * LATER(optim.): It's unlikely that we find a negative one,
		 * so we might theoretically skip all the cache code. */

		VERBOSE_MSG(qry, "=> skipping exact %s: rank 0%.2o (min. 0%.2o), new TTL %d\n",
				eh->is_packet ? "packet" : "RR", eh->rank, lowest_rank, new_ttl);
		return kr_error(ENOENT);
	}

	const uint8_t *eh_bound = knot_db_val_bound(val);
	if (eh->is_packet) {
		/* Note: we answer here immediately, even if it's (theoretically)
		 * possible that we could generate a higher-security negative proof.
		 * Rank is high-enough so we take it to save time searching;
		 * in practice this also helps in some incorrect zones (live-signed). */
		return answer_from_pkt  (ctx, pkt, qry->stype, eh, eh_bound, new_ttl);
	} else {
		return answer_simple_hit(ctx, pkt, qry->stype, eh, eh_bound, new_ttl);
	}
}


/** Try to satisfy via wildcard (positively).  See the single call site. */
static int try_wild(struct key *k, struct answer *ans, const knot_dname_t *clencl_name,
		    const uint16_t type, const uint8_t lowest_rank,
		    const struct kr_query *qry, struct kr_cache *cache)
{
	knot_db_val_t key = key_exact_type(k, type);
	/* Find the record. */
	knot_db_val_t val = { NULL, 0 };
	int ret = cache_op(cache, read, &key, &val, 1);
	if (!ret) {
		ret = entry_h_seek(&val, type);
	}
	if (ret) {
		if (!kr_assume(ret == kr_error(ENOENT)))
			VERBOSE_MSG(qry, "=> wildcard: hit error %d %s\n",
					ret, strerror(abs(ret)));
		WITH_VERBOSE(qry) {
			auto_free char *clencl_str = kr_dname_text(clencl_name),
				*type_str = kr_rrtype_text(type);
			VERBOSE_MSG(qry, "=> wildcard: not found: *.%s %s\n",
					clencl_str, type_str);
		}
		return ret;
	}
	/* Check if the record is OK. */
	const struct entry_h *eh = entry_h_consistent_E(val, type);
	if (!kr_assume(eh))
		return kr_error(ret);
		// LATER: recovery in case of error, perhaps via removing the entry?
	int32_t new_ttl = get_new_ttl(eh, qry, qry->sname, type, qry->timestamp.tv_sec);
		/* ^^ here we use the *expanded* wildcard name */
	if (new_ttl < 0 || eh->rank < lowest_rank || eh->is_packet) {
		/* Wildcard record with stale TTL, bad rank or packet.  */
		VERBOSE_MSG(qry, "=> wildcard: skipping %s, rank 0%.2o, new TTL %d\n",
				eh->is_packet ? "packet" : "RR", eh->rank, new_ttl);
		return kr_error(ESTALE);
	}
	/* Add the RR into the answer. */
	ret = entry2answer(ans, AR_ANSWER, eh, knot_db_val_bound(val),
			   qry->sname, type, new_ttl);
	VERBOSE_MSG(qry, "=> wildcard: answer expanded, ret = %d, new TTL %d\n",
			ret, (int)new_ttl);
	if (ret) return kr_error(ret);
	ans->rcode = PKT_NOERROR;
	return kr_ok();
}

int kr_cache_closest_apex(struct kr_cache *cache, const knot_dname_t *name, bool is_DS,
			  knot_dname_t ** apex)
{
	if (!kr_assume(cache && cache->db && name && apex && *apex == NULL))
		return kr_error(EINVAL);
	struct key k_storage, *k = &k_storage;
	int ret = kr_dname_lf(k->buf, name, false);
	if (ret)
		return kr_error(ret);
	entry_list_t el_;
	k->zname = name;
	ret = closest_NS(cache, k, el_, NULL, true, is_DS);
	if (ret && ret != -abs(ENOENT))
		return ret;
	*apex = knot_dname_copy(k->zname, NULL);
	if (!*apex)
		return kr_error(ENOMEM);
	return kr_ok();
}

/** \internal for closest_NS.  Check suitability of a single entry, setting k->type if OK.
 * \return error code, negative iff whole list should be skipped.
 */
static int check_NS_entry(struct key *k, knot_db_val_t entry, int i,
			  bool exact_match, bool is_DS,
			  const struct kr_query *qry, uint32_t timestamp);

/**
 * Find the longest prefix zone/xNAME (with OK time+rank), starting at k->*.
 *
 * The found type is returned via k->type; the values are returned in el.
 * \note we use k->type = KNOT_RRTYPE_NS also for the nsec_p result.
 * \param qry can be NULL (-> gettimeofday(), but you lose the stale-serve hook)
 * \param only_NS don't consider xNAMEs
 * \return error code
 */
static int closest_NS(struct kr_cache *cache, struct key *k, entry_list_t el,
			struct kr_query *qry, const bool only_NS, const bool is_DS)
{
	/* get the current timestamp */
	uint32_t timestamp;
	if (qry) {
		timestamp = qry->timestamp.tv_sec;
	} else {
		struct timeval tv;
		if (gettimeofday(&tv, NULL)) return kr_error(errno);
		timestamp = tv.tv_sec;
	}

	int zlf_len = k->buf[0];

	// LATER(optim): if stype is NS, we check the same value again
	bool exact_match = true;
	bool need_zero = true;
	/* Inspect the NS/xNAME entries, shortening by a label on each iteration. */
	do {
		k->buf[0] = zlf_len;
		knot_db_val_t key = key_exact_type(k, KNOT_RRTYPE_NS);
		knot_db_val_t val;
		int ret = cache_op(cache, read, &key, &val, 1);
		if (ret == kr_error(ENOENT)) goto next_label;
		if (!kr_assume(ret == 0)) {
			if (need_zero) memset(el, 0, sizeof(entry_list_t));
			return kr_error(ret);
		}

		/* Check consistency, find any type;
		 * using `goto` for shortening by another label. */
		ret = entry_list_parse(val, el);
		if (!kr_assume(ret == 0)) // do something about it?
			goto next_label;
		need_zero = false;
		/* More types are possible; try in order.
		 * For non-fatal failures just "continue;" to try the next type. */
		/* Now a complication - we need to try EL_DNAME before NSEC*
		 * (Unfortunately that's not easy to write very nicely.) */
		if (!only_NS) {
			const int i = EL_DNAME;
			ret = check_NS_entry(k, el[i], i, exact_match, is_DS,
						qry, timestamp);
			if (ret < 0) goto next_label; else
			if (!ret) {
				/* We found our match. */
				k->zlf_len = zlf_len;
				return kr_ok();
			}
		}
		const int el_count = only_NS ? EL_NS + 1 : EL_LENGTH;
		for (int i = 0; i < el_count; ++i) {
			if (i == EL_DNAME) continue;
			ret = check_NS_entry(k, el[i], i, exact_match, is_DS,
						qry, timestamp);
			if (ret < 0) goto next_label; else
			if (!ret) {
				/* We found our match. */
				k->zlf_len = zlf_len;
				return kr_ok();
			}
		}

	next_label:
		/* remove one more label */
		exact_match = false;
		if (k->zname[0] == 0) {
			/* We miss root NS in cache, but let's at least assume it exists. */
			k->type = KNOT_RRTYPE_NS;
			k->zlf_len = zlf_len;
			(void)!kr_assume(zlf_len == 0);
			if (need_zero) memset(el, 0, sizeof(entry_list_t));
			return kr_error(ENOENT);
		}
		zlf_len -= (k->zname[0] + 1);
		k->zname += (k->zname[0] + 1);
		k->buf[zlf_len + 1] = 0;
	} while (true);
}

static int check_NS_entry(struct key *k, const knot_db_val_t entry, const int i,
			  const bool exact_match, const bool is_DS,
			  const struct kr_query *qry, uint32_t timestamp)
{
	const int ESKIP = ABS(ENOENT);
	if (!entry.len
		/* On a zone cut we want DS from the parent zone. */
		|| (exact_match && is_DS)
		/* CNAME is interesting only if we
		 * directly hit the name that was asked.
		 * Note that we want it even in the DS case. */
		|| (i == EL_CNAME && !exact_match)
		/* DNAME is interesting only if we did NOT
		 * directly hit the name that was asked. */
		|| (i == EL_DNAME && exact_match)
	   ) {
		return ESKIP;
	}

	uint16_t type;
	if (i < ENTRY_APEX_NSECS_CNT) {
		type = KNOT_RRTYPE_NS;
		int32_t log_new_ttl = -123456789; /* visually recognizable value */
		const int err = nsec_p_ttl(entry, timestamp, &log_new_ttl);
		if (err) {
			VERBOSE_MSG(qry,
				"=> skipping unfit nsec_p: new TTL %d, error %d\n",
				(int)log_new_ttl, err);
			return ESKIP;
		}
	} else {
		type = EL2RRTYPE(i);
		/* Find the entry for the type, check positivity, TTL */
		const struct entry_h *eh = entry_h_consistent_E(entry, type);
		if (!kr_assume(eh)) {
			VERBOSE_MSG(qry, "=> EH not consistent\n");
			return kr_error(EILSEQ);
		}
		const int32_t log_new_ttl = get_new_ttl(eh, qry, k->zname, type, timestamp);

		const bool ok = /* Not interested in negative bogus or outdated RRs. */
			!eh->is_packet && log_new_ttl >= 0
			/* For NS any kr_rank is accepted, as insecure or even nonauth is OK */
			&& (type == KNOT_RRTYPE_NS
			    || eh->rank >= get_lowest_rank(qry, k->zname, type));

		WITH_VERBOSE(qry) { if (!ok) {
			auto_free char *type_str = kr_rrtype_text(type);
			const char *packet_str = eh->is_packet ? "packet" : "RR";
			VERBOSE_MSG(qry,
				"=> skipping unfit %s %s: rank 0%.2o, new TTL %d\n",
				type_str, packet_str, eh->rank, (int)log_new_ttl);
		} }
		if (!ok) return ESKIP;
	}
	k->type = type;
	return kr_ok();
}

