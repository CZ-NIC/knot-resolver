/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "lib/cache/impl.h"

#include "lib/dnssec/ta.h"
#include "lib/layer/iterate.h"

/* The whole file only exports peek_nosync().
 * Forwards for larger chunks of code: */

static int found_exact_hit(kr_layer_t *ctx, knot_pkt_t *pkt, knot_db_val_t val,
			   uint8_t lowest_rank);
static int closest_NS(kr_layer_t *ctx, struct key *k, entry_list_t el);
static int answer_simple_hit(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl);
static int try_wild(struct key *k, struct answer *ans, const knot_dname_t *clencl_name,
		    uint16_t type, uint8_t lowest_rank,
		    const struct kr_query *qry, struct kr_cache *cache);

static int peek_encloser(
	struct key *k, struct answer *ans, int sname_labels,
	uint8_t lowest_rank, const struct kr_query *qry, struct kr_cache *cache);


static int nsec_p_init(struct nsec_p *nsec_p, const uint8_t *nsec_p_raw)
{
	nsec_p->raw = nsec_p_raw;
	if (!nsec_p_raw) return kr_ok();
	nsec_p->hash = nsec_p_mkHash(nsec_p->raw);
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

static uint8_t get_lowest_rank(const struct kr_request *req, const struct kr_query *qry)
{
	/* TODO: move rank handling into the iterator (DNSSEC_* flags)? */
	const bool allow_unverified =
		knot_wire_get_cd(req->answer->wire) || qry->flags.STUB;
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
		const bool ta_covers = kr_ta_covers_qry(req->ctx, qry->sname, qry->stype);
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
	if (unlikely(ret)) {
		assert(false);
		return ctx->state;
	}

	const uint8_t lowest_rank = get_lowest_rank(req, qry);

	/**** 1. find the name or the closest (available) zone, not considering wildcards
	 **** 1a. exact name+type match (can be negative answer in insecure zones) */
	knot_db_val_t key = key_exact_type_maypkt(k, qry->stype);
	knot_db_val_t val = { NULL, 0 };
	ret = cache_op(cache, read, &key, &val, 1);
	if (!ret) {
		VERBOSE_MSG(qry, "=> read OK\n");
		/* found an entry: test conditions, materialize into pkt, etc. */
		ret = found_exact_hit(ctx, pkt, val, lowest_rank);
	}
	if (ret && ret != -abs(ENOENT)) {
		VERBOSE_MSG(qry, "=> exact hit error: %d %s\n", ret, kr_strerror(ret));
		assert(false);
		return ctx->state;
	} else if (!ret) {
		return KR_STATE_DONE;
	}

	/**** 1b. otherwise, find the longest prefix zone/xNAME (with OK time+rank). [...] */
	k->zname = qry->sname;
	ret = kr_dname_lf(k->buf, k->zname, false); /* LATER(optim.): probably remove */
	if (unlikely(ret)) {
		assert(false);
		return ctx->state;
	}
	entry_list_t el;
	ret = closest_NS(ctx, k, el);
	if (ret) {
		assert(ret == kr_error(ENOENT));
		if (ret != kr_error(ENOENT) || !el[0].len) {
			return ctx->state;
		}
	}
	switch (k->type) {
	case KNOT_RRTYPE_CNAME: {
		const knot_db_val_t v = el[EL_CNAME];
		assert(v.data && v.len);
		const int32_t new_ttl = get_new_ttl(v.data, qry, qry->sname,
						KNOT_RRTYPE_CNAME, qry->timestamp.tv_sec);
		ret = answer_simple_hit(ctx, pkt, KNOT_RRTYPE_CNAME, v.data,
					knot_db_val_bound(v), new_ttl);
		/* TODO: ^^ cumbersome code; we also recompute the TTL */
		return ret == kr_ok() ? KR_STATE_DONE : ctx->state;
		}
	case KNOT_RRTYPE_DNAME:
		VERBOSE_MSG(qry, "=> DNAME not supported yet\n"); // LATER
		return ctx->state;
	}

	/* We have to try proving from NSEC*. */
	WITH_VERBOSE(qry) {
		auto_free char *zname_str = kr_dname_text(k->zname);
		if (!el[0].len) {
			VERBOSE_MSG(qry, "=> no NSEC* cached for zone: %s\n", zname_str);
		} else {
			VERBOSE_MSG(qry, "=> trying zone: %s (first %s)\n", zname_str,
					(el[0].len == 4 ? "NSEC" : "NSEC3"));
		}
	}

#if 0
	if (!eh) { /* fall back to root hints? */
		ret = kr_zonecut_set_sbelt(req->ctx, &qry->zone_cut);
		if (ret) return ctx->state;
		assert(!qry->zone_cut.parent);

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
		if (!el[i].len) goto cont;
		/* OK iff the stamp is in future */
		uint32_t stamp;
		memcpy(&stamp, el[i].data, sizeof(stamp));
		const int32_t remains = stamp - qry->timestamp.tv_sec; /* using SOA serial arith. */
		if (remains < 0) goto cont;
		{
			const uint8_t *nsec_p_raw = el[i].len > sizeof(stamp)
					? (uint8_t *)el[i].data + sizeof(stamp) : NULL;
			nsec_p_init(&ans.nsec_p, nsec_p_raw);
		}
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
		key = key_exact_type(k, KNOT_RRTYPE_SOA);
		knot_db_val_t val = { NULL, 0 };
		ret = cache_op(cache, read, &key, &val, 1);
		const struct entry_h *eh;
		if (ret || !(eh = entry_h_consistent(val, KNOT_RRTYPE_SOA))) {
			assert(ret); /* only want to catch `eh` failures */
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
		assert(false);
	case 0: /* i.e. nothing was found */
		/* LATER(optim.): zone cut? */
		VERBOSE_MSG(qry, "=> cache miss\n");
		return ctx->state;
	}

	if (pkt_renew(pkt, qry->sname, qry->stype)
	    || knot_pkt_begin(pkt, KNOT_ANSWER)
	   ) {
		assert(false);
		return ctx->state;
	}
	knot_wire_set_rcode(pkt->wire, real_rcode);

	bool expiring = false; // TODO
	VERBOSE_MSG(qry, "=> writing RRsets: ");
	for (int i = 0; i < sizeof(ans.rrsets) / sizeof(ans.rrsets[0]); ++i) {
		if (i == 1) knot_pkt_begin(pkt, KNOT_AUTHORITY);
		if (!ans.rrsets[i].set.rr) continue;
		expiring = expiring || ans.rrsets[i].set.expiring;
		ret = pkt_append(pkt, &ans.rrsets[i], ans.rrsets[i].set.rank);
		if (ret) {
			assert(false);
			return ctx->state;
		}
		kr_log_verbose(kr_rank_test(ans.rrsets[i].set.rank, KR_RANK_SECURE)
				? "+" : "-");
	}
	kr_log_verbose("\n");
	/* Finishing touches. */
	qry->flags.EXPIRING = expiring;
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;

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
	if (ans->rcode != PKT_NODATA && ans->rcode != PKT_NXDOMAIN) {
		assert(false);
		return kr_error(EINVAL);
	}
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
		assert(ret <= 0);
		if (ret) return ret;

	} else if (ncloser_covered && ans->nsec_p.raw && !clencl_is_tentative) {
		int ret = nsec3_src_synth(k, ans, clencl_name, qry, cache);
		if (ret == AR_SOA) return 0;
		assert(ret <= 0);
		if (ret) return ret;

	} /* else (!ncloser_covered) so no wildcard checks needed,
	   * as we proved that sname exists. */

	/**** 3b. find wildcarded answer, if next closer name was covered
	 * and we don't have a full proof yet.  (common for NSEC*) */
	if (!ncloser_covered)
		return kr_ok(); /* decrease indentation */
	/* Construct key for exact qry->stype + source of synthesis. */
	int ret = kr_dname_lf(k->buf, clencl_name, true);
	if (ret) {
		assert(!ret);
		return kr_error(ret);
	}
	const uint16_t types[] = { qry->stype, KNOT_RRTYPE_CNAME };
	for (int i = 0; i < (2 - (qry->stype == KNOT_RRTYPE_CNAME)); ++i) {
		ret = try_wild(k, ans, clencl_name, types[i],
				lowest_rank, qry, cache);
		if (ret == kr_ok()) {
			return kr_ok();
		} else if (ret != -ABS(ENOENT) && ret != -ABS(ESTALE)) {
			assert(false);
			return kr_error(ret);
		}
		/* else continue */
	}
	/* Neither attempt succeeded, but the NSEC* proofs were found,
	 * so skip trying other parameters, as it seems very unlikely
	 * to turn out differently than by the same wildcard search. */
	return -ABS(ENOENT);
}


static int answer_simple_hit(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl)
#define CHECK_RET(ret) do { \
	if ((ret) < 0) { assert(false); return kr_error((ret)); } \
} while (false)
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
	/* Finishing touches. */
	qry->flags.EXPIRING = is_expiring(eh->ttl, new_ttl);
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;
	qry->flags.DNSSEC_INSECURE = kr_rank_test(eh->rank, KR_RANK_INSECURE);
	if (qry->flags.DNSSEC_INSECURE) {
		qry->flags.DNSSEC_WANT = false;
	}
	VERBOSE_MSG(qry, "=> satisfied by exact %s: rank 0%.2o, new TTL %d\n",
			(type == KNOT_RRTYPE_CNAME ? "CNAME" : "RRset"),
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
	VERBOSE_MSG(qry, "=> FEH seek OK \n");
	const struct entry_h *eh = entry_h_consistent(val, qry->stype);
	if (!eh) {
		assert(false);
		return kr_error(ENOENT);
		// LATER: recovery in case of error, perhaps via removing the entry?
		// LATER(optim): pehaps optimize the zone cut search
	}
	VERBOSE_MSG(qry, "=> FEH consistent OK \n");

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
		 * Rank is high-enough so we take it to save time searching. */
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
		if (ret != -ABS(ENOENT)) {
			VERBOSE_MSG(qry, "=> wildcard: hit error %d %s\n",
					ret, strerror(abs(ret)));
			assert(false);
		}
		WITH_VERBOSE(qry) {
			auto_free char *clencl_str = kr_dname_text(clencl_name),
				*type_str = kr_rrtype_text(type);
			VERBOSE_MSG(qry, "=> wildcard: not found: *.%s %s\n",
					clencl_str, type_str);
		}
		return ret;
	}
	/* Check if the record is OK. */
	const struct entry_h *eh = entry_h_consistent(val, type);
	if (!eh) {
		assert(false);
		return kr_error(ret);
		// LATER: recovery in case of error, perhaps via removing the entry?
	}
	int32_t new_ttl = get_new_ttl(eh, qry, qry->sname, type, qry->timestamp.tv_sec);
		/* ^^ here we use the *expanded* wildcard name */
	if (new_ttl < 0 || eh->rank < lowest_rank || eh->is_packet) {
		/* Wildcard record with stale TTL, bad rank or packet.  */
		VERBOSE_MSG(qry, "=> wildcard: skipping %s, rank 0%.2o, new TTL %d\n",
				eh->is_packet ? "packet" : "RR", eh->rank, new_ttl);
		return -ABS(ESTALE);
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

/** Find the longest prefix zone/xNAME (with OK time+rank), starting at k->*.
 * We store xNAME at NS type to lower the number of searches.
 * CNAME is only considered for equal name, of course.
 * We also store NSEC* parameters at NS type; probably the latest two will be kept.
 * Found type is returned via k->type.
 *
 * \return raw entry from cache (for NS) or rewound entry (xNAME) FIXME
 */
static int closest_NS(kr_layer_t *ctx, struct key *k, entry_list_t el)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	int zlf_len = k->buf[0];

	uint8_t rank_min = KR_RANK_INSECURE | KR_RANK_AUTH;
	// LATER(optim): if stype is NS, we check the same value again
	bool exact_match = true;
	bool need_zero = true;
	/* Inspect the NS/xNAME entries, shortening by a label on each iteration. */
	do {
		k->buf[0] = zlf_len;
		knot_db_val_t key = key_exact_type(k, KNOT_RRTYPE_NS);
		knot_db_val_t val;
		int ret = cache_op(cache, read, &key, &val, 1);
		if (ret == -abs(ENOENT)) goto next_label;
		if (ret) {
			assert(!ret);
			if (need_zero) memset(el, 0, sizeof(entry_list_t));
			return kr_error(ret);
		}

		/* Check consistency, find any type;
		 * using `goto` for shortening by another label. */
		ret = entry_list_parse(val, el);
		if (ret) {
			assert(!ret); // do something about it?
			goto next_label;
		}
		need_zero = false;
		/* More types are possible; try in order.
		 * For non-fatal failures just "continue;" to try the next type. */
		for (int i = ENTRY_APEX_NSECS_CNT; i < EL_LENGTH; ++i) {
			if (!el[i].len
				/* On a zone cut we want DS from the parent zone. */
				|| (i == EL_NS && exact_match && qry->stype == KNOT_RRTYPE_DS)
				/* CNAME is interesting only if we
				 * directly hit the name that was asked.
				 * Note that we want it even in the DS case. */
				|| (i == EL_CNAME && !exact_match)
				/* DNAME is interesting only if we did NOT
				 * directly hit the name that was asked. */
				|| (i == EL_DNAME && exact_match)
			   ) {
				continue;
			}
				/* ^^ LATER(optim.): not having NS but having
				 * non-timeouted nsec_p is also OK for a zone cut. */
			/* Find the entry for the type, check positivity, TTL */
			const uint16_t type = EL2RRTYPE(i);
			const struct entry_h *eh = entry_h_consistent(el[i], type);
			if (!eh) {
				VERBOSE_MSG(qry, "=> EH seek ret: %d\n", ret);
				assert(false);
				goto next_label;
			}
			int32_t new_ttl = get_new_ttl(eh, qry, k->zname, type,
							qry->timestamp.tv_sec);
			if (new_ttl < 0
			    /* Not interested in negative or bogus. */
			    || eh->is_packet
			    /* For NS any kr_rank is accepted,
			     * as insecure or even nonauth is OK */
			    || (type != KNOT_RRTYPE_NS && eh->rank < rank_min)) {

				WITH_VERBOSE(qry) {
					auto_free char *type_str =
						kr_rrtype_text(type);
					const char *packet_str =
						eh->is_packet ? "packet" : "RR";
					VERBOSE_MSG(qry, "=> skipping unfit %s %s: "
						"rank 0%.2o, new TTL %d\n",
						type_str, packet_str,
						eh->rank, new_ttl);
				}
				continue;
			}
			/* We found our match. */
			k->type = type;
			k->zlf_len = zlf_len;
			return kr_ok();
		}

	next_label:
		/* remove one more label */
		exact_match = false;
		if (k->zname[0] == 0) {
			/* We miss root NS in cache, but let's at least assume it exists. */
			k->type = KNOT_RRTYPE_NS;
			k->zlf_len = zlf_len;
			assert(zlf_len == 0);
			if (need_zero) memset(el, 0, sizeof(entry_list_t));
			return kr_error(ENOENT);
		}
		zlf_len -= (k->zname[0] + 1);
		k->zname += (k->zname[0] + 1);
		k->buf[zlf_len + 1] = 0;
	} while (true);
}

