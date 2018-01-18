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

#include <assert.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <libknot/errcode.h>
#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/rrtype/rrsig.h>

#include "contrib/ucw/lib.h"
#include "contrib/cleanup.h"
#include "lib/cache.h"
#include "lib/cdb_lmdb.h"
#include "lib/defines.h"
#include "lib/utils.h"

#include "lib/dnssec/ta.h"
#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"

#include "lib/cache/impl.h"


/** Cache version */
static const uint16_t CACHE_VERSION = 2;
/** Key size */
#define KEY_HSIZE (sizeof(uint8_t) + sizeof(uint16_t))
#define KEY_SIZE (KEY_HSIZE + KNOT_DNAME_MAXLEN)


/** @internal Removes all records from cache. */
static inline int cache_clear(struct kr_cache *cache)
{
	cache->stats.delete += 1;
	return cache_op(cache, clear);
}

/** @internal Set time when clearing cache. */
static void reset_timestamps(struct kr_cache *cache)
{
	cache->last_clear_monotime = kr_now();
	gettimeofday(&cache->last_clear_walltime, NULL);
}

/** @internal Open cache db transaction and check internal data version. */
static int assert_right_version(struct kr_cache *cache)
{
	/* Check cache ABI version */
	uint8_t key_str[] = "\x00\x00V"; /* CACHE_KEY_DEF; zero-term. but we don't care */
	knot_db_val_t key = { .data = key_str, .len = sizeof(key_str) };
	knot_db_val_t val = { NULL, 0 };
	int ret = cache_op(cache, read, &key, &val, 1);
	if (ret == 0 && val.len == sizeof(CACHE_VERSION)
	    && memcmp(val.data, &CACHE_VERSION, sizeof(CACHE_VERSION)) == 0) {
		ret = kr_error(EEXIST);
	} else {
		int oldret = ret;
		/* Version doesn't match. Recreate cache and write version key. */
		ret = cache_op(cache, count);
		if (ret != 0) { /* Non-empty cache, purge it. */
			kr_log_info("[     ][cach] incompatible cache database detected, purging\n");
			if (oldret) {
				kr_log_verbose("bad ret: %d\n", oldret);
			} else if (val.len != sizeof(CACHE_VERSION)) {
				kr_log_verbose("bad length: %d\n", (int)val.len);
			} else {
				uint16_t ver;
				memcpy(&ver, val.data, sizeof(ver));
				kr_log_verbose("bad version: %d\n", (int)ver);
			}
			ret = cache_clear(cache);
		}
		/* Either purged or empty. */
		if (ret == 0) {
			/* Key/Val is invalidated by cache purge, recreate it */
			val.data = /*const-cast*/(void *)&CACHE_VERSION;
			val.len = sizeof(CACHE_VERSION);
			ret = cache_op(cache, write, &key, &val, 1);
		}
	}
	kr_cache_sync(cache);
	return ret;
}

int kr_cache_open(struct kr_cache *cache, const struct kr_cdb_api *api, struct kr_cdb_opts *opts, knot_mm_t *mm)
{
	if (!cache) {
		return kr_error(EINVAL);
	}
	/* Open cache */
	if (!api) {
		api = kr_cdb_lmdb();
	}
	cache->api = api;
	int ret = cache->api->open(&cache->db, opts, mm);
	if (ret != 0) {
		return ret;
	}
	memset(&cache->stats, 0, sizeof(cache->stats));
	cache->ttl_min = KR_CACHE_DEFAULT_TTL_MIN;
	cache->ttl_max = KR_CACHE_DEFAULT_TTL_MAX;
	/* Check cache ABI version */
	reset_timestamps(cache);
	(void) assert_right_version(cache);
	return 0;
}


#define cache_isvalid(cache) ((cache) && (cache)->api && (cache)->db)

void kr_cache_close(struct kr_cache *cache)
{
	if (cache_isvalid(cache)) {
		cache_op(cache, close);
		cache->db = NULL;
	}
}

int kr_cache_sync(struct kr_cache *cache)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}
	if (cache->api->sync) {
		return cache_op(cache, sync);
	}
	return kr_ok();
}

int kr_cache_clear(struct kr_cache *cache)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}
	int ret = cache_clear(cache);
	if (ret == 0) {
		reset_timestamps(cache);
		ret = assert_right_version(cache);
	}
	return ret;
}



struct nsec_p {
	struct {
		uint8_t salt_len;
		uint8_t alg;
		uint16_t iters;
	} s;
	uint8_t *salt;
};

/* When going stricter, BEWARE of breaking entry_h_consistent_NSEC() */
struct entry_h * entry_h_consistent(knot_db_val_t data, uint16_t type)
{
	(void) type; /* unused, for now */
	/* Length checks. */
	if (data.len < offsetof(struct entry_h, data))
		return NULL;
	const struct entry_h *eh = data.data;
	if (eh->is_packet) {
		uint16_t pkt_len;
		if (data.len < offsetof(struct entry_h, data) + sizeof(pkt_len)) {
			return NULL;
		}
		memcpy(&pkt_len, eh->data, sizeof(pkt_len));
		if (data.len < offsetof(struct entry_h, data) + sizeof(pkt_len)
				+ pkt_len) {
			return NULL;
		}
	}

	bool ok = true;
	ok = ok && (!kr_rank_test(eh->rank, KR_RANK_BOGUS)
		    || eh->is_packet);
	ok = ok && (eh->is_packet || !eh->has_optout);

	/* doesn't hold, because of temporary NSEC3 packet caching
	if (eh->is_packet)
		ok = ok && !kr_rank_test(eh->rank, KR_RANK_SECURE);
	*/

	//LATER: rank sanity
	return ok ? /*const-cast*/(struct entry_h *)eh : NULL;
}


int32_t get_new_ttl(const struct entry_h *entry, const struct kr_query *qry,
		    const knot_dname_t *owner, uint16_t type)
{
	int32_t diff = qry->timestamp.tv_sec - entry->time;
	if (diff < 0) {
		/* We may have obtained the record *after* the request started. */
		diff = 0;
	}
	int32_t res = entry->ttl - diff;
	if (res < 0 && owner && false/*qry->flags.SERVE_STALE*/) {
		/* Stale-serving decision.  FIXME: modularize or make configurable, etc. */
		if (res + 3600 * 24 > 0) {
			VERBOSE_MSG(qry, "stale TTL accepted: %d -> 1\n", (int)res);
			return 1;
		}
	}
	return res;
}
int32_t kr_cache_ttl(const struct kr_cache_p *peek, const struct kr_query *qry,
		     const knot_dname_t *name, uint16_t type)
{
	const struct entry_h *eh = peek->raw_data;
	return get_new_ttl(eh, qry, name, type);
}






/** Check that no label contains a zero character.
 *
 * We refuse to work with those, as LF and our cache keys might become ambiguous.
 * Assuming uncompressed name, as usual.
 * CACHE_KEY_DEF
 */
static bool check_dname_for_lf(const knot_dname_t *n)
{
	return knot_dname_size(n) == strlen((const char *)n) + 1;
}

/** Like key_exact_type() but omits a couple checks not holding for pkt cache. */
knot_db_val_t key_exact_type_maypkt(struct key *k, uint16_t type)
{
	assert(!knot_rrtype_is_metatype(type));
	switch (type) {
	case KNOT_RRTYPE_RRSIG: /* no RRSIG query caching, at least for now */
		assert(false);
		return (knot_db_val_t){ NULL, 0 };
	/* xNAME lumped into NS. */
	case KNOT_RRTYPE_CNAME:
	case KNOT_RRTYPE_DNAME:
		type = KNOT_RRTYPE_NS;
	default:
		break;
	}

	int name_len = k->buf[0];
	k->buf[name_len + 1] = 0; /* make sure different names can never match */
	k->buf[name_len + 2] = 'E'; /* tag for exact name+type matches */
	memcpy(k->buf + name_len + 3, &type, 2);
	k->type = type;
	/* CACHE_KEY_DEF: key == dname_lf + '\0' + 'E' + RRTYPE */
	return (knot_db_val_t){ k->buf + 1, name_len + 4 };
}

/** Like key_exact_type_maypkt but with extra checks if used for RRs only. */
static knot_db_val_t key_exact_type(struct key *k, uint16_t type)
{
	switch (type) {
	/* Sanity check: forbidden types represented in other way(s). */
	case KNOT_RRTYPE_NSEC:
	case KNOT_RRTYPE_NSEC3:
		assert(false);
		return (knot_db_val_t){ NULL, 0 };
	}
	return key_exact_type_maypkt(k, type);
}



/* Forwards for larger chunks of code.  All just for cache_peek. */
static uint8_t get_lowest_rank(const struct kr_request *req, const struct kr_query *qry);
static int found_exact_hit(kr_layer_t *ctx, knot_pkt_t *pkt, knot_db_val_t val,
			   uint8_t lowest_rank);
static knot_db_val_t closest_NS(kr_layer_t *ctx, struct key *k);
static int answer_simple_hit(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl);
static int cache_peek_real(kr_layer_t *ctx, knot_pkt_t *pkt);

/** function for .produce phase */
int cache_peek(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	if (ctx->state & (KR_STATE_FAIL|KR_STATE_DONE) || qry->flags.NO_CACHE
	    || qry->stype == KNOT_RRTYPE_RRSIG /* LATER: some other behavior for this STYPE? */
	    || qry->sclass != KNOT_CLASS_IN) {
		return ctx->state; /* Already resolved/failed or already tried, etc. */
	}
	int ret = cache_peek_real(ctx, pkt);
	kr_cache_sync(&req->ctx->cache);
	return ret;
}

/**
 * \note we don't transition to KR_STATE_FAIL even in case of "unexpected errors".
 */
static int cache_peek_real(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	/* ATM cache only peeks for qry->sname and that would be useless
	 * to repeat on every iteration, so disable it from now on.
	 * LATER(optim.): assist with more precise QNAME minimization. */
	qry->flags.NO_CACHE = true;

	struct key k_storage, *k = &k_storage;
	if (!check_dname_for_lf(qry->sname)) {
		WITH_VERBOSE {
			VERBOSE_MSG(qry, "=> skipping zero-containing name ");
			kr_dname_print(qry->sname, "", "\n");
		}
		return ctx->state;
	}
	int ret = kr_dname_lf(k->buf, qry->sname, false);
	if (ret) {
		return ctx->state;
	}

	const uint8_t lowest_rank = get_lowest_rank(req, qry);

	/** 1. find the name or the closest (available) zone, not considering wildcards
	 *  1a. exact name+type match (can be negative answer in insecure zones)
	 */
	knot_db_val_t key = key_exact_type_maypkt(k, qry->stype);
	knot_db_val_t val = { NULL, 0 };
	ret = cache_op(cache, read, &key, &val, 1);
	if (!ret) {
		/* found an entry: test conditions, materialize into pkt, etc. */
		ret = found_exact_hit(ctx, pkt, val, lowest_rank);
	}
	if (ret && ret != -abs(ENOENT)) {
		VERBOSE_MSG(qry, "=> exact hit error: %d %s\n",
				ret, strerror(abs(ret)));
		assert(false);
		return ctx->state;
	} else if (!ret) {
		return KR_STATE_DONE;
	}

	/** 1b. otherwise, find the longest prefix NS/xNAME (with OK time+rank). [...] */
	k->zname = qry->sname;
	if (qry->stype == KNOT_RRTYPE_DS) { /* DS is parent-side. */
		k->zname = knot_wire_next_label(k->zname, NULL);
		if (!k->zname) {
			return ctx->state; /* can't go above root */
		}
	}
	kr_dname_lf(k->buf, k->zname, false); /* LATER(optim.): probably remove */
	const knot_db_val_t val_cut = closest_NS(ctx, k);
	if (!val_cut.data) {
		VERBOSE_MSG(qry, "=> not even root NS in cache\n");
		return ctx->state; /* nothing to do without any NS at all */
	}
	switch (k->type) {
	case KNOT_RRTYPE_NS:
		WITH_VERBOSE {
			VERBOSE_MSG(qry, "=> trying zone: ");
			kr_dname_print(k->zname, "", "\n");
		}
		break;
	case KNOT_RRTYPE_CNAME: {
		const uint32_t new_ttl = get_new_ttl(val_cut.data, qry,
						     qry->sname, KNOT_RRTYPE_CNAME);
		ret = answer_simple_hit(ctx, pkt, KNOT_RRTYPE_CNAME, val_cut.data,
					val_cut.data + val_cut.len, new_ttl);
		/* TODO: ^^ cumbersome code; we also recompute the TTL */
		return ret == kr_ok() ? KR_STATE_DONE : ctx->state;
		}

	case KNOT_RRTYPE_DNAME:
		VERBOSE_MSG(qry, "=> DNAME not supported yet\n"); // LATER
		return ctx->state;
	default:
		assert(false);
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

	/* Note: up to here we can run on any cache backend,
	 * without touching the code. */
	if (!eh->nsec1_pos) {
		/* No NSEC1 RRs for this zone in cache. */
		/* TODO: NSEC3 */
		//VERBOSE_MSG(qry, "   no NSEC1\n");
		//return ctx->state;
	}
#endif

	/* collecting multiple NSEC* + RRSIG records, in preparation for the answer
	 *  + track the progress
	 */
	struct answer ans;
	memset(&ans, 0, sizeof(ans));
	ans.mm = &pkt->mm;

	/** Start of NSEC* covering the sname;
	 * it's part of key - the one within zone (read only) */
	knot_db_val_t cover_low_kwz = { NULL, 0 };
	knot_dname_t cover_hi_storage[KNOT_DNAME_MAXLEN];
	/** End of NSEC* covering the sname. */
	knot_db_val_t cover_hi_kwz = {
		.data = cover_hi_storage,
		.len = sizeof(cover_hi_storage),
	};

	/** 2. Find a closest (provable) encloser (of sname).
	 * iterate over all NSEC* chain parameters
	 */
	int clencl_labels = -1;
	const int sname_labels = knot_dname_labels(qry->sname, NULL);
	//while (true) { //for (int i_nsecp = 0; i
	// TODO(NSEC3): better signalling when to "continue;" and when to "break;"
	// incl. clearing partial answers in `ans`
		//assert(eh->nsec1_pos <= 1);
		int nsec = 1;
		switch (nsec) {
		case 1:
			ans.nsec_v = 1;
			ret = nsec1_encloser(k, &ans, sname_labels, &clencl_labels,
					     &cover_low_kwz, &cover_hi_kwz, qry, cache);
			if (ret < 0) return ctx->state;
			//if (ret > 0) continue; // NSEC3
			break;
		case 3: //TODO NSEC3
		default:
			assert(false);
		}
	//}

	if (!ans.rcode) {
		/* Nothing suitable found. */
		return ctx->state;
	}

	/* Name of the closest (provable) encloser. */
	const knot_dname_t *clencl_name = qry->sname;
	for (int l = sname_labels; l > clencl_labels; --l)
		clencl_name = knot_wire_next_label(clencl_name, NULL);

	/** 3. source of synthesis checks, in case sname was covered.
	 *
	 * 3a. We want to query for NSEC* of source of synthesis (SS) or its predecessor,
	 * providing us with a proof of its existence or non-existence.
	 */
	if (ans.rcode == PKT_NODATA) {
		/* No wildcard checks needed, as we proved that sname exists. */
		assert(ans.nsec_v == 1); // for now

	} else if (ans.nsec_v == 1 && ans.rcode == PKT_NXDOMAIN) {
		int ret = nsec1_src_synth(k, &ans, clencl_name,
					  cover_low_kwz, cover_hi_kwz, qry, cache);
		if (ret < 0) return ctx->state;
		if (ret == AR_SOA) goto do_soa;
		assert(ret == 0);

	} else {
		//TODO NSEC3
		assert(false);
	}


	/** 3b. We need to find wildcarded answer, if SS wasn't covered.
	 * (common for NSEC*)
	 */
	if (ans.rcode == PKT_NOERROR) {
		/* Construct key for exact qry->stype + source of synthesis. */
		int ret = kr_dname_lf(k->buf, clencl_name, true);
		if (ret) {
			assert(!ret);
			return ctx->state;
		}
		knot_db_val_t key = key_exact_type(k, qry->stype);
		/* Find the record. */
		knot_db_val_t val = { NULL, 0 };
		ret = cache_op(cache, read, &key, &val, 1);
		if (!ret) {
			ret = entry_h_seek(&val, qry->stype);
		}
		if (ret) {
			if (ret != -abs(ENOENT)) {
				VERBOSE_MSG(qry, "=> wildcard: hit error %d %s\n",
						ret, strerror(abs(ret)));
				assert(false);
			}
			WITH_VERBOSE {
				VERBOSE_MSG(qry, "=> wildcard: not found: ");
				kr_dname_print(clencl_name, "*.", "\n");
			}
			return ctx->state;
		}
		/* Check if the record is OK. */
		const struct entry_h *eh = entry_h_consistent(val, qry->stype);
		if (!eh) {
			assert(false);
			return ctx->state;
			// LATER: recovery in case of error, perhaps via removing the entry?
		}
		int32_t new_ttl = get_new_ttl(eh, qry, qry->sname, qry->stype);
			/* ^^ here we use the *expanded* wildcard name */
		if (new_ttl < 0 || eh->rank < lowest_rank || eh->is_packet) {
			/* Wildcard record with stale TTL, bad rank or packet.  */
			VERBOSE_MSG(qry, "=> wildcard: skipping %s, rank 0%0.2o, new TTL %d\n",
					eh->is_packet ? "packet" : "RR", eh->rank, new_ttl);
			return ctx->state;
		}
		/* Add the RR into the answer. */
		const void *eh_bound = val.data + val.len;
		ret = entry2answer(&ans, AR_ANSWER, eh, eh_bound,
				   qry->sname, qry->stype, new_ttl);
		if (ret) return ctx->state;
	}


	/** 4. add SOA iff needed
	 */
do_soa:
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
		int32_t new_ttl = get_new_ttl(eh, qry, k->zname, KNOT_RRTYPE_SOA);
		if (new_ttl < 0 || eh->rank < lowest_rank || eh->is_packet) {
			VERBOSE_MSG(qry, "=> SOA unfit %s: ",
					eh->is_packet ? "packet" : "RR");
			kr_log_verbose("rank 0%0.2o, new TTL %d\n",
					eh->rank, new_ttl);
			return ctx->state;
		}
		/* Add the SOA into the answer. */
		void *eh_data_bound = val.data + val.len;
		ret = entry2answer(&ans, AR_SOA, eh, eh_data_bound,
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


/** It's simply inside of cycle taken out to decrease indentation.  \return error code. */
static int stash_rrset(const ranked_rr_array_t *arr, int arr_i,
			const struct kr_query *qry, struct kr_cache *cache);

int cache_stash(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	const uint16_t pkt_type = knot_pkt_qtype(pkt);
	const bool type_bad = knot_rrtype_is_metatype(pkt_type)
				|| pkt_type == KNOT_RRTYPE_RRSIG;
	/* Note: we cache even in KR_STATE_FAIL.  For example,
	 * BOGUS answer can go to +cd cache even without +cd request. */
	if (!qry || qry->flags.CACHED || type_bad || qry->sclass != KNOT_CLASS_IN) {
		return ctx->state;
	}
	/* Do not cache truncated answers, at least for now.  LATER */
	if (knot_wire_get_tc(pkt->wire)) {
		return ctx->state;
	}
	/* Stash individual records. */
	ranked_rr_array_t *selected[] = kr_request_selected(req);
	int ret = 0;
	for (int psec = KNOT_ANSWER; psec <= KNOT_ADDITIONAL; ++psec) {
		const ranked_rr_array_t *arr = selected[psec];
		/* uncached entries are located at the end */
		for (ssize_t i = arr->len - 1; i >= 0; --i) {
			ranked_rr_array_entry_t *entry = arr->at[i];
			if (entry->qry_uid != qry->uid) {
				continue;
				/* TODO: probably safe to break but maybe not worth it */
			}
			ret = stash_rrset(arr, i, qry, cache);
			if (ret) {
				VERBOSE_MSG(qry, "=> stashing RRs errored out\n");
				goto finally;
			}
			/* LATER(optim.): maybe filter out some type-rank combinations
			 * that won't be useful as separate RRsets. */
		}
	}

	stash_pkt(pkt, qry, req);

finally:
	kr_cache_sync(cache);
	return ctx->state; /* we ignore cache-stashing errors */
}

static int stash_rrset(const ranked_rr_array_t *arr, int arr_i,
			const struct kr_query *qry, struct kr_cache *cache)
{
	const ranked_rr_array_entry_t *entry = arr->at[arr_i];
	if (entry->cached) {
		return kr_ok();
	}
	const knot_rrset_t *rr = entry->rr;
	if (!rr) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
	if (!check_dname_for_lf(rr->owner)) {
		WITH_VERBOSE {
			VERBOSE_MSG(qry, "=> skipping zero-containing name ");
			kr_dname_print(rr->owner, "", "\n");
		}
		return kr_ok();
	}

	#if 0
	WITH_VERBOSE {
		VERBOSE_MSG(qry, "=> considering to stash ");
		kr_rrtype_print(rr->type, "", " ");
		kr_dname_print(rr->owner, "", "\n");
	}
	#endif

	switch (rr->type) {
	case KNOT_RRTYPE_RRSIG:
	case KNOT_RRTYPE_NSEC3:
		// for now; LATER NSEC3
		return kr_ok();
	default:
		break;
	}

	/* Find corresponding signatures, if validated.  LATER(optim.): speed. */
	const knot_rrset_t *rr_sigs = NULL;
	if (kr_rank_test(entry->rank, KR_RANK_SECURE)) {
		for (ssize_t j = arr->len - 1; j >= 0; --j) {
			/* TODO: ATM we assume that some properties are the same
			 * for all RRSIGs in the set (esp. label count). */
			ranked_rr_array_entry_t *e = arr->at[j];
			bool ok = e->qry_uid == qry->uid && !e->cached
				&& e->rr->type == KNOT_RRTYPE_RRSIG
				&& knot_rrsig_type_covered(&e->rr->rrs, 0) == rr->type
				&& knot_dname_is_equal(rr->owner, e->rr->owner);
			if (!ok) continue;
			rr_sigs = e->rr;
			break;
		}
	}

	const int wild_labels = rr_sigs == NULL ? 0 :
	       knot_dname_labels(rr->owner, NULL) - knot_rrsig_labels(&rr_sigs->rrs, 0);
	//kr_log_verbose("wild_labels = %d\n", wild_labels);
	if (wild_labels < 0) {
		return kr_ok();
	}
	const knot_dname_t *encloser = rr->owner;
	for (int i = 0; i < wild_labels; ++i) {
		encloser = knot_wire_next_label(encloser, NULL);
	}

	int ret = 0;
	/* Construct the key under which RRs will be stored. */
	struct key k_storage, *k = &k_storage;
	knot_db_val_t key;
	switch (rr->type) {
	case KNOT_RRTYPE_NSEC:
		if (!kr_rank_test(entry->rank, KR_RANK_SECURE)) {
			/* Skip any NSECs that aren't validated. */
			return kr_ok();
		}
		if (!rr_sigs || !rr_sigs->rrs.rr_count || !rr_sigs->rrs.data) {
			assert(!EINVAL);
			return kr_error(EINVAL);
		}
		k->zlf_len = knot_dname_size(knot_rrsig_signer_name(&rr_sigs->rrs, 0)) - 1;
		key = key_NSEC1(k, encloser, wild_labels);
		break;
	default:
		ret = kr_dname_lf(k->buf, encloser, wild_labels);
		if (ret) {
			assert(!ret);
			return kr_error(ret);
		}
		key = key_exact_type(k, rr->type);
	}

	/* Compute materialized sizes of the new data. */
	const knot_rdataset_t *rds_sigs = rr_sigs ? &rr_sigs->rrs : NULL;
	const int rr_ssize = rdataset_dematerialize_size(&rr->rrs);
	knot_db_val_t val_new_entry = {
		.data = NULL,
		.len = offsetof(struct entry_h, data) + rr_ssize
			+ rdataset_dematerialize_size(rds_sigs),
	};

	/* Prepare raw memory for the new entry. */
	ret = entry_h_splice(&val_new_entry, entry->rank, key, k->type, rr->type,
				rr->owner, qry, cache);
	if (ret) return kr_ok(); /* some aren't really errors */
	assert(val_new_entry.data);

	/* Compute TTL, just in case they weren't equal. */
	uint32_t ttl = -1;
	const knot_rdataset_t *rdatasets[] = { &rr->rrs, rds_sigs, NULL };
	for (int j = 0; rdatasets[j]; ++j) {
		knot_rdata_t *rd = rdatasets[j]->data;
		assert(rdatasets[j]->rr_count);
		for (uint16_t l = 0; l < rdatasets[j]->rr_count; ++l) {
			ttl = MIN(ttl, knot_rdata_ttl(rd));
			rd = kr_rdataset_next(rd);
		}
	} /* TODO: consider expirations of RRSIGs as well, just in case. */

	/* Write the entry itself. */
	struct entry_h *eh = val_new_entry.data;
	eh->time = qry->timestamp.tv_sec;
	eh->ttl  = MAX(MIN(ttl, cache->ttl_max), cache->ttl_min);
	eh->rank = entry->rank;
	if (rdataset_dematerialize(&rr->rrs, eh->data)
	    || rdataset_dematerialize(rds_sigs, eh->data + rr_ssize)) {
		/* minimize the damage from incomplete write; TODO: better */
		eh->ttl = 0;
		eh->rank = 0;
		assert(false);
	}
	assert(entry_h_consistent(val_new_entry, rr->type));

	WITH_VERBOSE {
		VERBOSE_MSG(qry, "=> stashed rank: 0%0.2o, ", entry->rank);
		kr_rrtype_print(rr->type, "", " ");
		kr_dname_print(encloser, wild_labels ? "*." : "", " ");
		kr_log_verbose("(%d B total, incl. %d RRSIGs)\n",
				(int)val_new_entry.len,
				(rr_sigs ? rr_sigs->rrs.rr_count : 0)
				);
	}
	return kr_ok();
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
	VERBOSE_MSG(qry, "=> satisfied by exact RR or CNAME: rank 0%0.2o, new TTL %d\n",
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
	const struct entry_h *eh = entry_h_consistent(val, qry->stype);
	if (!eh) {
		assert(false);
		return kr_error(ENOENT);
		// LATER: recovery in case of error, perhaps via removing the entry?
		// LATER(optim): pehaps optimize the zone cut search
	}

	int32_t new_ttl = get_new_ttl(eh, qry, qry->sname, qry->stype);
	if (new_ttl < 0 || eh->rank < lowest_rank) {
		/* Positive record with stale TTL or bad rank.
		 * LATER(optim.): It's unlikely that we find a negative one,
		 * so we might theoretically skip all the cache code. */

		VERBOSE_MSG(qry, "=> skipping exact %s: rank 0%0.2o (min. 0%0.2o), new TTL %d\n",
				eh->is_packet ? "packet" : "RR", eh->rank, lowest_rank, new_ttl);
		return kr_error(ENOENT);
	}

	const void *eh_bound = val.data + val.len;
	if (eh->is_packet) {
		/* Note: we answer here immediately, even if it's (theoretically)
		 * possible that we could generate a higher-security negative proof.
		 * Rank is high-enough so we take it to save time searching. */
		return answer_from_pkt  (ctx, pkt, qry->stype, eh, eh_bound, new_ttl);
	} else {
		return answer_simple_hit(ctx, pkt, qry->stype, eh, eh_bound, new_ttl);
	}
}

int kr_cache_peek_exact(struct kr_cache *cache, const knot_dname_t *name, uint16_t type,
			struct kr_cache_p *peek)
{
	struct key k_storage, *k = &k_storage;

	WITH_VERBOSE {
		VERBOSE_MSG(NULL, "_peek_exact: ");
		kr_rrtype_print(type, "", " ");
		kr_dname_print(name, "", " ");
	}

	int ret = kr_dname_lf(k->buf, name, false);
	if (ret) {
		kr_log_verbose("ERROR!\n");
		return kr_error(ret);
	}

	knot_db_val_t key = key_exact_type(k, type);
	knot_db_val_t val = { NULL, 0 };
	ret = cache_op(cache, read, &key, &val, 1);
	if (!ret) ret = entry_h_seek(&val, type);
	if (ret) {
		kr_log_verbose("miss (ret: %d)\n", ret);
		return ret;
	}
	const struct entry_h *eh = entry_h_consistent(val, type);
	if (!eh || eh->is_packet) {
		// TODO: no packets, but better get rid of whole kr_cache_peek_exact().
		kr_log_verbose("miss\n");
		return kr_error(ENOENT);
	}
	*peek = (struct kr_cache_p){
		.time = eh->time,
		.ttl  = eh->ttl,
		.rank = eh->rank,
		.raw_data = val.data,
		.raw_bound = val.data + val.len,
	};
	kr_log_verbose("hit\n");
	return kr_ok();
}

/** Find the longest prefix NS/xNAME (with OK time+rank), starting at k->*.
 * We store xNAME at NS type to lower the number of searches.
 * CNAME is only considered for equal name, of course.
 * We also store NSEC* parameters at NS type; probably the latest two will be kept.
 * Found type is returned via k->type.
 *
 * \param exact_match Whether exact match is considered special.
 */
static knot_db_val_t closest_NS(kr_layer_t *ctx, struct key *k)
{
	static const knot_db_val_t VAL_EMPTY = { NULL, 0 };
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	int zlf_len = k->buf[0];

	/* FIXME re-review:
	 * 	- exact_match for DS; probably start with false already
	 */
	uint8_t rank_min = KR_RANK_INSECURE | KR_RANK_AUTH;
	// LATER(optim): if stype is NS, we check the same value again
	bool exact_match = true;
	/* Inspect the NS/xNAME entries, shortening by a label on each iteration. */
	do {
		k->buf[0] = zlf_len;
		knot_db_val_t key = key_exact_type(k, KNOT_RRTYPE_NS);
		knot_db_val_t val = VAL_EMPTY;
		int ret = cache_op(cache, read, &key, &val, 1);
		if (ret == -abs(ENOENT)) goto next_label;
		if (ret) {
			assert(!ret);
			return VAL_EMPTY; // TODO: do something with kr_error(ret)?
		}

		/* Check consistency, find any type;
		 * using `goto` for shortening by another label. */
		const struct entry_h *eh = entry_h_consistent(val, KNOT_RRTYPE_NS),
			*eh_orig = eh;
		const knot_db_val_t val_orig = val;
		assert(eh);
		if (!eh) goto next_label; // do something about EILSEQ?
		/* More types are possible; try in order.
		 * For non-fatal failures just "continue;" to try the next type. */
		uint16_t type = 0;
		while (type != KNOT_RRTYPE_DNAME) {
			/* Determine the next type to try. */
			switch (type) {
			case 0:
				type = KNOT_RRTYPE_NS;
				if (!eh_orig->has_ns) continue;
				break;
			case KNOT_RRTYPE_NS:
				type = KNOT_RRTYPE_CNAME;
				/* CNAME is interesting only if we
				 * directly hit the name that was asked */
				if (!exact_match || !eh_orig->has_cname)
					continue;
				break;
			case KNOT_RRTYPE_CNAME:
				type = KNOT_RRTYPE_DNAME;
				/* DNAME is interesting only if we did NOT
				 * directly hit the name that was asked */
				if (exact_match || !eh_orig->has_dname)
					continue;
				break;
			default:
				assert(false);
				return VAL_EMPTY;
			}
			/* Find the entry for the type, check positivity, TTL */
			val = val_orig;
			ret = entry_h_seek(&val, type);
			if (ret || !(eh = entry_h_consistent(val, type))) {
				assert(false);
				goto next_label;
			}
			int32_t new_ttl = get_new_ttl(eh, qry, k->zname, type);
			if (new_ttl < 0
			    /* Not interested in negative or bogus. */
			    || eh->is_packet
			    /* For NS any kr_rank is accepted,
			     * as insecure or even nonauth is OK */
			    || (type != KNOT_RRTYPE_NS && eh->rank < rank_min)) {

				WITH_VERBOSE {
					VERBOSE_MSG(qry, "=> skipping unfit ");
					kr_rrtype_print(type, "",
							eh->is_packet ? " packet" : " RR");
					kr_log_verbose(": rank 0%0.2o, new TTL %d\n",
							eh->rank, new_ttl);
				}
				continue;
			}
			/* We found our match. */
			k->type = type;
			k->zlf_len = zlf_len;
			return val;
		}

	next_label:
		/* remove one more label */
		exact_match = false;
		if (k->zname[0] == 0) { /* missing root NS in cache */
			return VAL_EMPTY;
		}
		zlf_len -= (k->zname[0] + 1);
		k->zname += (k->zname[0] + 1);
		k->buf[zlf_len + 1] = 0;
	} while (true);
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




