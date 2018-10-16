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
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/errcode.h>
#include <libknot/rrtype/rrsig.h>

#include "contrib/cleanup.h"
#include "contrib/ucw/lib.h"
#include "lib/cache/api.h"
#include "lib/cache/cdb_lmdb.h"
#include "lib/defines.h"
#include "lib/generic/trie.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/utils.h"

#include "lib/cache/impl.h"

/* TODO:
 *	- Reconsider when RRSIGs are put in and retrieved from the cache.
 *	  Currently it's always done, which _might_ be spurious, depending
 *	  on how kresd will use the returned result.
 *	  There's also the "problem" that kresd ATM does _not_ ask upstream
 *	  with DO bit in some cases.
 */


/** Cache version */
static const uint16_t CACHE_VERSION = 5;
/** Key size */
#define KEY_HSIZE (sizeof(uint8_t) + sizeof(uint16_t))
#define KEY_SIZE (KEY_HSIZE + KNOT_DNAME_MAXLEN)


/** @internal Forward declarations of the implementation details
 * \param optout[out] Set *optout = true; when encountering an opt-out NSEC3 (optional). */
static ssize_t stash_rrset(struct kr_cache *cache, const struct kr_query *qry,
		const knot_rrset_t *rr, const knot_rrset_t *rr_sigs, uint32_t timestamp,
		uint8_t rank, trie_t *nsec_pmap, bool *has_optout);
/** Preliminary checks before stash_rrset().  Don't call if returns <= 0. */
static int stash_rrset_precond(const knot_rrset_t *rr, const struct kr_query *qry/*logs*/);

/** @internal Removes all records from cache. */
static inline int cache_clear(struct kr_cache *cache)
{
	cache->stats.delete += 1;
	return cache_op(cache, clear);
}

/** @internal Open cache db transaction and check internal data version. */
static int assert_right_version(struct kr_cache *cache)
{
	/* Check cache ABI version. */
	/* CACHE_KEY_DEF: to avoid collisions with kr_cache_match(). */
	uint8_t key_str[4] = "VERS";
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
	kr_cache_make_checkpoint(cache);
	(void)assert_right_version(cache);

	char *fpath;
	ret = asprintf(&fpath, "%s/data.mdb", opts->path);
	if (ret > 0) {
		kr_cache_emergency_file_to_remove = fpath;
	} else {
		assert(false); /* non-critical, but still */
	}
	return 0;
}

const char *kr_cache_emergency_file_to_remove = NULL;


#define cache_isvalid(cache) ((cache) && (cache)->api && (cache)->db)

void kr_cache_close(struct kr_cache *cache)
{
	if (cache_isvalid(cache)) {
		cache_op(cache, close);
		cache->db = NULL;
	}
	free(/*const-cast*/(char*)kr_cache_emergency_file_to_remove);
	kr_cache_emergency_file_to_remove = NULL;
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

int kr_cache_insert_rr(struct kr_cache *cache, const knot_rrset_t *rr, const knot_rrset_t *rrsig, uint8_t rank, uint32_t timestamp)
{
	int err = stash_rrset_precond(rr, NULL);
	if (err <= 0) {
		return kr_ok();
	}
	ssize_t written = stash_rrset(cache, NULL, rr, rrsig, timestamp, rank, NULL, NULL);
		/* Zone's NSEC* parames aren't updated, but that's probably OK
		 * for kr_cache_insert_rr() */
	if (written >= 0) {
		return kr_ok();
	}

	return (int) written;
}

int kr_cache_clear(struct kr_cache *cache)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}
	int ret = cache_clear(cache);
	if (ret == 0) {
		kr_cache_make_checkpoint(cache);
		ret = assert_right_version(cache);
	}
	return ret;
}

/* When going stricter, BEWARE of breaking entry_h_consistent_NSEC() */
struct entry_h * entry_h_consistent(knot_db_val_t data, uint16_t type)
{
	(void) type; /* unused, for now */
	if (!data.data) return NULL;
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
	ok = ok && kr_rank_check(eh->rank);
	ok = ok && (!kr_rank_test(eh->rank, KR_RANK_BOGUS)
		    || eh->is_packet);
	ok = ok && (eh->is_packet || !eh->has_optout);

	return ok ? /*const-cast*/(struct entry_h *)eh : NULL;
}

int32_t get_new_ttl(const struct entry_h *entry, const struct kr_query *qry,
                    const knot_dname_t *owner, uint16_t type, uint32_t now)
{
	int32_t diff = now - entry->time;
	if (diff < 0) {
		/* We may have obtained the record *after* the request started. */
		diff = 0;
	}
	int32_t res = entry->ttl - diff;
	if (res < 0 && owner && qry && qry->stale_cb) {
		/* Stale-serving decision, delegated to a callback. */
		int res_stale = qry->stale_cb(res, owner, type, qry);
		if (res_stale >= 0)
			return res_stale;
	}
	return res;
}

int32_t kr_cache_ttl(const struct kr_cache_p *peek, const struct kr_query *qry,
		     const knot_dname_t *name, uint16_t type)
{
	const struct entry_h *eh = peek->raw_data;
	return get_new_ttl(eh, qry, name, type, qry->timestamp.tv_sec);
}

/** Check that no label contains a zero character, incl. a log trace.
 *
 * We refuse to work with those, as LF and our cache keys might become ambiguous.
 * Assuming uncompressed name, as usual.
 * CACHE_KEY_DEF
 */
static bool check_dname_for_lf(const knot_dname_t *n, const struct kr_query *qry/*logging*/)
{
	const bool ret = knot_dname_size(n) == strlen((const char *)n) + 1;
	if (!ret) { WITH_VERBOSE(qry) {
		auto_free char *n_str = kr_dname_text(n);
		VERBOSE_MSG(qry, "=> skipping zero-containing name %s\n", n_str);
	} }
	return ret;
}

/** Return false on types to be ignored.  Meant both for sname and direct cache requests. */
static bool check_rrtype(uint16_t type, const struct kr_query *qry/*logging*/)
{
	const bool ret = !knot_rrtype_is_metatype(type)
			&& type != KNOT_RRTYPE_RRSIG;
	if (!ret) { WITH_VERBOSE(qry) {
		auto_free char *type_str = kr_rrtype_text(type);
		VERBOSE_MSG(qry, "=> skipping RR type %s\n", type_str);
	} }
	return ret;
}

/** Like key_exact_type() but omits a couple checks not holding for pkt cache. */
knot_db_val_t key_exact_type_maypkt(struct key *k, uint16_t type)
{
	assert(check_rrtype(type, NULL));
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


/** The inside for cache_peek(); implementation separated to ./peek.c */
int peek_nosync(kr_layer_t *ctx, knot_pkt_t *pkt);
/** function for .produce phase */
int cache_peek(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	/* We first check various exit-conditions and then call the _real function. */

	if (!kr_cache_is_open(&req->ctx->cache)
	    || ctx->state & (KR_STATE_FAIL|KR_STATE_DONE) || qry->flags.NO_CACHE
	    || (qry->flags.CACHE_TRIED && !qry->stale_cb)
	    || !check_rrtype(qry->stype, qry) /* LATER: some other behavior for some of these? */
	    || qry->sclass != KNOT_CLASS_IN) {
		return ctx->state; /* Already resolved/failed or already tried, etc. */
	}
	/* ATM cache only peeks for qry->sname and that would be useless
	 * to repeat on every iteration, so disable it from now on.
	 * LATER(optim.): assist with more precise QNAME minimization. */
	qry->flags.CACHE_TRIED = true;

	if (qry->stype == KNOT_RRTYPE_NSEC) {
		VERBOSE_MSG(qry, "=> skipping stype NSEC\n");
		return ctx->state;
	}
	if (!check_dname_for_lf(qry->sname, qry)) {
		return ctx->state;
	}

	int ret = peek_nosync(ctx, pkt);
	kr_cache_sync(&req->ctx->cache);
	return ret;
}



/** It's simply inside of cycle taken out to decrease indentation.  \return error code. */
static int stash_rrarray_entry(ranked_rr_array_t *arr, int arr_i,
			const struct kr_query *qry, struct kr_cache *cache,
			int *unauth_cnt, trie_t *nsec_pmap, bool *has_optout);
/** Stash a single nsec_p.  \return 0 (errors are ignored). */
static int stash_nsec_p(const knot_dname_t *dname, const char *nsec_p_v,
			struct kr_request *req);

/** The whole .consume phase for the cache module. */
int cache_stash(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	/* Note: we cache even in KR_STATE_FAIL.  For example,
	 * BOGUS answer can go to +cd cache even without +cd request. */
	if (!kr_cache_is_open(cache) || !qry
	    || qry->flags.CACHED || !check_rrtype(knot_pkt_qtype(pkt), qry)
	    || qry->sclass != KNOT_CLASS_IN) {
		return ctx->state;
	}
	/* Do not cache truncated answers, at least for now.  LATER */
	if (knot_wire_get_tc(pkt->wire)) {
		return ctx->state;
	}
	/* Stash individual records. */
	ranked_rr_array_t *selected[] = kr_request_selected(req);
	int unauth_cnt = 0;
	trie_t *nsec_pmap = trie_create(&req->pool);
	if (!nsec_pmap) {
		assert(!ENOMEM);
		goto finally;
	}
	bool has_optout = false;
		/* ^^ DNSSEC_OPTOUT is not fired in cases like `com. A`,
		 * but currently we don't stash separate NSEC3 proving that. */
	for (int psec = KNOT_ANSWER; psec <= KNOT_ADDITIONAL; ++psec) {
		ranked_rr_array_t *arr = selected[psec];
		/* uncached entries are located at the end */
		for (ssize_t i = arr->len - 1; i >= 0; --i) {
			ranked_rr_array_entry_t *entry = arr->at[i];
			if (entry->qry_uid != qry->uid) {
				continue;
				/* TODO: probably safe to break but maybe not worth it */
			}
			int ret = stash_rrarray_entry(arr, i, qry, cache, &unauth_cnt,
							nsec_pmap, &has_optout);
			if (ret) {
				VERBOSE_MSG(qry, "=> stashing RRs errored out\n");
				goto finally;
			}
			/* LATER(optim.): maybe filter out some type-rank combinations
			 * that won't be useful as separate RRsets. */
		}
	}

	trie_it_t *it;
	for (it = trie_it_begin(nsec_pmap); !trie_it_finished(it); trie_it_next(it)) {
		stash_nsec_p((const knot_dname_t *)trie_it_key(it, NULL),
				(const char *)*trie_it_val(it), req);
	}
	trie_it_free(it);
	/* LATER(optim.): typically we also have corresponding NS record in the list,
	 * so we might save a cache operation. */

	stash_pkt(pkt, qry, req, has_optout);

finally:
	if (unauth_cnt) {
		VERBOSE_MSG(qry, "=> stashed also %d nonauth RRsets\n", unauth_cnt);
	};
	kr_cache_sync(cache);
	return ctx->state; /* we ignore cache-stashing errors */
}

/** Preliminary checks before stash_rrset().  Don't call if returns <= 0. */
static int stash_rrset_precond(const knot_rrset_t *rr, const struct kr_query *qry/*logs*/)
{
	if (!rr || rr->rclass != KNOT_CLASS_IN) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
	if (!check_rrtype(rr->type, qry)) {
		return kr_ok();
	}
	if (!check_dname_for_lf(rr->owner, qry)) {
		return kr_ok();
	}
	return 1/*proceed*/;
}

static ssize_t stash_rrset(struct kr_cache *cache, const struct kr_query *qry,
		const knot_rrset_t *rr, const knot_rrset_t *rr_sigs, uint32_t timestamp,
		uint8_t rank, trie_t *nsec_pmap, bool *has_optout)
{
	assert(stash_rrset_precond(rr, qry) > 0);
	if (!cache) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}

	const int wild_labels = rr_sigs == NULL ? 0 :
	       knot_dname_labels(rr->owner, NULL) - knot_rrsig_labels(rr_sigs->rrs.rdata);
	if (wild_labels < 0) {
		return kr_ok();
	}
	const knot_dname_t *encloser = rr->owner; /**< the closest encloser name */
	for (int i = 0; i < wild_labels; ++i) {
		encloser = knot_wire_next_label(encloser, NULL);
	}
	int ret = 0;

	/* Construct the key under which RRs will be stored,
	 * and add corresponding nsec_pmap item (if necessary). */
	struct key k_storage, *k = &k_storage;
	knot_db_val_t key;
	switch (rr->type) {
	case KNOT_RRTYPE_NSEC3:
		/* Skip "suspicious" or opt-out NSEC3 sets. */
		if (rr->rrs.count != 1) return kr_ok();
		if (KNOT_NSEC3_FLAG_OPT_OUT & knot_nsec3_flags(rr->rrs.rdata)) {
			if (has_optout) *has_optout = true;
			return kr_ok();
		}
		/* fall through */
	case KNOT_RRTYPE_NSEC:
		if (!kr_rank_test(rank, KR_RANK_SECURE)) {
			/* Skip any NSEC*s that aren't validated. */
			return kr_ok();
		}
		if (!rr_sigs || !rr_sigs->rrs.count || !rr_sigs->rrs.rdata) {
			assert(!EINVAL);
			return kr_error(EINVAL);
		}
		const knot_dname_t *signer = knot_rrsig_signer_name(rr_sigs->rrs.rdata);
		const int signer_size = knot_dname_size(signer);
		k->zlf_len = signer_size - 1;

		void **npp = nsec_pmap == NULL ? NULL
			: trie_get_ins(nsec_pmap, (const char *)signer, signer_size);
		assert(!nsec_pmap || (npp && ENOMEM));
		if (rr->type == KNOT_RRTYPE_NSEC) {
			key = key_NSEC1(k, encloser, wild_labels);
			break;
		}

		assert(rr->type == KNOT_RRTYPE_NSEC3);
		const knot_rdata_t * const rdata = rr->rrs.rdata;
		if (rdata->len <= 4) return kr_error(EILSEQ); /*< data from outside; less trust */
		const int np_dlen = nsec_p_rdlen(rdata->data);
		if (np_dlen > rdata->len) return kr_error(EILSEQ);
		key = key_NSEC3(k, encloser, nsec_p_mkHash(rdata->data));
		if (npp && !*npp) {
			*npp = mm_alloc(&qry->request->pool, np_dlen);
			if (!*npp) {
				assert(!ENOMEM);
				break;
			}
			memcpy(*npp, rdata->data, np_dlen);
		}
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
	assert(rr_ssize == to_even(rr_ssize));
	knot_db_val_t val_new_entry = {
		.data = NULL,
		.len = offsetof(struct entry_h, data) + rr_ssize
			+ rdataset_dematerialize_size(rds_sigs),
	};

	/* Prepare raw memory for the new entry. */
	ret = entry_h_splice(&val_new_entry, rank, key, k->type, rr->type,
				rr->owner, qry, cache, timestamp);
	if (ret) return kr_ok(); /* some aren't really errors */
	assert(val_new_entry.data);

	const uint32_t ttl = rr->ttl;
	/* FIXME: consider TTLs and expirations of RRSIGs as well, just in case. */

	/* Write the entry itself. */
	struct entry_h *eh = val_new_entry.data;
	memset(eh, 0, offsetof(struct entry_h, data));
	eh->time = timestamp;
	eh->ttl  = MAX(MIN(ttl, cache->ttl_max), cache->ttl_min);
	eh->rank = rank;
	if (rdataset_dematerialize(&rr->rrs, eh->data)
	    || rdataset_dematerialize(rds_sigs, eh->data + rr_ssize)) {
		/* minimize the damage from incomplete write; TODO: better */
		eh->time = 0;
		eh->ttl = 0;
		eh->rank = 0;
		assert(false);
	}
	assert(entry_h_consistent(val_new_entry, rr->type));

	#if 0 /* Occasionally useful when debugging some kinds of changes. */
	{
	kr_cache_sync(cache);
	knot_db_val_t val = { NULL, 0 };
	ret = cache_op(cache, read, &key, &val, 1);
	if (ret != kr_error(ENOENT)) { // ENOENT might happen in some edge case, I guess
		assert(!ret);
		entry_list_t el;
		entry_list_parse(val, el);
	}
	}
	#endif

	/* Update metrics */
	cache->stats.insert += 1;

	/* Verbose-log some not-too-common cases. */
	WITH_VERBOSE(qry) { if (kr_rank_test(rank, KR_RANK_AUTH)
				|| rr->type == KNOT_RRTYPE_NS) {
		auto_free char *type_str = kr_rrtype_text(rr->type),
			*encl_str = kr_dname_text(encloser);
		VERBOSE_MSG(qry, "=> stashed %s%s %s, rank 0%.2o, "
			"%d B total, incl. %d RRSIGs\n",
			(wild_labels ? "*." : ""), encl_str, type_str, rank,
			(int)val_new_entry.len, (rr_sigs ? rr_sigs->rrs.count : 0)
			);
	} }

	return (ssize_t) val_new_entry.len;
}

static int stash_rrarray_entry(ranked_rr_array_t *arr, int arr_i,
			const struct kr_query *qry, struct kr_cache *cache,
			int *unauth_cnt, trie_t *nsec_pmap, bool *has_optout)
{
	ranked_rr_array_entry_t *entry = arr->at[arr_i];
	if (entry->cached) {
		return kr_ok();
	}
	const knot_rrset_t *rr = entry->rr;
	if (rr->type == KNOT_RRTYPE_RRSIG) {
		return kr_ok(); /* reduce verbose logging from the following call */
	}
	int ret = stash_rrset_precond(rr, qry);
	if (ret <= 0) {
		return ret;
	}

	/* Try to find corresponding signatures, always.  LATER(optim.): speed. */
	ranked_rr_array_entry_t *entry_rrsigs = NULL;
	const knot_rrset_t *rr_sigs = NULL;
	for (ssize_t j = arr->len - 1; j >= 0; --j) {
		/* TODO: ATM we assume that some properties are the same
		 * for all RRSIGs in the set (esp. label count). */
		ranked_rr_array_entry_t *e = arr->at[j];
		bool ok = e->qry_uid == qry->uid && !e->cached
			&& e->rr->type == KNOT_RRTYPE_RRSIG
			&& knot_rrsig_type_covered(e->rr->rrs.rdata) == rr->type
			&& knot_dname_is_equal(rr->owner, e->rr->owner);
		if (!ok) continue;
		entry_rrsigs = e;
		rr_sigs = e->rr;
		break;
	}

	ssize_t written = stash_rrset(cache, qry, rr, rr_sigs, qry->timestamp.tv_sec,
					entry->rank, nsec_pmap, has_optout);
	if (written < 0) {
		kr_log_error("[%05u.%02u][cach] stash failed, ret = %d\n", qry->request->uid,
			     qry->uid, ret);
		return (int) written;
	}

	if (written > 0) {
		/* Mark entry as cached for the rest of the query processing */
		entry->cached = true;
		if (entry_rrsigs) {
			entry_rrsigs->cached = true;
		}
		if (!kr_rank_test(entry->rank, KR_RANK_AUTH) && rr->type != KNOT_RRTYPE_NS) {
			*unauth_cnt += 1;
		}
	}

	return kr_ok();
}

static int stash_nsec_p(const knot_dname_t *dname, const char *nsec_p_v,
			struct kr_request *req)
{
	const struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;
	uint32_t valid_until = qry->timestamp.tv_sec + cache->ttl_max;
		/* LATER(optim.): be more precise here ^^ and reduce calls. */
	static const int32_t ttl_margin = 3600;
	const uint8_t *nsec_p = (const uint8_t *)nsec_p_v;
	int data_stride = sizeof(valid_until) + nsec_p_rdlen(nsec_p);

	unsigned int log_hash = 0xFeeeFeee; /* this type is simpler for printf args */
	auto_free char *log_dname = NULL;
	WITH_VERBOSE(qry) {
		log_hash = nsec_p_v ? nsec_p_mkHash((const uint8_t *)nsec_p_v) : 0;
		log_dname = kr_dname_text(dname);
	}
	/* Find what's in the cache. */
	struct key k_storage, *k = &k_storage;
	int ret = kr_dname_lf(k->buf, dname, false);
	if (ret) return kr_error(ret);
	knot_db_val_t key = key_exact_type(k, KNOT_RRTYPE_NS);
	knot_db_val_t val_orig = { NULL, 0 };
	ret = cache_op(cache, read, &key, &val_orig, 1);
	if (ret && ret != -ABS(ENOENT)) {
		VERBOSE_MSG(qry, "=> EL read failed (ret: %d)\n", ret);
		return kr_ok();
	}
	/* Prepare new entry_list_t so we can just write at el[0]. */
	entry_list_t el;
	int log_refresh_by = 0;
	if (ret == -ABS(ENOENT)) {
		memset(el, 0, sizeof(el));
	} else {
		ret = entry_list_parse(val_orig, el);
		if (ret) {
			VERBOSE_MSG(qry, "=> EL parse failed (ret: %d)\n", ret);
			return kr_error(0);
		}
		/* Find the index to replace. */
		int i_replace = ENTRY_APEX_NSECS_CNT - 1;
		for (int i = 0; i < ENTRY_APEX_NSECS_CNT; ++i) {
			if (el[i].len != data_stride) continue;
			if (nsec_p && memcmp(nsec_p, (uint8_t *)el[i].data + sizeof(uint32_t),
						data_stride - sizeof(uint32_t)) != 0) {
				continue;
			}
			/* Save a cache operation if TTL extended only a little. */
			uint32_t valid_orig;
			memcpy(&valid_orig, el[i].data, sizeof(valid_orig));
			const int32_t ttl_extended_by = valid_until - valid_orig;
			if (ttl_extended_by < ttl_margin) {
				VERBOSE_MSG(qry,
					"=> nsec_p stash for %s skipped (extra TTL: %d, hash: %x)\n",
					log_dname, ttl_extended_by, log_hash);
				return kr_ok();
			}
			i_replace = i;
			log_refresh_by = ttl_extended_by;
			break;
		}
		/* Shift the other indices: move the first `i_replace` blocks
		 * by one position. */
		if (i_replace) {
			memmove(&el[1], &el[0], sizeof(el[0]) * i_replace);
		}
	}
	/* Prepare old data into a buffer.  See entry_h_splice() for why.  LATER(optim.) */
	el[0].len = data_stride;
	el[0].data = NULL;
	knot_db_val_t val;
	val.len = entry_list_serial_size(el),
	val.data = mm_alloc(&req->pool, val.len),
	entry_list_memcpy(val.data, el);
	/* Prepare the new data chunk */
	memcpy(el[0].data, &valid_until, sizeof(valid_until));
	if (nsec_p) {
		memcpy((uint8_t *)el[0].data + sizeof(valid_until), nsec_p,
			data_stride - sizeof(valid_until));
	}
	/* Write it all to the cache */
	ret = cache_op(cache, write, &key, &val, 1);
	if (ret || !val.data) {
		VERBOSE_MSG(qry, "=> EL write failed (ret: %d)\n", ret);
		return kr_ok();
	}
	if (log_refresh_by) {
		VERBOSE_MSG(qry, "=> nsec_p stashed for %s (refresh by %d, hash: %x)\n",
				log_dname, log_refresh_by, log_hash);
	} else {
		VERBOSE_MSG(qry, "=> nsec_p stashed for %s (new, hash: %x)\n",
				log_dname, log_hash);
	}
	return kr_ok();
}


static int peek_exact_real(struct kr_cache *cache, const knot_dname_t *name, uint16_t type,
			struct kr_cache_p *peek)
{
	if (!check_rrtype(type, NULL) || !check_dname_for_lf(name, NULL)) {
		return kr_error(ENOTSUP);
	}
	struct key k_storage, *k = &k_storage;

	int ret = kr_dname_lf(k->buf, name, false);
	if (ret) return kr_error(ret);

	knot_db_val_t key = key_exact_type(k, type);
	knot_db_val_t val = { NULL, 0 };
	ret = cache_op(cache, read, &key, &val, 1);
	if (!ret) ret = entry_h_seek(&val, type);
	if (ret) return kr_error(ret);

	const struct entry_h *eh = entry_h_consistent(val, type);
	if (!eh || eh->is_packet) {
		// TODO: no packets, but better get rid of whole kr_cache_peek_exact().
		return kr_error(ENOENT);
	}
	*peek = (struct kr_cache_p){
		.time = eh->time,
		.ttl  = eh->ttl,
		.rank = eh->rank,
		.raw_data = val.data,
		.raw_bound = knot_db_val_bound(val),
	};
	return kr_ok();
}
int kr_cache_peek_exact(struct kr_cache *cache, const knot_dname_t *name, uint16_t type,
			struct kr_cache_p *peek)
{	/* Just wrap with extra verbose logging. */
	const int ret = peek_exact_real(cache, name, type, peek);
	if (false && VERBOSE_STATUS) { /* too noisy for usual --verbose */
		auto_free char *type_str = kr_rrtype_text(type),
			*name_str = kr_dname_text(name);
		const char *result_str = (ret == kr_ok() ? "hit" :
				(ret == kr_error(ENOENT) ? "miss" : "error"));
		VERBOSE_MSG(NULL, "_peek_exact: %s %s %s (ret: %d)",
				type_str, name_str, result_str, ret);
	}
	return ret;
}

int kr_cache_remove(struct kr_cache *cache, const knot_dname_t *name, uint16_t type)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}
	if (!cache->api->remove) {
		return kr_error(ENOSYS);
	}
	struct key k_storage, *k = &k_storage;
	int ret = kr_dname_lf(k->buf, name, false);
	if (ret) return kr_error(ret);

	knot_db_val_t key = key_exact_type(k, type);
	return cache_op(cache, remove, &key, 1);
}

int kr_cache_match(struct kr_cache *cache, const knot_dname_t *name,
		   bool exact_name, knot_db_val_t keyval[][2], int maxcount)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}
	if (!cache->api->match) {
		return kr_error(ENOSYS);
	}

	struct key k_storage, *k = &k_storage;

	int ret = kr_dname_lf(k->buf, name, false);
	if (ret) return kr_error(ret);

	// use a mock type
	knot_db_val_t key = key_exact_type(k, KNOT_RRTYPE_A);
	/* CACHE_KEY_DEF */
	key.len -= sizeof(uint16_t); /* the type */
	if (!exact_name) {
		key.len -= 2; /* '\0' 'E' */
		if (name[0] == '\0') ++key.len; /* the root name is special ATM */
	}
	return cache_op(cache, match, &key, keyval, maxcount);
}

int kr_unpack_cache_key(knot_db_val_t key, knot_dname_t *buf, uint16_t *type)
{
	if (key.data == NULL || buf == NULL || type == NULL) {
		return kr_error(EINVAL);
	}

	int len = -1;
	const char *tag, *key_data = key.data;
	for (tag = key_data + 1; tag < key_data + key.len; ++tag) {
		/* CACHE_KEY_DEF */
		if (tag[-1] == '\0' && (tag == key_data + 1 || tag[-2] == '\0')) {
			if (tag[0] != 'E') return kr_error(EINVAL);
			len = tag - 1 - key_data;
			break;
		}
	}

	if (len == -1 || len > KNOT_DNAME_MAXLEN) {
		return kr_error(EINVAL);
	}

	int ret = knot_dname_lf2wire(buf, len, key.data);
	if (ret < 0) {
		return kr_error(ret);
	}

	/* CACHE_KEY_DEF: jump over "\0 E/1" */
	memcpy(type, tag + 1, sizeof(uint16_t));

	return kr_ok();
}


int kr_cache_remove_subtree(struct kr_cache *cache, const knot_dname_t *name,
			    bool exact_name, int maxcount)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}

	knot_db_val_t keyval[maxcount][2], keys[maxcount];
	int ret = kr_cache_match(cache, name, exact_name, keyval, maxcount);
	if (ret <= 0) { /* ENOENT -> nothing to remove */
		return (ret == KNOT_ENOENT) ? 0 : ret;
	}
	const int count = ret;
	/* Duplicate the key strings, as deletion may invalidate the pointers. */
	int i;
	for (i = 0; i < count; ++i) {
		keys[i].len = keyval[i][0].len;
		keys[i].data = malloc(keys[i].len);
		if (!keys[i].data) {
			ret = kr_error(ENOMEM);
			goto cleanup;
		}
		memcpy(keys[i].data, keyval[i][0].data, keys[i].len);
	}
	ret = cache->api->remove(cache->db, keys, count);
cleanup:
	kr_cache_sync(cache); /* Sync even after just kr_cache_match(). */
	/* Free keys */
	while (--i >= 0) {
		free(keys[i].data);
	}
	return ret;
}

