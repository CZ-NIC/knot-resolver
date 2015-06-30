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

#include <libknot/descriptor.h>
#include <libknot/errcode.h>
#include <libknot/rrset.h>
#include <libknot/internal/mempool.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/rrtype/rrsig.h>

#include "lib/layer/iterate.h"
#include "lib/cache.h"
#include "lib/module.h"

#define DEBUG_MSG(fmt...) QRDEBUG(kr_rplan_current(rplan), "rrsc",  fmt)
#define DEBUG_MSG_NOPLAN(fmt...) QRDEBUG(NULL, "rrsc",  fmt)
//#define DEBUG_MSG(fmt...)
//#define DEBUG_MSG_NOPLAN(fmt...)

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return ctx->state;
}

/** @internal Baton for stash_commit */
struct stash_baton
{
	struct kr_cache_txn *txn;
	unsigned timestamp;
};

static int commit_rrsig(const char *key, void *val, void *data)
{
	knot_rrset_t *rrsig = val;
	struct stash_baton *baton = data;
	if (knot_rrset_ttl(rrsig) < 1) {
		return kr_ok(); /* Ignore cache busters. */
	}
	/* Check if already cached */
	/** @todo This should check if less trusted data is in the cache,
	          for that the cache would need to trace data trust level.
	   */
	unsigned drift = baton->timestamp;
	knot_rrset_t query_rrsig;

	knot_rrset_init(&query_rrsig, rrsig->owner, rrsig->type, rrsig->rclass);
	if (kr_cache_peek_rrsig(baton->txn, &query_rrsig, &drift) == 0) {
	        return kr_ok();
	}
	return kr_cache_insert_rrsig(baton->txn, rrsig, rrsig->type, baton->timestamp);
}

static int stash_commit(map_t *stash, unsigned timestamp, struct kr_cache_txn *txn)
{
	struct stash_baton baton = {
		.txn = txn,
		.timestamp = timestamp
	};
	return map_walk(stash, &commit_rrsig, &baton);
	return kr_ok();
}

static int validate_rrsig(const knot_rrset_t *rrsig, size_t pos, const knot_rrset_t *rr,
                      struct kr_cache_txn *txn, struct kr_request *req)
{
	struct kr_rplan *rplan = &req->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	uint32_t timestamp = qry->timestamp.tv_sec;

	const knot_dname_t *signer = knot_rrsig_signer_name(&rrsig->rrs, pos);

	knot_rrset_t dnskey_rr;
	knot_rrset_init(&dnskey_rr, (knot_dname_t *)signer, KNOT_RRTYPE_DNSKEY, rr->rclass);
	int ret = kr_cache_peek_rr(txn, &dnskey_rr, &timestamp);
	if (ret != 0) {
		DEBUG_MSG("<= missing DNSKEY\n");
		return KNOT_DNSSEC_ENOKEY;
	}

	return kr_ok();
}

static int merge_in_rrsigs(knot_rrset_t *cache_rr, const knot_rrset_t *rrsigset, const knot_rrset_t *rr,
                           struct kr_cache_txn *txn, struct kr_request *req)
{
	struct kr_rplan *rplan = &req->rplan;
	int ret = KNOT_EOK;

	/* Find rrset corresponding to RRSIG. */
	for (unsigned i = 0; i < rrsigset->rrs.rr_count; ++i) {
		if ((knot_rrsig_type_covered(&rrsigset->rrs, i) == rr->type) &&
		    knot_dname_is_equal(cache_rr->owner, rrsigset->owner)) {
			ret = validate_rrsig(rrsigset, i, rr, txn, req);
			switch (ret) {
			case KNOT_DNSSEC_ENOKEY:
#ifndef NDEBUG
				{
					char name_str[KNOT_DNAME_MAXLEN], type_str[16];
					knot_dname_to_str(name_str, knot_rrsig_signer_name(&rrsigset->rrs, i), sizeof(name_str));
					knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
					DEBUG_MSG_NOPLAN("%s() Missing DNSKEY for '%s %s'.\n", __func__, type_str, name_str);
				}
#endif
				break;
			case 0:
				break;
			default:
				return ret;
				break;
			}

			const knot_rdata_t *rdata = knot_rdataset_at(&rrsigset->rrs, i);
			ret = knot_rdataset_add(&cache_rr->rrs, rdata, rplan->pool);
			if (KNOT_EOK != ret) {
				return ret;
			}
		}
	}

	return ret;
}

static int scan_for_rrsigs(knot_rrset_t *cache_rrsig, const knot_pktsection_t *section,
                           const knot_rrset_t *rr, struct kr_request *req)
{
	struct kr_rplan *rplan = &req->rplan;
	struct kr_cache *cache = &req->ctx->cache;

	struct kr_cache_txn txn;
	int ret = kr_cache_txn_begin(cache, &txn, 0);
	if (0 != ret) {
		return ret;
	}

	knot_rrset_init(cache_rrsig, rr->owner, rr->type, rr->rclass);
	for (uint16_t i = 0; i < section->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(section, i);
		if (KNOT_RRTYPE_RRSIG != rrset->type) {
			continue;
		}
		/* Currently only merge. Signature check is missing. */
		int ret = merge_in_rrsigs(cache_rrsig, rrset, rr, &txn, req);
		if (KNOT_EOK != ret) {
			knot_rrset_clear(cache_rrsig, rplan->pool);
			kr_cache_txn_abort(&txn);
			return ret;
		}
	}

	kr_cache_txn_abort(&txn);
	return kr_ok();
}

static int stash_add_rrsig(map_t *stash, const knot_pktsection_t *section,
                           const knot_rrset_t *rr, struct kr_request *req)
{
	if (rr->type == KNOT_RRTYPE_RRSIG) {
		return kr_ok();
	}

	struct kr_rplan *rplan = &req->rplan;

	/* Stash key = {[1-255] owner, [1-5] type covered, [1] \x00 } */
	char key[8 + KNOT_DNAME_MAXLEN];
	int ret = knot_dname_to_wire((uint8_t *)key, rr->owner, KNOT_DNAME_MAXLEN);
	if (ret <= 0) {
		return ret;
	}
	knot_dname_to_lower((uint8_t *)key);
	ret = snprintf(key + ret - 1, sizeof(key) - KNOT_DNAME_MAXLEN, "%hu", rr->type);
	if (ret <= 0 || ret >= KNOT_DNAME_MAXLEN) {
		return kr_error(EILSEQ);
	}

	/* Check if already exists */
	knot_rrset_t *stashed = map_get(stash, key);
	if (stashed) {
		return kr_ok();
	}

	/* Construct RRSIG RRSet containing related data. */
	knot_rrset_t cache_rrsig;
	ret = scan_for_rrsigs(&cache_rrsig, section, rr, req);
	if (ret != 0) {
		return ret;
	}

	if (cache_rrsig.rrs.rr_count) {
		stashed = knot_rrset_copy(&cache_rrsig, rplan->pool);
		if (!stashed) {
			return kr_error(ENOMEM);
		}
	}
	knot_rrset_clear(&cache_rrsig, rplan->pool);
	if (stashed) {
		return map_set(stash, key, stashed);
	}
	return kr_ok();
}

static void stash_glue(map_t *stash, knot_pkt_t *pkt, const knot_dname_t *ns_name, mm_ctx_t *pool)
{
	const knot_pktsection_t *additional = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	for (unsigned i = 0; i < additional->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(additional, i);
		if ((rr->type != KNOT_RRTYPE_A && rr->type != KNOT_RRTYPE_AAAA) ||
		    !knot_dname_is_equal(rr->owner, ns_name)) {
			continue;
		}
//		stash_add_rrsig(stash, additional, rr, pool);
	}
}

static int stash_authority(map_t *stash, knot_pkt_t *pkt, struct kr_request *req)
{
	struct kr_rplan *rplan = &req->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < authority->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(authority, i);
		/* Cache in-bailiwick data only */
		if (!knot_dname_in(qry->zone_cut.name, rr->owner)) {
			continue;
		}
		/* Look up glue records for NS */
		if (rr->type == KNOT_RRTYPE_NS) {
			stash_glue(stash, pkt, knot_ns_name(&rr->rrs, 0), rplan->pool);
		}
		/* Ignore RRSIGs directly. */
		if (rr->type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		/* Stash record */
		stash_add_rrsig(stash, authority, rr, req);
	}
	return kr_ok();
}

static int stash_answer(map_t *stash, knot_pkt_t *pkt, struct kr_request *req)
{
	struct kr_rplan *rplan = &req->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	const knot_dname_t *cname = qry->sname;
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	for (unsigned i = 0; i < answer->count; ++i) {
		/* Stash direct answers (equal to current QNAME/CNAME) */
		const knot_rrset_t *rr = knot_pkt_rr(answer, i);
		if (!knot_dname_is_equal(rr->owner, cname)) {
			continue;
		}
		/* Ignore RRSIGs directly. */
		if (rr->type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		stash_add_rrsig(stash, answer, rr, req);
		/* Follow CNAME chain */
		if (rr->type == KNOT_RRTYPE_CNAME) {
			cname = knot_cname_name(&rr->rrs);
		} else {
			cname = qry->sname;
		}
	}
	return kr_ok();
}

static int scan_rrsigs(map_t *stash, knot_pkt_t *pkt, struct kr_request *req)
{
	int ret = stash_authority(stash, pkt, req);
	if (ret == 0 && knot_wire_get_aa(pkt->wire)) {
		ret = stash_answer(stash, pkt, req);
	}
	return ret;
}

static int stash(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	/* Do nothing when no DNSSEC required. */
	bool dobit = knot_pkt_has_dnssec(pkt);
	if (!dobit) {
		return ctx->state;
	}

	struct kr_request *req = ctx->data;
	struct kr_rplan *rplan = &req->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	if (!qry || ctx->state & KNOT_STATE_FAIL) {
		return ctx->state;
	}

	/* Cache only positive answers. */
	if (qry->flags & QUERY_CACHED || knot_wire_get_rcode(pkt->wire) != KNOT_RCODE_NOERROR) {
		return ctx->state;
	}
	/* Stash RRSIG data from the AUTHORITY and ANSWER. */
	map_t stash_rrsig = map_make();
	stash_rrsig.malloc = (map_alloc_f) mm_alloc;
	stash_rrsig.free = (map_free_f) mm_free;
	stash_rrsig.baton = rplan->pool;
	int ret = scan_rrsigs(&stash_rrsig, pkt, req);
	/* Cache stashed records */
	if (ret == 0) {
		/* Open write transaction */
		struct kr_cache *cache = &req->ctx->cache;
		struct kr_cache_txn txn;
		if (kr_cache_txn_begin(cache, &txn, 0) == 0) {
			ret = stash_commit(&stash_rrsig, qry->timestamp.tv_sec, &txn);
			if (ret == 0) {
				kr_cache_txn_commit(&txn);
			} else {
				kr_cache_txn_abort(&txn);
			}
		}
		/* Clear if full */
		if (ret == KNOT_ESPACE) {
			/*
			 * Commit empty transaction to make freed pages reclaimable
			 * (This increases the txnid)
			 */
			if (kr_cache_txn_begin(cache, &txn, 0) == 0) {
				kr_cache_txn_commit(&txn);
			}
			/* Now drop the database */
			if (kr_cache_txn_begin(cache, &txn, 0) == 0) {
				ret = kr_cache_clear(&txn);
				if (ret == 0) {
					kr_cache_txn_commit(&txn);
				} else {
					kr_cache_txn_abort(&txn);
				}
			}
		}
	}

	return ctx->state;
}

/** Module implementation. */
const knot_layer_api_t *rrsigcache_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.begin = &begin,
		.consume = &stash
	};

	return &_layer;
}

KR_MODULE_EXPORT(rrsigcache)
