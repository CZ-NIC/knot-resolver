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

#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>

#include <libknot/packet/wire.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/rrtype/rrsig.h>

#include "lib/dnssec/nsec.h"
#include "lib/dnssec/nsec3.h"
#include "lib/dnssec/packet/pkt.h"
#include "lib/dnssec.h"
#include "lib/layer.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/defines.h"
#include "lib/module.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "vldr", fmt)

struct rrset_ids {
	const knot_dname_t *owner;
	uint16_t type;
	uint32_t ttl;
};

/** Simplistic structure holding RR types that are contained in the packet. */
struct contained_ids {
	struct rrset_ids *ids;
	size_t size;
	size_t max;
	mm_ctx_t *pool;
};

static int rrtypes_add(struct contained_ids *stored, const knot_rrset_t *rr)
{
	if (!stored || !rr) {
		return kr_error(EINVAL);
	}

	size_t i;
	for (i = 0; i < stored->size; ++i) {
		if ((knot_dname_cmp(stored->ids[i].owner, rr->owner) == 0) &&
		    (stored->ids[i].type == rr->type)) {
			break;
		}
	}
	uint32_t rr_ttl = knot_rdata_ttl(knot_rdataset_at(&rr->rrs, 0));
	if (i < stored->size) {
		if (stored->ids[i].ttl == rr_ttl) {
			return kr_ok(); /* Type is stored. */
		} else {
			/* RFC2181 5.2 */
			return kr_error(EINVAL);
		}
	}

	if (stored->max == stored->size) {
#define INCREMENT 8
		struct rrset_ids *new = mm_realloc(stored->pool, stored->ids, stored->max + INCREMENT * sizeof(*stored->ids), stored->max);
		if (new) {
			stored->ids = new;
			stored->max += INCREMENT * sizeof(uint16_t);
		} else {
			return kr_error(ENOMEM);
		}
#undef INCREMENT
	}
	assert(stored->max > stored->size);

	stored->ids[stored->size].owner = rr->owner;
	stored->ids[stored->size].type = rr->type;
	stored->ids[stored->size].ttl = rr_ttl;
	++stored->size;
	return kr_ok();
}

static int validate_section(struct kr_query *qry, knot_pkt_t *answer,
                            knot_section_t section_id, mm_ctx_t *pool,
                            bool has_nsec3)
{
	const knot_pktsection_t *sec = knot_pkt_section(answer, section_id);
	if (!sec) {
		return kr_ok();
	}

	int ret = kr_ok();
	struct contained_ids stored = {0, };
	stored.pool = pool;
	knot_rrset_t *covered = NULL;

	/* Determine RR types contained in the section. */
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(sec, i);
		if (rr->type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		if ((rr->type == KNOT_RRTYPE_NS) && (section_id == KNOT_AUTHORITY)) {
			continue;
		}
		ret = rrtypes_add(&stored, rr);
		if (ret != 0) {
			goto fail;
		}
	}

	for (size_t i = 0; i < stored.size; ++i) {
		knot_rrset_free(&covered, pool);
		/* Construct a RRSet. */
		for (unsigned j = 0; j < sec->count; ++j) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, j);
			if ((rr->type != stored.ids[i].type) ||
			    (knot_dname_cmp(rr->owner, stored.ids[i].owner) != 0)) {
				continue;
			}

			if (covered) {
				ret = knot_rdataset_merge(&covered->rrs, &rr->rrs, pool);
				if (ret != 0) {
					goto fail;
				}
			} else {
				covered = knot_rrset_copy(rr, pool);
				if (!covered) {
					ret = kr_error(ENOMEM);
					goto fail;
				}
			}
		}
		/* Validate RRSet. */
		/* Can't use qry->zone_cut.name directly, as this name can
		 * change when updating cut information before validation.
		 */
		const knot_dname_t *zone_name = qry->zone_cut.key ? qry->zone_cut.key->owner : NULL;
		ret = kr_rrset_validate(answer, section_id, covered, qry->zone_cut.key, zone_name, qry->timestamp.tv_sec, has_nsec3);
		if (ret != 0) {
			break;
		}
	}

fail:
	mm_free(stored.pool, stored.ids);
	knot_rrset_free(&covered, pool);
	return ret;
}

static int validate_records(struct kr_query *qry, knot_pkt_t *answer, mm_ctx_t *pool, bool has_nsec3)
{
#warning TODO: validate RRSIGS (records with ZSK, keys with KSK), return FAIL if failed
	if (!qry->zone_cut.key) {
		DEBUG_MSG(qry, "<= no DNSKEY, can't validate\n");
		return kr_error(KNOT_DNSSEC_ENOKEY);
	}

	int ret;

	ret = validate_section(qry, answer, KNOT_ANSWER, pool, has_nsec3);
	if (ret != 0) {
		return ret;
	}
	ret = validate_section(qry, answer, KNOT_AUTHORITY, pool, has_nsec3);

	return ret;
}

static int validate_keyset(struct kr_query *qry, knot_pkt_t *answer, bool has_nsec3)
{
	/* Merge DNSKEY records from answer */
	const knot_pktsection_t *an = knot_pkt_section(answer, KNOT_ANSWER);
	for (unsigned i = 0; i < an->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(an, i);
		if ((rr->type != KNOT_RRTYPE_DNSKEY) ||
		    (knot_dname_cmp(rr->owner, qry->zone_cut.name) != 0)) {
			continue;
		}
		/* Merge with zone cut (or replace ancestor key). */
		if (!qry->zone_cut.key || !knot_dname_is_equal(qry->zone_cut.key->owner, rr->owner)) {
			qry->zone_cut.key = knot_rrset_copy(rr, qry->zone_cut.pool);
			if (!qry->zone_cut.key) {
				return kr_error(ENOMEM);
			}
		} else {
			int ret = knot_rdataset_merge(&qry->zone_cut.key->rrs,
			                              &rr->rrs, qry->zone_cut.pool);
			if (ret != 0) {
				knot_rrset_free(&qry->zone_cut.key, qry->zone_cut.pool);
				return ret;
			}
		}
	}

	if (!qry->zone_cut.key) {
		/* TODO -- Not sure about the error value. */
		return kr_error(KNOT_DNSSEC_ENOKEY);
	}

#warning TODO: Ensure canonical format of the whole DNSKEY RRSet. (Also remove duplicities?)

	/* Check if there's a key for current TA. */
	/* @todo this is not going to work with cached DNSKEY, as the TA is not yet ready,
	 *       must not check if the data comes from cache */
	int ret = kr_dnskeys_trusted(answer, KNOT_ANSWER, qry->zone_cut.key,
	                             qry->zone_cut.trust_anchor, qry->zone_cut.name,
	                             qry->timestamp.tv_sec, has_nsec3);
	if (ret != 0) {
		knot_rrset_free(&qry->zone_cut.key, qry->zone_cut.pool);
		return ret;
	}
	return kr_ok();
}

static const knot_dname_t *section_first_signer_name(knot_pkt_t *pkt, knot_section_t section_id)
{
	const knot_dname_t *sname = NULL;
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec) {
		return sname;
	}

	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(sec, i);
		if (rr->type != KNOT_RRTYPE_RRSIG) {
			continue;
		}

		sname = knot_rrsig_signer_name(&rr->rrs, 0);
		break;
	}

	return sname;
}

static const knot_dname_t *first_rrsig_signer_name(knot_pkt_t *answer)
{
	const knot_dname_t *ans_sname = section_first_signer_name(answer, KNOT_ANSWER);
	const knot_dname_t *auth_sname = section_first_signer_name(answer, KNOT_AUTHORITY);

	if (!ans_sname) {
		return auth_sname;
	} else if (!auth_sname) {
		return ans_sname;
	} else if (knot_dname_is_equal(ans_sname, auth_sname)) {
		return ans_sname;
	} else {
		return NULL;
	}
}

static knot_rrset_t *update_ds(struct kr_zonecut *cut, const knot_pktsection_t *sec)
{
	/* Aggregate DS records (if using multiple keys) */
	knot_rrset_t *new_ds = NULL;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(sec, i);
		if (rr->type != KNOT_RRTYPE_DS) {
			continue;
		}
		int ret = 0;
		if (new_ds) {
			ret = knot_rdataset_merge(&new_ds->rrs, &rr->rrs, cut->pool);
		} else {
			new_ds = knot_rrset_copy(rr, cut->pool);
			if (!new_ds) {
				return NULL;
			}
		}
		if (ret != 0) {
			knot_rrset_free(&new_ds, cut->pool);
			return NULL;
		}
	}
	return new_ds;	
}

static int update_parent(struct kr_query *qry, uint16_t answer_type)
{
	struct kr_query *parent = qry->parent;
	assert(parent);
	switch(answer_type) {
	case KNOT_RRTYPE_DNSKEY:
		DEBUG_MSG(qry, "<= parent: updating DNSKEY\n");
		parent->zone_cut.key = knot_rrset_copy(qry->zone_cut.key, parent->zone_cut.pool);
		if (!parent->zone_cut.key) {
			return KNOT_STATE_FAIL;
		}
		break;
	case KNOT_RRTYPE_DS:
		DEBUG_MSG(qry, "<= parent: updating DS\n");
		parent->zone_cut.trust_anchor = knot_rrset_copy(qry->zone_cut.trust_anchor, parent->zone_cut.pool);
		if (!parent->zone_cut.trust_anchor) {
			return KNOT_STATE_FAIL;
		}
		break;
	default: break;
	}
	return kr_ok();
}

static int update_delegation(struct kr_request *req, struct kr_query *qry, knot_pkt_t *answer, bool has_nsec3)
{
	struct kr_zonecut *cut = &qry->zone_cut;

	/* RFC4035 3.1.4. authoritative must send either DS or proof of non-existence.
	 * If it contains neither, the referral is bogus (or an attempted downgrade attack).
	 */

	/* Aggregate DS records (if using multiple keys) */
	unsigned section = KNOT_ANSWER;
	if (!knot_wire_get_aa(answer->wire)) { /* Referral */
		section = KNOT_AUTHORITY;
	} else if (knot_pkt_qtype(answer) == KNOT_RRTYPE_DS) { /* Subrequest */
		section = KNOT_ANSWER;
	} else { /* N/A */
		return kr_ok();
	}

	/* No DS provided, check for proof of non-existence. */
	int ret = 0;
	knot_rrset_t *new_ds = update_ds(cut, knot_pkt_section(answer, section));
	if (!new_ds) {
		if (has_nsec3) {
			ret = kr_nsec3_no_data_response_check(answer, section,
			      knot_pkt_qname(answer), KNOT_RRTYPE_DS);
		} else {
			ret = kr_nsec_no_data_response_check(answer, section,
			      knot_pkt_qname(answer), KNOT_RRTYPE_DS);
		}
		if (ret != 0) {
			DEBUG_MSG(qry, "<= bogus proof of DS non-existence\n");
			qry->flags |= QUERY_DNSSEC_BOGUS;
		} else {
			DEBUG_MSG(qry, "<= DS doesn't exist, going insecure\n");
			qry->flags &= ~QUERY_DNSSEC_WANT;
		}
		return ret;
	}

	/* Extend trust anchor */
	DEBUG_MSG(qry, "<= DS: OK\n");
	cut->trust_anchor = new_ds;
	return ret;
}

static int validate(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	int ret = 0;
	struct kr_request *req = ctx->data;
	struct kr_query *qry = kr_rplan_current(&req->rplan);
	/* Ignore faulty or unprocessed responses. */
	if (ctx->state & (KNOT_STATE_FAIL|KNOT_STATE_CONSUME)) {
		return ctx->state;
	}

	/* Pass-through if user doesn't want secure answer. */
	if (!(qry->flags & QUERY_DNSSEC_WANT)) {
		return ctx->state;
	}
	if (!(qry->flags & QUERY_CACHED) && !knot_pkt_has_dnssec(pkt)) {
		DEBUG_MSG(qry, "<= got insecure response\n");
		qry->flags |= QUERY_DNSSEC_BOGUS;
		return KNOT_STATE_FAIL;
	}

	/* Check if this is a DNSKEY answer, check trust chain and store. */
	uint16_t qtype = knot_pkt_qtype(pkt);
	bool has_nsec3 = _knot_pkt_has_type(pkt, KNOT_RRTYPE_NSEC3);
	if (qtype == KNOT_RRTYPE_DNSKEY) {
		ret = validate_keyset(qry, pkt, has_nsec3);
		if (ret != 0) {
			DEBUG_MSG(qry, "<= bad keys, broken trust chain\n");
			qry->flags |= QUERY_DNSSEC_BOGUS;
			return KNOT_STATE_FAIL;
		}
	}

	/* Check whether the current zone cut holds keys that can be used
	 * for validation (i.e. RRSIG signer name matches key owner).
	 */
	const knot_dname_t *key_own = qry->zone_cut.key ? qry->zone_cut.key->owner : NULL;
	const knot_dname_t *sig_name = first_rrsig_signer_name(pkt);
	if (key_own && sig_name && !knot_dname_is_equal(key_own, sig_name)) {
		/* @todo this sometimes causes duplicated data in answer, as the answer is
		 *       fetched again after we have a valid DS/DNSKEY, fix this */
		/* @todo for non-existence proofs, there may be only SOA and we need to fetch the
		 *       keys matching it instead of current cut */
		DEBUG_MSG(qry, ">< cut changed, needs revalidation\n");
		qry->flags &= ~QUERY_RESOLVED;
		return KNOT_STATE_CONSUME;
	}

	uint8_t pkt_rcode = knot_wire_get_rcode(pkt->wire);

	/* Validate non-existence proof if not positive answer. */
	if (pkt_rcode == KNOT_RCODE_NXDOMAIN) {
		/* @todo If knot_pkt_qname(pkt) is used instead of qry->sname then the test crash. */
		if (!has_nsec3) {
			ret = kr_nsec_name_error_response_check(pkt, KNOT_AUTHORITY, qry->sname, &req->pool);
		} else {
			ret = kr_nsec3_name_error_response_check(pkt, KNOT_AUTHORITY, qry->sname);
		}
		if (ret != 0) {
			DEBUG_MSG(qry, "<= bad NXDOMAIN proof\n");
			qry->flags |= QUERY_DNSSEC_BOGUS;
			return KNOT_STATE_FAIL;
		}
	}

	/* @todo WTH, this needs API that just tries to find a proof and the caller
	 * doesn't have to worry about NSEC/NSEC3
	 * @todo rework this */
	{
		const knot_pktsection_t *sec = knot_pkt_section(pkt, KNOT_ANSWER);
		uint16_t answer_count = sec ? sec->count : 0;

		/* Validate no data response. */
		if ((pkt_rcode == KNOT_RCODE_NOERROR) && (!answer_count) &&
		    (KNOT_WIRE_AA_MASK & knot_wire_get_flags1(pkt->wire))) {
			/* @todo
			 * ? quick mechanism to determine which check to preform first
			 * ? merge the functionality together to share code/resources
			 */
			if (!has_nsec3) {
				ret = kr_nsec_no_data_response_check(pkt, KNOT_AUTHORITY, knot_pkt_qname(pkt), knot_pkt_qtype(pkt));
				if (ret != 0) {
					ret = kr_nsec_wildcard_no_data_response_check(pkt, KNOT_AUTHORITY, knot_pkt_qname(pkt), knot_pkt_qtype(pkt));
				}
				if (ret != 0) {
					ret = kr_nsec_empty_nonterminal_response_check(pkt, KNOT_AUTHORITY, knot_pkt_qname(pkt));
				}
			} else {
				ret = kr_nsec3_no_data_response_check(pkt, KNOT_AUTHORITY, knot_pkt_qname(pkt), knot_pkt_qtype(pkt));
				if (ret != 0) {
					ret = kr_nsec3_wildcard_no_data_response_check(pkt, KNOT_AUTHORITY, knot_pkt_qname(pkt), knot_pkt_qtype(pkt));
				}
			}
			if (ret != 0) {
				DEBUG_MSG(qry, "<= bad no data response proof\n");
				qry->flags |= QUERY_DNSSEC_BOGUS;
				return KNOT_STATE_FAIL;
			}
		}
	}

	/* Validate all records, fail as bogus if it doesn't match.
	 * Do not revalidate data from cache, as it's already trusted. */
	if (!(qry->flags & QUERY_CACHED)) {
		ret = validate_records(qry, pkt, req->rplan.pool, has_nsec3);
		if (ret != 0) {
			DEBUG_MSG(qry, "<= couldn't validate RRSIGs\n");
			qry->flags |= QUERY_DNSSEC_BOGUS;
			return KNOT_STATE_FAIL;
		}
	}

	/* Check and update current delegation point security status. */
	ret = update_delegation(req, qry, pkt, has_nsec3);
	if (ret != 0) {
		return KNOT_STATE_FAIL;
	}
	/* Update parent query zone cut */
	if (qry->parent) {
		if (update_parent(qry, qtype) != 0) {
			return KNOT_STATE_FAIL;
		}
	}
	DEBUG_MSG(qry, "<= answer valid, OK\n");
	return ctx->state;
}
/** Module implementation. */
const knot_layer_api_t *validate_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.consume = &validate,
	};
	/* Store module reference */
	return &_layer;
}

int validate_init(struct kr_module *module)
{
	return kr_ok();
}

KR_MODULE_EXPORT(validate)
