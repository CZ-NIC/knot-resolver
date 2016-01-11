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
#include "lib/dnssec.h"
#include "lib/layer.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/utils.h"
#include "lib/defines.h"
#include "lib/module.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "vldr", fmt)

/**
 * Search in section for given type.
 * @param sec  Packet section.
 * @param type Type to search for.
 * @return     True if found.
 */
static bool section_has_type(const knot_pktsection_t *sec, uint16_t type)
{
	if (!sec) {
		return false;
	}

	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(sec, i);
		if (rr->type == type) {
			return true;
		}
	}

	return false;
}

static bool pkt_has_type(const knot_pkt_t *pkt, uint16_t type)
{
	if (!pkt) {
		return false;
	}

	if (section_has_type(knot_pkt_section(pkt, KNOT_ANSWER), type)) {
		return true;
	}
	if (section_has_type(knot_pkt_section(pkt, KNOT_AUTHORITY), type)) {
		return true;
	}
	return section_has_type(knot_pkt_section(pkt, KNOT_ADDITIONAL), type);
}


/** @internal Baton for validate_section */
struct validate_baton {
	const knot_pkt_t *pkt;
	knot_section_t section_id;
	const knot_rrset_t *keys;
	const knot_dname_t *zone_name;
	uint32_t timestamp;
	bool has_nsec3;
	int result;
};

static int validate_rrset(const char *key, void *val, void *data)
{
	knot_rrset_t *rr = val;
	struct validate_baton *baton = data;

	if (baton->result != 0) {
		return baton->result;
	}
	baton->result = kr_rrset_validate(baton->pkt, baton->section_id, rr,
	                                  baton->keys, baton->zone_name,
	                                  baton->timestamp, baton->has_nsec3);
	return baton->result;
}

static int validate_section(struct kr_query *qry, knot_pkt_t *answer,
                            knot_section_t section_id, knot_mm_t *pool,
                            bool has_nsec3)
{
	const knot_pktsection_t *sec = knot_pkt_section(answer, section_id);
	if (!sec) {
		return kr_ok();
	}

	int ret = kr_ok();

	map_t stash = map_make();
	stash.malloc = (map_alloc_f) mm_alloc;
	stash.free = (map_free_f) mm_free;
	stash.baton = pool;

	/* Determine RR types contained in the section. */
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(sec, i);
		if (rr->type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		if ((rr->type == KNOT_RRTYPE_NS) && (section_id == KNOT_AUTHORITY)) {
			continue;
		}
		/* Only validate answers from current cut, records above the cut are stripped. */
		if (section_id == KNOT_ANSWER && !knot_dname_in(qry->zone_cut.name, rr->owner)) {
			continue;
		}
		ret = kr_rrmap_add(&stash, rr, 0, pool);
		if (ret != 0) {
			goto fail;
		}
	}

	struct validate_baton baton = {
		.pkt = answer,
		.section_id = section_id,
		.keys = qry->zone_cut.key,
		/* Can't use qry->zone_cut.name directly, as this name can
		 * change when updating cut information before validation.
		 */
		.zone_name = qry->zone_cut.key ? qry->zone_cut.key->owner : NULL,
		.timestamp = qry->timestamp.tv_sec,
		.has_nsec3 = has_nsec3,
		.result = 0
	};

	ret = map_walk(&stash, &validate_rrset, &baton);
	if (ret != 0) {
		return ret;
	}
	ret = baton.result;

fail:
	return ret;
}

static int validate_records(struct kr_query *qry, knot_pkt_t *answer, knot_mm_t *pool, bool has_nsec3)
{
	if (!qry->zone_cut.key) {
		DEBUG_MSG(qry, "<= no DNSKEY, can't validate\n");
		return kr_error(EBADMSG);
	}

	int ret = validate_section(qry, answer, KNOT_ANSWER, pool, has_nsec3);
	if (ret != 0) {
		return ret;
	}

	return validate_section(qry, answer, KNOT_AUTHORITY, pool, has_nsec3);
}

static int validate_keyset(struct kr_query *qry, knot_pkt_t *answer, bool has_nsec3)
{
	/* Merge DNSKEY records from answer that are below/at current cut. */
	bool updated_key = false;
	const knot_pktsection_t *an = knot_pkt_section(answer, KNOT_ANSWER);
	for (unsigned i = 0; i < an->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(an, i);
		if ((rr->type != KNOT_RRTYPE_DNSKEY) || !knot_dname_in(qry->zone_cut.name, rr->owner)) {
			continue;
		}
		/* Merge with zone cut (or replace ancestor key). */
		if (!qry->zone_cut.key || !knot_dname_is_equal(qry->zone_cut.key->owner, rr->owner)) {
			qry->zone_cut.key = knot_rrset_copy(rr, qry->zone_cut.pool);
			if (!qry->zone_cut.key) {
				return kr_error(ENOMEM);
			}
			updated_key = true;
		} else {
			int ret = knot_rdataset_merge(&qry->zone_cut.key->rrs,
			                              &rr->rrs, qry->zone_cut.pool);
			if (ret != 0) {
				knot_rrset_free(&qry->zone_cut.key, qry->zone_cut.pool);
				return ret;
			}
			updated_key = true;
		}
	}

	/* Check if there's a key for current TA. */
	if (updated_key && !(qry->flags & QUERY_CACHED)) {
		int ret = kr_dnskeys_trusted(answer, KNOT_ANSWER, qry->zone_cut.key,
		                             qry->zone_cut.trust_anchor, qry->zone_cut.name,
		                             qry->timestamp.tv_sec, has_nsec3);
		if (ret != 0) {
			knot_rrset_free(&qry->zone_cut.key, qry->zone_cut.pool);
			return ret;
		}
	}
	return kr_ok();
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

static int update_parent_keys(struct kr_query *qry, uint16_t answer_type)
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
		if (qry->flags & QUERY_DNSSEC_INSECURE) { /* DS non-existence proven. */
			parent->flags &= ~QUERY_DNSSEC_WANT;
			parent->flags |= QUERY_DNSSEC_INSECURE;
		} else { /* DS existence proven. */
			parent->zone_cut.trust_anchor = knot_rrset_copy(qry->zone_cut.trust_anchor, parent->zone_cut.pool);
			if (!parent->zone_cut.trust_anchor) {
				return KNOT_STATE_FAIL;
			}
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
	const knot_dname_t *proved_name = qry->zone_cut.name;
	knot_rrset_t *new_ds = update_ds(cut, knot_pkt_section(answer, section));
	if (!new_ds) {
		if (!has_nsec3) {
			ret = kr_nsec_existence_denial(answer, KNOT_AUTHORITY, proved_name, KNOT_RRTYPE_DS);
		} else {
			ret = kr_nsec3_no_data(answer, KNOT_AUTHORITY, proved_name, KNOT_RRTYPE_DS);
		}
		if (ret != 0) {
			DEBUG_MSG(qry, "<= bogus proof of DS non-existence\n");
			qry->flags |= QUERY_DNSSEC_BOGUS;
		} else {
			DEBUG_MSG(qry, "<= DS doesn't exist, going insecure\n");
			qry->flags &= ~QUERY_DNSSEC_WANT;
			qry->flags |= QUERY_DNSSEC_INSECURE;
		}
		return ret;
	}

	/* Extend trust anchor */
	DEBUG_MSG(qry, "<= DS: OK\n");
	cut->trust_anchor = new_ds;
	return ret;
}

static const knot_dname_t *signature_authority(knot_pkt_t *pkt)
{
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_AUTHORITY; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			if (rr->type == KNOT_RRTYPE_RRSIG) {
				return knot_rrsig_signer_name(&rr->rrs, 0);
			}
		}
	}
	return NULL;
}

static int validate(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	int ret = 0;
	struct kr_request *req = ctx->data;
	struct kr_query *qry = req->current_query;
	/* Ignore faulty or unprocessed responses. */
	if (ctx->state & (KNOT_STATE_FAIL|KNOT_STATE_CONSUME)) {
		return ctx->state;
	}

	/* Pass-through if user doesn't want secure answer or stub. */
	/* @todo: Validating stub resolver mode. */
	if (!(qry->flags & QUERY_DNSSEC_WANT) || (qry->flags & QUERY_STUB)) {
		return ctx->state;
	}
	/* Answer for RRSIG may not set DO=1, but all records MUST still validate. */
	bool use_signatures = (knot_pkt_qtype(pkt) != KNOT_RRTYPE_RRSIG);
	if (!(qry->flags & QUERY_CACHED) && !knot_pkt_has_dnssec(pkt) && !use_signatures) {
		DEBUG_MSG(qry, "<= got insecure response\n");
		qry->flags |= QUERY_DNSSEC_BOGUS;
		return KNOT_STATE_FAIL;
	}

	/* Track difference between current TA and signer name.
	 * This indicates that the NS is auth for both parent-child, and we must update DS/DNSKEY to validate it.
	 */
	const bool track_pc_change = (!(qry->flags & QUERY_CACHED) && (qry->flags & QUERY_DNSSEC_WANT));
	const knot_dname_t *ta_name = qry->zone_cut.trust_anchor ? qry->zone_cut.trust_anchor->owner : NULL;
	const knot_dname_t *signer = signature_authority(pkt);
	if (track_pc_change && ta_name && (!signer || !knot_dname_is_equal(ta_name, signer))) {
		if (ctx->state == KNOT_STATE_YIELD) { /* Already yielded for revalidation. */
			return KNOT_STATE_FAIL;
		}
		DEBUG_MSG(qry, ">< cut changed, needs revalidation\n");
		if (!signer) {
			/* Not a DNSSEC-signed response, ask parent for DS to prove transition to INSECURE. */
		} else if (knot_dname_is_sub(signer, qry->zone_cut.name)) {
			/* Key signer is below current cut, advance and refetch keys. */
			qry->zone_cut.name = knot_dname_copy(signer, &req->pool);
		} else if (!knot_dname_is_equal(signer, qry->zone_cut.name)) {
			/* Key signer is above the current cut, so we can't validate it. This happens when
			   a server is authoritative for both grandparent, parent and child zone.
			   Ascend to parent cut, and refetch authority for signer. */
			if (qry->zone_cut.parent) {
				memcpy(&qry->zone_cut, qry->zone_cut.parent, sizeof(qry->zone_cut));
			} else {
				qry->flags |= QUERY_AWAIT_CUT;
			}
			qry->zone_cut.name = knot_dname_copy(signer, &req->pool);
		} /* else zone cut matches, but DS/DNSKEY doesn't => refetch. */
		return KNOT_STATE_YIELD;
	}
	
	/* Check if this is a DNSKEY answer, check trust chain and store. */
	uint8_t pkt_rcode = knot_wire_get_rcode(pkt->wire);
	uint16_t qtype = knot_pkt_qtype(pkt);
	bool has_nsec3 = pkt_has_type(pkt, KNOT_RRTYPE_NSEC3);
	if (knot_wire_get_aa(pkt->wire) && qtype == KNOT_RRTYPE_DNSKEY) {
		ret = validate_keyset(qry, pkt, has_nsec3);
		if (ret != 0) {
			DEBUG_MSG(qry, "<= bad keys, broken trust chain\n");
			qry->flags |= QUERY_DNSSEC_BOGUS;
			return KNOT_STATE_FAIL;
		}
	}

	/* Validate non-existence proof if not positive answer. */
	if (!(qry->flags & QUERY_CACHED) && pkt_rcode == KNOT_RCODE_NXDOMAIN) {
		/* @todo If knot_pkt_qname(pkt) is used instead of qry->sname then the tests crash. */
		if (!has_nsec3) {
			ret = kr_nsec_name_error_response_check(pkt, KNOT_AUTHORITY, qry->sname);
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
	if (!(qry->flags & QUERY_CACHED)) {
		const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
		if (pkt_rcode == KNOT_RCODE_NOERROR && an->count == 0 && knot_wire_get_aa(pkt->wire)) { 
			/* @todo
			 * ? quick mechanism to determine which check to preform first
			 * ? merge the functionality together to share code/resources
			 */
			if (!has_nsec3) {
				ret = kr_nsec_existence_denial(pkt, KNOT_AUTHORITY, knot_pkt_qname(pkt), knot_pkt_qtype(pkt));
			} else {
				ret = kr_nsec3_no_data(pkt, KNOT_AUTHORITY, knot_pkt_qname(pkt), knot_pkt_qtype(pkt));
			}
			if (ret != 0) {
				DEBUG_MSG(qry, "<= bad NODATA proof\n");
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
		if (update_parent_keys(qry, qtype) != 0) {
			return KNOT_STATE_FAIL;
		}
	}
	DEBUG_MSG(qry, "<= answer valid, OK\n");
	return KNOT_STATE_DONE;
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

#undef DEBUG_MSG
