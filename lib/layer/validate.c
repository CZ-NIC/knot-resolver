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

#include <ccan/json/json.h>
#include <libknot/packet/wire.h>
#include <libknot/rrset-dump.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/rrtype/rrsig.h>

#include "lib/dnssec/nsec.h"
#include "lib/dnssec/nsec3.h"
#include "lib/dnssec/packet/pkt.h"
#include "lib/dnssec/ta.h"
#include "lib/dnssec.h"
#include "lib/layer.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/defines.h"
#include "lib/nsrep.h"
#include "lib/module.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "vldr", fmt)

static knot_dump_style_t KNOT_DUMP_STYLE_TA = {
	.wrap = false,
	.show_class = true,
	.show_ttl = false,
	.verbose = false,
	.empty_ttl = false,
	.human_ttl = false,
	.human_tmstamp = true,
	.ascii_to_idn = NULL
};

/* Set resolution context and parameters. */
static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return KNOT_STATE_PRODUCE;
}

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
		/* Merge with zone cut. */
		if (!qry->zone_cut.key) {
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

static int update_delegation(struct kr_query *qry, knot_pkt_t *answer)
{
	int ret = kr_ok();
	struct kr_zonecut *cut = &qry->zone_cut;

	DEBUG_MSG(qry, "<= referral, checking DS\n");

	/* New trust anchor. */
	knot_rrset_t *new_ds = NULL;
	knot_section_t section_id = (knot_pkt_qtype(answer) == KNOT_RRTYPE_DS) ? KNOT_ANSWER : KNOT_AUTHORITY;
	const knot_pktsection_t *sec = knot_pkt_section(answer, section_id);
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(sec, i);
		if ((rr->type != KNOT_RRTYPE_DS) ||
		    (0)) {
//		    (knot_dname_cmp(rr->owner, cut->name) != 0)) {
			continue;
		}
		if (new_ds) {
			ret = knot_rdataset_merge(&new_ds->rrs, &rr->rrs, cut->pool);
			if (ret != 0) {
				goto fail;
			}
		} else {
			new_ds = knot_rrset_copy(rr, cut->pool);
			if (!new_ds) {
				ret = kr_error(ENOMEM);
				goto fail;
			}
		}
	}

	if (new_ds) {
		knot_rrset_free(&cut->trust_anchor, cut->pool);
		cut->trust_anchor = new_ds;
		new_ds = NULL;

		/* It is very likely, that the keys don't match now. */
		knot_rrset_free(&cut->key, cut->pool);
	}

fail:
	knot_rrset_free(&new_ds, cut->pool);
	return ret;
}

static int validate(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	int ret;
	struct kr_request *req = ctx->data;
	struct kr_query *qry = kr_rplan_current(&req->rplan);
	if (ctx->state & KNOT_STATE_FAIL) {
		return ctx->state;
	}

	/* Pass-through if user doesn't want secure answer. */
	if (!(req->options & QUERY_DNSSEC_WANT)) {
		return ctx->state;
	}

	/* Ignore truncated messages. */
	if (knot_wire_get_tc(pkt->wire)) {
		return ctx->state;
	}

	/* Server didn't copy back DO=1, this is okay if it doesn't have DS => insecure.
	 * If it has DS, it must be secured, fail it as bogus. */
	if (!knot_pkt_has_dnssec(pkt)) {
		DEBUG_MSG(qry, "<= asked with DO=1, got insecure response\n");
#warning TODO: fail and retry if it has TA, otherwise flag as INSECURE and continue
		return KNOT_STATE_FAIL;
	}

	bool has_nsec3 = _knot_pkt_has_type(pkt, KNOT_RRTYPE_NSEC3);

	/* Validate non-existence proof if not positive answer. */
	if (knot_wire_get_rcode(pkt->wire) == KNOT_RCODE_NXDOMAIN) {
#warning TODO: validate NSECx proof, RRSIGs will be checked later if it matches
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

	/* Check whether the current zone cut holds keys that can be used
	 * for validation (i.e. RRSIG signer name matches key owner).
	 */
	const knot_dname_t *key_own = qry->zone_cut.key ? qry->zone_cut.key->owner : NULL;
	const knot_dname_t *sig_name = first_rrsig_signer_name(pkt);
	if (key_own && sig_name && !knot_dname_is_equal(key_own, sig_name)) {
		mm_free(qry->zone_cut.pool, qry->zone_cut.missing_name);
		qry->zone_cut.missing_name = knot_dname_copy(sig_name, qry->zone_cut.pool);
		if (!qry->zone_cut.missing_name) {
			return KNOT_STATE_FAIL;
		}
		qry->flags |= QUERY_AWAIT_DS;
		qry->flags &= ~QUERY_RESOLVED;
		return KNOT_STATE_CONSUME;
	}

	/* Check if this is a DNSKEY answer, check trust chain and store. */
	uint16_t qtype = knot_pkt_qtype(pkt);
	if (qtype == KNOT_RRTYPE_DNSKEY) {
		if (!qry->zone_cut.trust_anchor) {
			DEBUG_MSG(qry, "Missing trust anchor.\n");
#warning TODO: the trust anchor must be fetched from a configurable storage
			if (qry->zone_cut.name[0] == '\0') {
				kr_ta_get(&qry->zone_cut.trust_anchor, &global_trust_anchors, ROOT_NAME, qry->zone_cut.pool);
			}
		}

		ret = validate_keyset(qry, pkt, has_nsec3);
		if (ret != 0) {
			DEBUG_MSG(qry, "<= bad keys, broken trust chain\n");
			qry->flags |= QUERY_DNSSEC_BOGUS;
			return KNOT_STATE_FAIL;
		}
	}

	/* Validate all records, fail as bogus if it doesn't match. */
	ret = validate_records(qry, pkt, req->rplan.pool, has_nsec3);
	if (ret != 0) {
		DEBUG_MSG(qry, "<= couldn't validate RRSIGs\n");
		qry->flags |= QUERY_DNSSEC_BOGUS;
		return KNOT_STATE_FAIL;
	}

	/* Update trust anchor. */
	ret = update_delegation(qry, pkt);
	if (ret != 0) {
		return KNOT_STATE_FAIL;
	}

	if ((qtype == KNOT_RRTYPE_DS) && (qry->parent != NULL) && (qry->parent->zone_cut.trust_anchor == NULL)) {
		DEBUG_MSG(qry, "updating trust anchor in zone cut\n");
		qry->parent->zone_cut.trust_anchor = knot_rrset_copy(qry->zone_cut.trust_anchor, qry->parent->zone_cut.pool);
		if (!qry->parent->zone_cut.trust_anchor) {
			return KNOT_STATE_FAIL;
		}
		/* Update zone cut name */
		mm_free(qry->parent->zone_cut.pool, qry->parent->zone_cut.name);
		qry->parent->zone_cut.name = knot_dname_copy(qry->zone_cut.trust_anchor->owner, qry->parent->zone_cut.pool);
	}

	if ((qtype == KNOT_RRTYPE_DNSKEY) && (qry->parent != NULL) && (qry->parent->zone_cut.key == NULL)) {
		DEBUG_MSG(qry, "updating keys in zone cut\n");
		qry->parent->zone_cut.key = knot_rrset_copy(qry->zone_cut.key, qry->parent->zone_cut.pool);
		if (!qry->parent->zone_cut.key) {
			return KNOT_STATE_FAIL;
		}
	}

	DEBUG_MSG(qry, "<= answer valid, OK\n");
	return ctx->state;
}

static int rrset_txt_dump_line(const knot_rrset_t *rrset, size_t pos,
                               char *dst, const size_t maxlen, const knot_dump_style_t *style)
{
	assert(rrset && dst && maxlen && style);

	int written = 0;
	uint32_t ttl = knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, 0));
	int ret = knot_rrset_txt_dump_header(rrset, ttl, dst + written, maxlen - written, style);
	if (ret <= 0) {
		return ret;
	}
	written += ret;
	ret = knot_rrset_txt_dump_data(rrset, pos, dst + written, maxlen - written, style);
	if (ret <= 0) {
		return ret;
	}
	written += ret;

	return written;
}

static char *validate_trust_anchors(void *env, struct kr_module *module, const char *args)
{
#define MAX_BUF_LEN 1024
	JsonNode *root = json_mkarray();

	kr_ta_rdlock(&global_trust_anchors);

	const knot_rrset_t *ta;
	int count = kr_ta_rrs_count_nolock(&global_trust_anchors);
	for (int i = 0; i < count; ++i) {
		ta = NULL;
		kr_ta_rrs_at_nolock(&ta, &global_trust_anchors, i);
		assert(ta);
		char buf[MAX_BUF_LEN];
		for (uint16_t j = 0; j < ta->rrs.rr_count; ++j) {
			buf[0] = '\0';
			rrset_txt_dump_line(ta, j, buf, MAX_BUF_LEN, &KNOT_DUMP_STYLE_TA);
			json_append_element(root, json_mkstring(buf));
		}
	}

	kr_ta_unlock(&global_trust_anchors);

	char *result = json_encode(root);
	json_delete(root);
	return result;
#undef MAX_BUF_LEN
}

static char *validate_trust_anchor_add(void *env, struct kr_module *module, const char *args)
{
	int ret = 0;
	if (!args || (args[0] == '\0')) {
		ret = kr_error(EINVAL);
	} else {
		ret = kr_ta_add(&global_trust_anchors, args);
	}

	char *result = NULL;
	asprintf(&result, "{ \"result\": %s }", ret == 0 ? "true" : "false");
	return result;
}

static int load(struct trust_anchors *tas, const char *path)
{
#define MAX_LINE_LEN 512
	auto_fclose FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		DEBUG_MSG(NULL, "reading '%s' failed: %s\n", path, strerror(errno));
		return kr_error(errno);
	} else {
		DEBUG_MSG(NULL, "reading '%s'\n", path);
	}

	char line[MAX_LINE_LEN];
	while (fgets(line, sizeof(line), fp) != NULL) {
		int ret = kr_ta_add(tas, line);
		if (ret != 0) {
			return ret;
		}
	}

	return kr_ok();
#undef MAX_LINE_LEN
}

/** Module implementation. */
const knot_layer_api_t *validate_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.begin = &begin,
		.consume = &validate,
	};
	/* Store module reference */
	return &_layer;
}

int validate_init(struct kr_module *module)
{
	int ret = kr_ta_init(&global_trust_anchors);
	if (ret != 0) {
		return ret;
	}
//	/* Add root trust anchor. */
//	ret = kr_ta_add(&global_trust_anchors, ROOT_TA);
	if (ret != 0) {
		return ret;
	}
	return kr_ok();
}

#warning TODO: set root trust anchor from config
int validate_config(struct kr_module *module, const char *conf)
{
	int ret = kr_ta_reset(&global_trust_anchors, NULL);
	if (ret != 0) {
		return ret;
	}
	return load(&global_trust_anchors, conf);
}

int validate_deinit(struct kr_module *module)
{
	kr_ta_deinit(&global_trust_anchors);
	return kr_ok();
}

const struct kr_prop validate_prop_list[] = {
    { &validate_trust_anchors, "trust_anchors", "Retrieve trust anchors.", },
    { &validate_trust_anchor_add, "trust_anchor_add", "Adds a trust anchor.", },
    { NULL, NULL, NULL }
};

struct kr_prop *validate_props(void)
{
	return (struct kr_prop *) validate_prop_list;
}

KR_MODULE_EXPORT(validate)
