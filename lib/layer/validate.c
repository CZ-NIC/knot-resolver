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
#include <ctype.h>
#include <sys/time.h>
#include <string.h>

#include <libknot/descriptor.h>
#include <libknot/internal/base64.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/rrtype/dnskey.h>
#include <libknot/rrtype/rrsig.h>

#include "lib/dnssec.h"
#include "lib/layer/iterate.h"
#include "lib/layer/validate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/defines.h"
#include "lib/nsrep.h"
#include "lib/module.h"

#define DEBUG_MSG(fmt...) QRDEBUG(qry, "vldr", fmt)

static int dname_parse(knot_dname_t **dname, const char *dname_str, mm_ctx_t *pool)
{
	if (!dname) {
		return kr_error(EINVAL);
	}

	knot_dname_t *owner = mm_alloc(pool, KNOT_DNAME_MAXLEN);
	if (owner == NULL) {
		return kr_error(ENOMEM);
	}
	knot_dname_t *aux = knot_dname_from_str(owner, dname_str, KNOT_DNAME_MAXLEN);
	if (aux == NULL) {
		mm_free(pool, owner);
		return kr_error(ENOMEM);
	}

	assert(!*dname);
	*dname = owner;
	return 0;
}

static int uint_parse(const char *str, unsigned *u)
{
	char *err_pos;
	long num = strtol(str, &err_pos, 10);
	if ((*err_pos != '\0') || (num < 0)) {
		return kr_error(EINVAL);
	}
	*u = (unsigned) num;
	return 0;
}

static int strcicmp(char const *a, char const *b)
{
	if (!a && !b) {
		return 0;
	}
	if (!a) {
		return -1;
	}
	if (!b) {
		return 1;
	}
	for ( ; ; ++a, ++b) {
		int d = tolower(*a) - tolower(*b);
		if ((d != 0) || (*a == '\0')) {
			return d;
		}
	}
}

static int algorithm_parse(const char *str, unsigned *u)
{
	int ret = uint_parse(str, u);
	if (ret == 0) {
		return 0;
	}

	const lookup_table_t *item = knot_dnssec_alg_names;
	while (item->id) {
		if (strcicmp(str, item->name) == 0) {
			break;
		}
		++item;
	}

	if (!item->id) {
		return kr_error(ENOENT);
	}

	*u = (unsigned) item->id;
	return 0;
}

static int hex2value(const char hex)
{
	if ((hex >= '0') && (hex <= '9')) {
		return hex - '0';
	} else if ((hex >= 'a') && (hex <= 'f')) {
		return hex - 'a' + 10;
	} else if ((hex >= 'A') && (hex <= 'F')) {
		return hex - 'A' + 10;
	} else {
		return -1;
	}
}

static int hex2byte(const char hex[2], uint8_t *u)
{
	int d0, d1;
	d0 = hex2value(hex[0]);
	d1 = hex2value(hex[1]);

	if ((d0 == -1) || (d1 == -1)) {
		return kr_error(EINVAL);
	}

	*u = ((d0 & 0x0f) << 4) | (d1 & 0x0f);
	return 0;
}

static int ta_ds_parse(uint8_t *rd, size_t *rd_written, size_t rd_maxsize, const char *seps, char **saveptr)
{
	if (!rd || !rd_written || !seps || !saveptr) {
		return kr_error(EINVAL);
	}

	int ret = 0;
	const char *token;
	unsigned aux;

	/* Key tag. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = uint_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint16_t key_tag = aux;

	/* Algorithm. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = algorithm_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint8_t algorithm = aux;

	/* Digest type. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = uint_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint8_t digest_type = aux;

	size_t rd_pos = 0;
	if (rd_maxsize >= 4) {
		* (uint16_t *) (rd + rd_pos) = htons(key_tag); rd_pos += 2;
		*(rd + rd_pos++) = algorithm;
		*(rd + rd_pos++) = digest_type;
	} else {
		return kr_error(EINVAL);
	}

	char hexbuf[2];
	int i = 0;
	while ((token = strtok_r(NULL, seps, saveptr)) != NULL) {
		for (int j = 0; j < strlen(token); ++j) {
			hexbuf[i++] = token[j];
			if (i == 2) {
				uint8_t byte;
				ret = hex2byte(hexbuf, &byte);
				if (ret != 0) {
					return ret;
				}
				i = 0;

				if (rd_pos < rd_maxsize) {
					*(rd + rd_pos++) = byte;
				} else {
					return kr_error(ENOMEM);
				}
			}
		}
	}

	if (i != 0) {
		return kr_error(EINVAL);
	}

	*rd_written = rd_pos;
	return 0;
}

static int base2bytes(const uint8_t base[4], uint8_t bytes[3], unsigned *valid)
{
	int32_t decoded = base64_decode(base, 4, bytes, 3);
	if (decoded < 0) {
		return kr_error(EINVAL);
	}
	*valid = decoded;
	return 0;
}

int ta_dnskey_parse(uint8_t *rd, size_t *rd_written, size_t rd_maxsize, const char *seps, char **saveptr)
{
	fprintf(stderr, "%s()\n", __func__);

	if (!rd || !rd_written || !seps || !saveptr) {
		return kr_error(EINVAL);
	}

	int ret = 0;
	const char *token;
	unsigned aux;

	/* Flags. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = uint_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint16_t flags = aux;

	/* Protocol. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = uint_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint8_t protocol = aux;
	if (protocol != 3) {
		return kr_error(EINVAL);
	}

	/* Algorithm. */
	token = strtok_r(NULL, seps, saveptr);
	if (!token) {
		return kr_error(EINVAL);
	}
	ret = algorithm_parse(token, &aux);
	if (ret != 0) {
		return ret;
	}
	uint8_t algorithm = aux;

	size_t rd_pos = 0;
	if (rd_maxsize >= 4) {
		* (uint16_t *) (rd + rd_pos) = htons(flags); rd_pos += 2;
		*(rd + rd_pos++) = protocol;
		*(rd + rd_pos++) = algorithm;
	} else {
		return kr_error(EINVAL);
	}

	uint8_t basebuf[4];
	uint8_t databuf[3];
	int i = 0;
	while ((token = strtok_r(NULL, seps, saveptr)) != NULL) {
		for (int j = 0; j < strlen(token); ++j) {
			basebuf[i++] = token[j];
			if (i == 4) {
				unsigned written;
				ret = base2bytes(basebuf, databuf, &written);
				if (ret != 0) {
					return ret;
				}
				i = 0;

				if ((rd_pos + written) < rd_maxsize) {
					memcpy(rd + rd_pos, databuf, written);
					rd_pos += written;
				} else {
					return kr_error(ENOMEM);
				}
			}
		}
	}

	if (i != 0) {
		return kr_error(EINVAL);
	}

	*rd_written = rd_pos;
	return 0;
}

int kr_ta_parse(knot_rrset_t **rr, const char *ds_str, mm_ctx_t *pool)
{
#define SEPARATORS " \t\n\r"
#define RDATA_MAXSIZE 640
	int ret = 0;

	if (!rr || !ds_str || !pool) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	char *ds_cpy = NULL;
	knot_dname_t *owner = NULL;
	knot_rdata_t *rdata = NULL;
	knot_rrset_t *ds_set = NULL;

	size_t ds_len = strlen(ds_str) + 1;
	ds_cpy = mm_alloc(pool, ds_len);
	if (!ds_cpy) {
		ret = kr_error(ENOMEM);
		goto fail;
	}
	memcpy(ds_cpy, ds_str, ds_len);
	char *saveptr = NULL, *token;

	/* Owner name. */
	token = strtok_r(ds_cpy, SEPARATORS, &saveptr);
	if (!token) {
		ret = kr_error(EINVAL);
		goto fail;
	}
	ret = dname_parse(&owner, token, pool);
	if (ret != 0) {
		goto fail;
	}

	/* Class. */
	uint16_t class;
	token = strtok_r(NULL, SEPARATORS, &saveptr);
	if (!token) {
		ret = kr_error(EINVAL);
		goto fail;
	}
	ret = knot_rrclass_from_string(token, &class);
	if (ret != 0) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	/* Type. */
	uint16_t type;
	token = strtok_r(NULL, SEPARATORS, &saveptr);
	if (!token) {
		ret = kr_error(EINVAL);
		goto fail;
	}
	ret = knot_rrtype_from_string(token, &type);
	if ((ret != 0) ||
	    ((type != KNOT_RRTYPE_DS) && (type != KNOT_RRTYPE_DNSKEY))) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	/* Construct RDATA. */
	rdata = mm_alloc(pool, RDATA_MAXSIZE);
	if (!rdata) {
		ret = kr_error(ENOMEM);
		goto fail;
	}
	size_t rd_written = 0;

	switch (type) {
	case KNOT_RRTYPE_DS:
		ret = ta_ds_parse(rdata, &rd_written, RDATA_MAXSIZE, SEPARATORS, &saveptr);
		break;
	case KNOT_RRTYPE_DNSKEY:
		ret = ta_dnskey_parse(rdata, &rd_written, RDATA_MAXSIZE, SEPARATORS, &saveptr);
		break;
	default:
		assert(0);
		ret = kr_error(EINVAL);
		break;
	}
	if (ret != 0) {
		goto fail;
	}

	ds_set = knot_rrset_new(owner, type, class, pool);
	if (!ds_set) {
		ret = kr_error(ENOMEM);
		goto fail;
	}

	ret = knot_rrset_add_rdata(ds_set, rdata, rd_written, 0, pool);
	if (ret != 0) {
		goto fail;
	}

	*rr = ds_set;
	ds_set = NULL;

fail:
	knot_rrset_free(&ds_set, pool);
	mm_free(pool, rdata);
	knot_dname_free(&owner, pool);
	mm_free(pool, ds_cpy);
	return ret;
#undef RDATA_MAXSIZE
#undef SEPARATORS
}

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
                            knot_section_t section_id, mm_ctx_t *pool)
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
		ret = kr_rrset_validate(sec, covered, qry->zone_cut.key, zone_name, qry->timestamp.tv_sec);
		if (ret != 0) {
			break;
		}
	}

fail:
	mm_free(stored.pool, stored.ids);
	knot_rrset_free(&covered, pool);
	return ret;
}

static int validate_records(struct kr_query *qry, knot_pkt_t *answer, mm_ctx_t *pool)
{
#warning TODO: validate RRSIGS (records with ZSK, keys with KSK), return FAIL if failed
	if (!qry->zone_cut.key) {
		DEBUG_MSG("<= no DNSKEY, can't validate\n");
		return kr_error(KNOT_DNSSEC_ENOKEY);
	}

	int ret;

	ret = validate_section(qry, answer, KNOT_ANSWER, pool);
	if (ret != 0) {
		return ret;
	}
	ret = validate_section(qry, answer, KNOT_AUTHORITY, pool);

	return ret;
}

static int validate_proof(struct kr_query *qry, knot_pkt_t *answer)
{
#warning TODO: validate NSECx proof, RRSIGs will be checked later if it matches
	return kr_ok();
}

static int validate_keyset(struct kr_query *qry, knot_pkt_t *answer)
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
	int ret = kr_dnskeys_trusted(an, qry->zone_cut.key, qry->zone_cut.trust_anchor, qry->zone_cut.name, qry->timestamp.tv_sec);
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

	DEBUG_MSG("<= referral, checking DS\n");

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

	/* Server didn't copy back DO=1, this is okay if it doesn't have DS => insecure.
	 * If it has DS, it must be secured, fail it as bogus. */
	if (!knot_pkt_has_dnssec(pkt)) {
		DEBUG_MSG("<= asked with DO=1, got insecure response\n");
#warning TODO: fail and retry if it has TA, otherwise flag as INSECURE and continue
		return KNOT_STATE_FAIL;
	}

	/* Validate non-existence proof if not positive answer. */
	if (knot_wire_get_rcode(pkt->wire) == KNOT_RCODE_NXDOMAIN) {
		ret = validate_proof(qry, pkt);
		if (ret != 0) {
			DEBUG_MSG("<= bad NXDOMAIN proof\n");
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
			DEBUG_MSG("Missing trust anchor.\n");
#warning TODO: the trust anchor must be fetched from a configurable storage
			if (qry->zone_cut.name[0] == '\0') {
				kr_ta_parse(&qry->zone_cut.trust_anchor, ROOT_TA, qry->zone_cut.pool);
			}
		}

		ret = validate_keyset(qry, pkt);
		if (ret != 0) {
			DEBUG_MSG("<= bad keys, broken trust chain\n");
			qry->flags |= QUERY_DNSSEC_BOGUS;
			return KNOT_STATE_FAIL;
		}
	}

	/* Validate all records, fail as bogus if it doesn't match. */
	ret = validate_records(qry, pkt, req->rplan.pool);
	if (ret != 0) {
		DEBUG_MSG("<= couldn't validate RRSIGs\n");
		qry->flags |= QUERY_DNSSEC_BOGUS;
		return KNOT_STATE_FAIL;
	}

	/* Update trust anchor. */
	ret = update_delegation(qry, pkt);
	if (ret != 0) {
		return KNOT_STATE_FAIL;
	}

	if ((qtype == KNOT_RRTYPE_DS) && (qry->parent != NULL) && (qry->parent->zone_cut.trust_anchor == NULL)) {
		DEBUG_MSG("updating trust anchor in zone cut\n");
		qry->parent->zone_cut.trust_anchor = knot_rrset_copy(qry->zone_cut.trust_anchor, qry->parent->zone_cut.pool);
		if (!qry->parent->zone_cut.trust_anchor) {
			return KNOT_STATE_FAIL;
		}
		/* Update zone cut name */
		mm_free(qry->parent->zone_cut.pool, qry->parent->zone_cut.name);
		qry->parent->zone_cut.name = knot_dname_copy(qry->zone_cut.trust_anchor->owner, qry->parent->zone_cut.pool);
	}
	if ((qtype == KNOT_RRTYPE_DNSKEY) && (qry->parent != NULL) && (qry->parent->zone_cut.key == NULL)) {
		DEBUG_MSG("updating keys in zone cut\n");
		qry->parent->zone_cut.key = knot_rrset_copy(qry->zone_cut.key, qry->parent->zone_cut.pool);
		if (!qry->parent->zone_cut.key) {
			return KNOT_STATE_FAIL;
		}
	}

	DEBUG_MSG("<= answer valid, OK\n");
	return ctx->state;
}

/** Module implementation. */
const knot_layer_api_t *validate_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.begin = &begin,
		.consume = &validate,
	};
	return &_layer;
}

KR_MODULE_EXPORT(validate)
