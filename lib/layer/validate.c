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
#include <libknot/rrtype/rdname.h>
#include <libknot/rrtype/dnskey.h>

#include "lib/layer/iterate.h"
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

int kr_ta_parse(knot_rrset_t **rr, const char *ds_str, mm_ctx_t *pool)
{
#define SEPARATORS " \t\n\r"
#define RDATA_MAXSIZE 640
	int ret = 0;
	unsigned aux;

	if (!rr || !ds_str || !pool) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	size_t ds_len = strlen(ds_str) + 1;
	char *ds_cpy = mm_alloc(pool, ds_len);
	if (!ds_cpy) {
		ret = kr_error(ENOMEM);
		goto fail;
	}
	memcpy(ds_cpy, ds_str, ds_len);
	char *saveptr = NULL, *token;

	/* Owner name. */
	knot_dname_t *owner = NULL;
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
	if ((ret != 0) || (type != KNOT_RRTYPE_DS)) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	/* Key tag. */
	token = strtok_r(NULL, SEPARATORS, &saveptr);
	if (!token) {
		ret = kr_error(EINVAL);
		goto fail;
	}
	ret = uint_parse(token, &aux);
	if (ret != 0) {
		goto fail;
	}
	uint16_t key_tag = aux;

	/* Algorithm. */
	token = strtok_r(NULL, SEPARATORS, &saveptr);
	if (!token) {
		ret = kr_error(EINVAL);
		goto fail;
	}
	ret = algorithm_parse(token, &aux);
	if (ret != 0) {
		goto fail;
	}
	uint8_t algorithm = aux;

	/* Digest type. */
	token = strtok_r(NULL, SEPARATORS, &saveptr);
	if (!token) {
		ret = kr_error(EINVAL);
		goto fail;
	}
	ret = uint_parse(token, &aux);
	if (ret != 0) {
		goto fail;
	}
	uint8_t digest_type = aux;

	/* Construct RDATA. */
	knot_rdata_t *rdata = mm_alloc(pool, RDATA_MAXSIZE);
	if (!rdata) {
		ret = kr_error(ENOMEM);
		goto fail;
	}
	size_t rd_pos = 0;
	uint8_t *rd = rdata;

	* (uint16_t *) (rd + rd_pos) = htons(key_tag); rd_pos += 2;
	*(rd + rd_pos++) = algorithm;
	*(rd + rd_pos++) = digest_type;

	char hexbuf[2];
	int i = 0;
	while ((token = strtok_r(NULL, SEPARATORS, &saveptr)) != NULL) {
		for (int j = 0; j < strlen(token); ++j) {
			hexbuf[i++] = token[j];
			if (i == 2) {
				uint8_t byte;
				ret = hex2byte(hexbuf, &byte);
				if (ret != 0) {
					goto fail;
				}
				i = 0;

				if (rd_pos < RDATA_MAXSIZE) {
					*(rd + rd_pos++) = byte;
				} else {
					ret = kr_error(ENOMEM);
					goto fail;
				}
			}
		}
	}

	if (i != 0) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	knot_rrset_t *ds_set = knot_rrset_new(owner, type, class, pool);
	if (!ds_set) {
		ret = kr_error(ENOMEM);
		goto fail;
	}

	ret = knot_rrset_add_rdata(ds_set, rdata, rd_pos, 0, pool);
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

#if 0
static int secure_query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_request *req = ctx->data;
	struct kr_query *query = kr_rplan_current(&req->rplan);
	if (ctx->state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
		return ctx->state;
	}

	if (query->zone_cut.key == NULL) {
/*
		query->flags |= QUERY_AWAIT_TRUST;

		DEBUG_MSG("%s() A002 '%s'\n", __func__, knot_pkt_qname(pkt));

		struct knot_rrset *opt_rr = knot_rrset_copy(req->answer->opt_rr, &pkt->mm);
		if (opt_rr == NULL) {
			return KNOT_STATE_FAIL;
		}
		knot_pkt_clear(pkt);
		int ret = knot_pkt_put_question(pkt, query->zone_cut.name, query->sclass, KNOT_RRTYPE_DNSKEY);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&opt_rr, &pkt->mm);
			return KNOT_STATE_FAIL;
		}
		knot_pkt_begin(pkt, KNOT_ADDITIONAL);
		knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, opt_rr, KNOT_PF_FREE);

		{
		char name_str[KNOT_DNAME_MAXLEN], type_str[16];
		knot_dname_to_str(name_str, knot_pkt_qname(pkt), sizeof(name_str));
		knot_rrtype_to_string(knot_pkt_qtype(pkt), type_str, sizeof(type_str));
		DEBUG_MSG("%s() A003 '%s %s'\n", __func__, name_str, type_str);
		}

		return KNOT_STATE_CONSUME;
*/
	}

	DEBUG_MSG("%s() A004\n", __func__);

#if 0
	/* Copy query EDNS options and request DNSKEY for current cut. */
	pkt->opt_rr = knot_rrset_copy(req->answer->opt_rr, &pkt->mm);
	query->flags |= QUERY_AWAIT_TRUST;
#warning TODO: check if we already have valid DNSKEY in zone cut, otherwise request it from the resolver
#warning FLOW: since first query doesnt have it, resolve.c will catch this and issue subrequest for it
	/* Write OPT to additional section */
	knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, pkt->opt_rr, KNOT_PF_FREE);

	return KNOT_STATE_CONSUME;
#endif
	return ctx->state;
}
#endif

static int validate_records(struct kr_query *qry, knot_pkt_t *answer)
{
#warning TODO: validate RRSIGS (records with ZSK, keys with KSK), return FAIL if failed
	if (!qry->zone_cut.key) {
		DEBUG_MSG("<= no DNSKEY, can't validate\n");
	}

	DEBUG_MSG("!! validation not implemented\n");
	return kr_error(ENOSYS);
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
		if (rr->type == KNOT_RRTYPE_DNSKEY) {
			DEBUG_MSG("+= DNSKEY flags: %hu algo: %x\n",
				knot_dnskey_flags(&rr->rrs, 0),
				0xff & knot_dnskey_alg(&rr->rrs, 0));
#warning TODO: merge with zone cut 'key' RRSet
		}
	}
	/* Check if there's a key for current TA. */
#warning TODO: check if there is a DNSKEY we can trust (matching current TA)
	return kr_ok();
}

static int update_delegation(struct kr_query *qry, knot_pkt_t *answer)
{
	DEBUG_MSG("<= referral, checking DS\n");
#warning TODO: delegation, check DS record presence
	return kr_ok();
}

static int validate(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	int ret = 0;
	struct kr_request *req = ctx->data;
	struct kr_query *qry = kr_rplan_current(&req->rplan);
	if (ctx->state & KNOT_STATE_FAIL) {
		return ctx->state;
	}

	/* Pass-through if user doesn't want secure answer. */
	if (!(req->flags & KR_REQ_DNSSEC)) {
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

	/* Check if this is a DNSKEY answer, check trust chain and store. */
	uint16_t qtype = knot_pkt_qtype(pkt);
	if (qtype == KNOT_RRTYPE_DNSKEY) {
		ret = validate_keyset(qry, pkt);
		if (ret != 0) {
			DEBUG_MSG("<= bad keys, broken trust chain\n");
			qry->flags |= QUERY_DNSSEC_BOGUS;
			return KNOT_STATE_FAIL;
		}
	/* Update trust anchor. */
	} else if (qtype == KNOT_RRTYPE_NS) {
		update_delegation(qry, pkt);
	}

	/* Validate all records, fail as bogus if it doesn't match. */
	ret = validate_records(qry, pkt);
	if (ret != 0) {
		DEBUG_MSG("<= couldn't validate RRSIGs\n");
		qry->flags |= QUERY_DNSSEC_BOGUS;
		return KNOT_STATE_FAIL;
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
