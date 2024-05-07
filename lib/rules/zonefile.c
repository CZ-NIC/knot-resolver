/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
/** @file
 *
 * Code for loading rules from some kinds of zonefile, e.g. RPZ.
 */

#include "lib/rules/api.h"
#include "lib/rules/impl.h"

#include "lib/log.h"
#include "lib/utils.h"
#include "lib/generic/trie.h"

#include <libzscanner/scanner.h>

/// State used in zs_scanner_t::process.data
typedef struct {
	const struct kr_rule_zonefile_config *c; /// owned by the caller
	trie_t *rrs; /// map: local_data_key() -> knot_rrset_t  where we only use .ttl and .rrs
	knot_mm_t *pool; /// used for everything inside s_data_t (unless noted otherwise)

	// state data for owner_relativize()
	const knot_dname_t *origin_soa;
	bool seen_record, warned_soa, warned_bailiwick;
} s_data_t;

//TODO: logs should better include file name and position within


/// Process scanned RR of other types, gather RRsets in a map.
static void rr_scan2trie(zs_scanner_t *s)
{
	s_data_t *s_data = s->process.data;
	uint8_t key_data[KEY_MAXLEN];
	knot_rrset_t rrs_for_key = {
		.owner = s->r_owner,
		.type = s->r_type,
	};
	knot_db_val_t key = local_data_key(&rrs_for_key, key_data, RULESET_DEFAULT);
	trie_val_t *rr_p = trie_get_ins(s_data->rrs, key.data, key.len);
	knot_rrset_t *rr;
	if (*rr_p) {
		rr = *rr_p;
		if (s->r_ttl < rr->ttl)
			rr->ttl = s->r_ttl; // we could also warn here
	} else {
		rr = *rr_p = mm_alloc(s_data->pool, sizeof(*rr));
		knot_rrset_init(rr, NULL, s->r_type, KNOT_CLASS_IN, s->r_ttl);
			// we don't ^^ need owner so save allocation
	}
	knot_rrset_add_rdata(rr, s->r_data, s->r_data_length, s_data->pool);
}
/// Process an RRset of other types into a rule
static int rr_trie2rule(const char *key_data, uint32_t key_len, trie_val_t *rr_p, void *config)
{
	const knot_db_val_t key = { .data = (void *)key_data, .len = key_len };
	const knot_rrset_t *rr = *rr_p;
	const struct kr_rule_zonefile_config *c = config;
	return local_data_ins(key, rr, NULL, c->tags);
	//TODO: check error logging path here (LMDB)
}

/// Process a scanned CNAME RR into a rule
static void cname_scan2rule(zs_scanner_t *s)
{
	s_data_t *s_data = s->process.data;
	const struct kr_rule_zonefile_config *c = s_data->c;

	const char *last_label = NULL; // last label of the CNAME
	for (knot_dname_t *dn = s->r_data; *dn != '\0'; dn += 1 + *dn)
		last_label = (const char *)dn + 1;
	if (last_label && strncmp(last_label, "rpz-", 4) == 0) {
		kr_log_warning(RULES, "skipping unsupported CNAME target .%s\n", last_label);
		return;
	}
	int ret = 0;
	if (s->r_data[0] == 0) { // "CNAME ." i.e. NXDOMAIN
		const knot_dname_t *apex = s->r_owner;
		if (knot_dname_is_wildcard(apex))
			apex += 2;
		// RPZ_COMPAT: we NXDOMAIN the whole subtree regardless of being wildcard.
		// Exact RPZ semantics would be hard here, it makes more sense
		// to apply also to a subtree, and corresponding wildcard rule
		// usually accompanies this rule anyway.
		ret = kr_rule_local_subtree(apex, KR_RULE_SUB_NXDOMAIN, s->r_ttl, c->tags);
	} else if (knot_dname_is_wildcard(s->r_data) && s->r_data[2] == 0) {
		// "CNAME *." -> NODATA
		knot_dname_t *apex = s->r_owner;
		if (knot_dname_is_wildcard(apex)) {
			apex += 2;
			ret = kr_rule_local_subtree(apex, KR_RULE_SUB_NODATA,
							s->r_ttl, c->tags);
		} else { // using special kr_rule_ semantics of empty CNAME RRset
			knot_rrset_t rrs;
			knot_rrset_init(&rrs, apex, KNOT_RRTYPE_CNAME,
					KNOT_CLASS_IN, s->r_ttl);
			ret = kr_rule_local_data_ins(&rrs, NULL, c->tags);
		}
	} else {
		knot_dname_t *target = s->r_owner;
		knot_rrset_t rrs;
		knot_rrset_init(&rrs, target, KNOT_RRTYPE_CNAME, KNOT_CLASS_IN, s->r_ttl);
		// TODO: implement wildcard expansion for target
		ret = knot_rrset_add_rdata(&rrs, s->r_data, s->r_data_length, NULL);
		if (!ret) ret = kr_rule_local_data_ins(&rrs, NULL, c->tags);
		knot_rdataset_clear(&rrs.rrs, NULL);
	}
	if (ret)
		kr_log_warning(RULES, "failure code %d\n", ret);
}

/// Relativize s->r_owner if suitable.  (Also react to SOA.)  Return false to skip RR.
static bool owner_relativize(zs_scanner_t *s)
{
	s_data_t *d = s->process.data;
	if (!d->c->is_rpz)
		return true;

	// $ORIGIN as fallback if SOA is missing
	const knot_dname_t *apex = d->origin_soa;
	if (!apex)
		apex = s->zone_origin;

	// SOA determines the zone apex, but lots of error/warn cases
	if (s->r_type == KNOT_RRTYPE_SOA) {
		if (d->seen_record && !knot_dname_is_equal(apex, s->r_owner)) {
			// We most likely inserted some rules wrong already, so abort.
			kr_log_error(RULES,
				"SOA encountered late, with unexpected owner; aborting\n");
			s->state = ZS_STATE_STOP;
			return false;
		}
		if (!d->warned_soa && d->origin_soa) {
			d->warned_soa = true;
			kr_log_warning(RULES, "ignoring repeated SOA record in a RPZ\n");
		} else if (!d->warned_soa && d->seen_record) {
			d->warned_soa = true;
			kr_log_warning(RULES,
				"SOA should come as the first record in a RPZ\n");
		}
		if (!d->origin_soa) // sticking with the first encountered SOA
			apex = d->origin_soa = knot_dname_copy(s->r_owner, d->pool);
	}
	d->seen_record = true;
	if (s->r_type == KNOT_RRTYPE_SOA)
		return false; // otherwise we'd insert `. SOA` record

	const int labels = knot_dname_in_bailiwick(s->r_owner, apex);
	if (labels < 0) {
		if (!d->warned_bailiwick) {
			d->warned_bailiwick = true;
			KR_DNAME_GET_STR(owner_str, s->r_owner);
			kr_log_warning(RULES,
				"skipping out-of-zone record(s); first name %s\n",
				owner_str);
		}
		return false;
	}
	const int len = kr_dname_prefixlen(s->r_owner, labels);
	s->r_owner[len] = '\0'; // not very nice but safe at this point
	return true;
}

/// Process a single scanned RR
static void process_record(zs_scanner_t *s)
{
	s_data_t *s_data = s->process.data;
	if (s->r_class != KNOT_CLASS_IN) {
		kr_log_warning(RULES, "skipping unsupported RR class\n");
		return;
	}

	// inspect the owner name
	const bool ok = knot_dname_size(s->r_owner) == strlen((const char *)s->r_owner) + 1;
	if (!ok) {
		kr_log_warning(RULES, "skipping zero-containing RR owner name\n");
		return;
	}
	// .rpz-* owner; sounds OK to warn and skip even for non-RPZ input
	//  TODO: support "rpz-client-ip"
	const char *last_label = NULL;
	for (knot_dname_t *dn = s->r_owner; *dn != '\0'; dn += 1 + *dn)
		last_label = (const char *)dn + 1;
	if (last_label && strncmp(last_label, "rpz-", 4) == 0) {
		kr_log_warning(RULES, "skipping unsupported RR owner .%s\n", last_label);
		return;
	}
	if (!owner_relativize(s))
		return;

	// RR type: mainly deal with various unsupported cases
	switch (s->r_type) {
	case KNOT_RRTYPE_RRSIG:
	case KNOT_RRTYPE_NSEC:
	case KNOT_RRTYPE_NSEC3:
	case KNOT_RRTYPE_DNSKEY:
	case KNOT_RRTYPE_DS:
	unsupported_type:
		(void)0; // C can't have a variable definition following a label
		KR_RRTYPE_GET_STR(type_str, s->r_type);
		kr_log_warning(RULES, "skipping unsupported RR type %s\n", type_str);
		return;
	}
	if (knot_rrtype_is_metatype(s->r_type))
		goto unsupported_type;
	// Especially the apex NS record in RPZ needs to be ignored.
	// That case is clear and silent.  For non-RPZ we assume the NS is desired.
	if (s->r_type == KNOT_RRTYPE_NS && s_data->c->is_rpz) {
		if (s->r_owner[0] != '\0') {
			auto_free char *owner_text = kr_dname_text(s->r_owner);
			// remove the final dot to hint that the name is relative to apex
			owner_text[strlen(owner_text) - 1] = '\0';
			kr_log_warning(RULES, "skipping `%s NS` record\n", owner_text);
		} else {
			kr_log_debug(RULES, "skipping apex NS\n");
		}
		return;
	}

	if (s_data->c->is_rpz && s->r_type == KNOT_RRTYPE_CNAME) {
		cname_scan2rule(s);
		return;
	}
	// Records in zonefile format generally may not be grouped by name and RR type,
	// so we accumulate RR sets in a trie and push them as rules at the end.
	rr_scan2trie(s);
}

int kr_rule_zonefile(const struct kr_rule_zonefile_config *c)
{
	ENSURE_the_rules;
	zs_scanner_t s_storage, *s = &s_storage;
	/* zs_init(), zs_set_input_file(), zs_set_processing() returns -1 in case of error,
	 * so don't print error code as it meaningless. */
	uint32_t ttl = c->ttl ? c->ttl : KR_RULE_TTL_DEFAULT; // 0 would be nonsense
	int ret = zs_init(s, NULL, KNOT_CLASS_IN, ttl);
	if (ret) {
		kr_log_error(RULES, "error initializing zone scanner instance, error: %i (%s)\n",
			     s->error.code, zs_strerror(s->error.code));
		return ret;
	}

	s_data_t s_data = { 0 };
	s_data.c = c;
	s_data.pool = mm_ctx_mempool2(64 * 1024);
	s_data.rrs = trie_create(s_data.pool);
	ret = zs_set_processing(s, process_record, NULL, &s_data);
	if (kr_fails_assert(ret == 0))
		goto finish;

	// set the input to parse
	if (c->filename) {
		kr_assert(!c->input_str && !c->input_len);
		ret = zs_set_input_file(s, c->filename);
		if (ret) {
			kr_log_error(RULES, "error opening zone file `%s`, error: %i (%s)\n",
				     c->filename, s->error.code, zs_strerror(s->error.code));
			goto finish;
		}
	} else {
		if (kr_fails_assert(c->input_str)) {
			ret = kr_error(EINVAL);
		} else {
			size_t len = c->input_len ? c->input_len : strlen(c->input_str);
			ret = zs_set_input_string(s, c->input_str, len);
		}
		if (ret) {
			kr_log_error(RULES, "error %d when opening input with rules\n", ret);
			goto finish;
		}
	}

	/* TODO: disable $INCLUDE?  In future RPZones could come from wherever.
	 * Automatic processing will do $INCLUDE, so perhaps use a manual loop instead?
	 */
	ret = zs_parse_all(s);
	if (ret != 0) {
		kr_log_error(RULES, "error parsing zone file `%s`, error %i: %s\n",
			c->filename, s->error.code, zs_strerror(s->error.code));
	} else if (s->state == ZS_STATE_STOP) { // interrupted inside
		ret = kr_error(EINVAL);
	} else { // no fatal error so far
		ret = trie_apply_with_key(s_data.rrs, rr_trie2rule, (void *)c);
	}
finish:
	zs_deinit(s);
	mm_ctx_delete(s_data.pool); // this also deletes whole s_data.rrs
	return ret;
}

