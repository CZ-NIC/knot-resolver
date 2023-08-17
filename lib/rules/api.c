/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/rules/api.h"
#include "lib/rules/impl.h"

#include "lib/cache/cdb_lmdb.h"

#include <stdlib.h>

struct kr_rules *the_rules = NULL;

/* DB key-space summary

 - "\0" starts special keys like "\0rulesets" or "\0stamp"
  - "\0tagBits" -> kr_rule_tags_t denoting the set of tags that have a name in DB
  - "\0tag_" + tag name -> one byte with the tag's number
 - some future additions?
 - otherwise it's rulesets - each has a prefix, e.g. RULESET_DEFAULT,
   its length is bounded by KEY_RULESET_MAXLEN - 1; after that prefix:
    - KEY_EXACT_MATCH + dname_lf ended by double '\0' + KNOT_RRTYPE_FOO
	-> exact-match rule (for the given name)
    - KEY_ZONELIKE_A  + dname_lf (no '\0' at end)
	-> zone-like apex (on the given name)
    - KEY_VIEW_SRC4 or KEY_VIEW_SRC6 + subnet_encode()
	-> action-rule string; see kr_view_insert_action()
 */

/*const*/ char RULESET_DEFAULT[] = "d";

static const uint8_t KEY_EXACT_MATCH[1] = "e";
static const uint8_t KEY_ZONELIKE_A [1] = "a";

static const uint8_t KEY_VIEW_SRC4[1] = "4";
static const uint8_t KEY_VIEW_SRC6[1] = "6";

static int answer_exact_match(struct kr_query *qry, knot_pkt_t *pkt, uint16_t type,
		const uint8_t *data, const uint8_t *data_bound);
static int answer_zla_empty(val_zla_type_t type, struct kr_query *qry, knot_pkt_t *pkt,
		knot_db_val_t zla_lf, uint32_t ttl);
static int answer_zla_redirect(struct kr_query *qry, knot_pkt_t *pkt, const char *ruleset_name,
				knot_db_val_t zla_lf, uint32_t ttl);

// LATER: doing tag_names_default() and kr_rule_tag_add() inside a RW transaction would be better.
static int tag_names_default(void)
{
	uint8_t key_tb_str[] = "\0tagBits";
	knot_db_val_t key = { .data = key_tb_str, .len = sizeof(key_tb_str) };
	knot_db_val_t val;
	// Check what's in there.
	int ret = ruledb_op(read, &key, &val, 1);
	if (ret == 0 && !kr_fails_assert(val.data && val.len == sizeof(kr_rule_tags_t)))
		return kr_ok(); // it's probably OK
	if (ret != kr_error(ENOENT))
		return kr_error(ret);
	kr_rule_tags_t empty = 0;
	val.data = &empty;
	val.len = sizeof(empty);
	return ruledb_op(write, &key, &val, 1);
}

int kr_rule_tag_add(const char *tag, kr_rule_tags_t *tagset)
{
	ENSURE_the_rules;
	// Construct the DB key.
	const uint8_t key_prefix[] = "\0tag_";
	knot_db_val_t key;
	knot_db_val_t val;
	const size_t tag_len = strlen(tag);
	key.len = sizeof(key_prefix) + tag_len;
	uint8_t key_buf[key.len];
	key.data = key_buf;
	memcpy(key_buf, key_prefix, sizeof(key_prefix));
	memcpy(key_buf + sizeof(key_prefix), tag, tag_len);

	int ret = ruledb_op(read, &key, &val, 1);
	if (ret == 0) { // tag exists already
		uint8_t *tindex_p = val.data;
		static_assert(KR_RULE_TAGS_CAP < (1 << 8 * sizeof(*tindex_p)),
				"bad combination of constants");
		if (kr_fails_assert(val.data && val.len == 1
					&& *tindex_p < KR_RULE_TAGS_CAP)) {
			kr_log_error(RULES, "ERROR: invalid length: %d\n", (int)val.len);
			return kr_error(EILSEQ);
		}
		*tagset |= (1 << *tindex_p);
		return kr_ok();
	} else if (ret != kr_error(ENOENT)) {
		return ret;
	}

	// We need to add it as a new tag.  First find the bitmap of named tags.
	uint8_t key_tb_str[] = "\0tagBits";
	knot_db_val_t key_tb = { .data = key_tb_str, .len = sizeof(key_tb_str) };
	ret = ruledb_op(read, &key_tb, &val, 1);
	if (ret != 0)
		return kr_error(ret);
	if (kr_fails_assert(val.data && val.len == sizeof(kr_rule_tags_t))) {
		kr_log_error(RULES, "ERROR: invalid length: %d\n", (int)val.len);
		return kr_error(EILSEQ);
	}
	kr_rule_tags_t bmp;
	memcpy(&bmp, val.data, sizeof(bmp));
	// Find a free index.
	static_assert(sizeof(long long) >= sizeof(bmp), "bad combination of constants");
	int ix = ffsll(~bmp) - 1;
	if (ix < 0 || ix >= 8 * sizeof(bmp))
		return kr_error(E2BIG);
	const kr_rule_tags_t tag_new = 1 << ix;
	kr_require((tag_new & bmp) == 0);

	// Update the mappings
	bmp |= tag_new;
	val.data = &bmp;
	val.len = sizeof(bmp);
	ret = ruledb_op(write, &key_tb, &val, 1);
	if (ret != 0)
		return kr_error(ret);
	uint8_t ix_8t = ix;
	val.data = &ix_8t;
	val.len = sizeof(ix_8t);
	ret = ruledb_op(write, &key, &val, 1); // key remained correct
	if (ret != 0)
		return kr_error(ret);
	*tagset |= tag_new;
	return kr_ok();
}


int kr_rules_init_ensure(void)
{
	if (the_rules)
		return kr_ok();
	return kr_rules_init(NULL, 0);
}
int kr_rules_init(const char *path, size_t maxsize)
{
	if (the_rules)
		return kr_error(EINVAL);
	the_rules = calloc(1, sizeof(*the_rules));
	kr_require(the_rules);
	the_rules->api = kr_cdb_lmdb();

	struct kr_cdb_opts opts = {
		.is_cache = false,
		.path = path ? path : "ruledb", // under current workdir
		// FIXME: the file will be sparse, but we still need to choose its size somehow.
		// Later we might improve it to auto-resize in case of running out of space.
		// Caveat: mdb_env_set_mapsize() can only be called without transactions open.
		.maxsize = maxsize ? maxsize : 100 * 1024*(size_t)1024,
	};
	int ret = the_rules->api->open(&the_rules->db, &the_rules->stats, &opts, NULL);
	/* No persistence - we always refill from config for now.
	 * LATER:
	 *  - Make it include versioning?
	 *  - "\0stamp" key when loading config(s)?
	 *  - Don't clear ruleset data that doesn't come directly from config;
	 *    and add marks for that, etc.
	 *    (after there actually are any kinds of rules like that)
	 */
	if (ret == 0) ret = ruledb_op(clear);
	if (ret != 0) goto failure;
	kr_require(the_rules->db);

	ret = tag_names_default();
	if (ret != 0) goto failure;

	ret = rules_defaults_insert();
	if (ret != 0) goto failure;

	/* Activate one default ruleset. */
	uint8_t key_rs[] = "\0rulesets";
	knot_db_val_t key = { .data = key_rs, .len = sizeof(key_rs) };
	knot_db_val_t rulesets = { .data = &RULESET_DEFAULT, .len = strlen(RULESET_DEFAULT) + 1 };
	ret = ruledb_op(write, &key, &rulesets, 1);
	if (ret == 0) return kr_ok();
failure:
	free(the_rules);
	the_rules = NULL;
	auto_free const char *path_abs = kr_absolutize_path(".", opts.path);
	kr_log_error(RULES, "failed while opening or initializing rule DB %s/\n", path_abs);
	return ret;
}

void kr_rules_deinit(void)
{
	if (!the_rules) return;
	ruledb_op(close);
	free(the_rules);
	the_rules = NULL;
}

int kr_rules_commit(bool accept)
{
	if (!the_rules) return kr_error(EINVAL);
	return ruledb_op(commit, accept);
}

static bool kr_rule_consume_tags(knot_db_val_t *val, const struct kr_request *req)
{
	kr_rule_tags_t tags;
	if (deserialize_fails_assert(val, &tags)) {
		val->len = 0;
		/* We may not fail immediately, but further processing
		 * will fail anyway due to zero remaining length. */
		return false;
	}
	return tags == KR_RULE_TAGS_ALL || (tags & req->rule_tags);
}






/** Add name lookup format on the fixed end-position inside key_data.
 *
 * Note: key_data[KEY_DNAME_END_OFFSET] = '\0' even though
 * not always used as a part of the key. */
static inline uint8_t * key_dname_lf(const knot_dname_t *name, uint8_t key_data[KEY_MAXLEN])
{
	return knot_dname_lf(name, key_data + KEY_RULESET_MAXLEN + 1)
		// FIXME: recheck
		+ (name[0] == '\0' ? 0 : 1);
}

/** Return length of the common prefix of two strings (knot_db_val_t). */
static size_t key_common_prefix(knot_db_val_t k1, knot_db_val_t k2)
{
	const size_t len = MIN(k1.len, k2.len);
	const uint8_t *data1 = k1.data, *data2 = k2.data;
	kr_require(len == 0 || (data1 && data2));
	for (ssize_t i = 0; i < len; ++i) {
		if (data1[i] != data2[i])
			return i;
	}
	return len;
}

/** Find common "subtree" of two strings that both end in a dname_lf ('\0' terminator excluded).
 *
 * \return index pointing at the '\0' ending the last matching label
 * 	(possibly the virtual '\0' just past the end of either string),
 * 	or if no LF label matches, the first character that differs
 * Function reviewed thoroughly, including the dependency.
 */
static size_t key_common_subtree(knot_db_val_t k1, knot_db_val_t k2, size_t lf_start_i)
{
	ssize_t i = key_common_prefix(k1, k2);
	const char *data1 = k1.data, *data2 = k2.data;
	// beware: '\0' at the end is excluded, so we need to handle ends separately
	if (i <= lf_start_i
		|| (i == k1.len && i == k2.len)
		|| (i == k1.len && data2[i] == '\0')
		|| (i == k2.len && data1[i] == '\0')) {
			return i;
		}
	do {
		--i;
		if (i <= lf_start_i)
			return i;
		if (data2[i] == '\0')
			return i;
	} while (true);
}

int rule_local_data_answer(struct kr_query *qry, knot_pkt_t *pkt)
{
	// return shorthands; see doc-comment for kr_rule_local_data_answer()
	static const int RET_CONT_CACHE = 0;
	static const int RET_ANSWERED = 1;

	kr_require(the_rules);
	// TODO: implement EDE codes somehow

	//if (kr_fails_assert(!qry->data_src.initialized)) // low-severity assertion
	if (qry->data_src.initialized) // TODO: why does it happen?
		memset(&qry->data_src, 0, sizeof(qry->data_src));

	const uint16_t rrtype = qry->stype;

	// Init the SNAME-based part of key; it's pretty static.
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key;
	key.data = key_dname_lf(qry->sname, key_data);
	key_data[KEY_DNAME_END_OFFSET + 1] = '\0'; // double zero
	key.data -= sizeof(KEY_EXACT_MATCH);

	int ret;

	// Init code for managing the ruleset part of the key.
	// LATER(optim.): we might cache the ruleset list a bit
	uint8_t * const key_data_ruleset_end = key.data;
	knot_db_val_t rulesets = { NULL, 0 };
	{
		uint8_t key_rs[] = "\0rulesets";
		knot_db_val_t key_rsk = { .data = key_rs, .len = sizeof(key_rs) };
		ret = ruledb_op(read, &key_rsk, &rulesets, 1);
	}
	if (ret == kr_error(ENOENT)) return RET_CONT_CACHE; // no rulesets -> no rule used
	if (ret != 0) return kr_error(ret);
	const char *rulesets_str = rulesets.data;

	// Iterate over all rulesets.
	while (rulesets.len > 0) {
		const char * const ruleset_name = rulesets_str;
		{ // Write ruleset-specific prefix of the key.
			const size_t rsp_len = strnlen(rulesets_str, rulesets.len);
			kr_require(rsp_len <= KEY_RULESET_MAXLEN - 1);
			key.data = key_data_ruleset_end - rsp_len;
			memcpy(key.data, rulesets_str, rsp_len);
			rulesets_str += rsp_len + 1;
			rulesets.len -= rsp_len + 1;
		}

		// Probe for exact and CNAME rule.
		memcpy(key_data_ruleset_end, &KEY_EXACT_MATCH, sizeof(KEY_EXACT_MATCH));
		key.len = key_data + KEY_DNAME_END_OFFSET + 2 + sizeof(rrtype)
			- (uint8_t *)key.data;
		const uint16_t types[] = { rrtype, KNOT_RRTYPE_CNAME };
		const bool want_CNAME = rrtype != KNOT_RRTYPE_CNAME
					&& rrtype != KNOT_RRTYPE_DS;
		for (int i = 0; i < 1 + want_CNAME; ++i) {
			memcpy(key_data + KEY_DNAME_END_OFFSET + 2, &types[i], sizeof(rrtype));
			knot_db_val_t val;
			// LATER: use cursor to iterate over multiple rules on the same key,
			// testing tags on each
			ret = ruledb_op(read, &key, &val, 1);
			switch (ret) {
				case -ENOENT: continue;
				case 0: break;
				default: return kr_error(ret);
			}
			if (!kr_rule_consume_tags(&val, qry->request)) continue;

			// We found a rule that applies to the dname+rrtype+req.
			ret = answer_exact_match(qry, pkt, types[i],
						 val.data, val.data + val.len);
			return ret ? kr_error(ret) : RET_ANSWERED;
		}

		/* Find the closest zone-like apex that applies.
		 * Now the key needs one byte change and a little truncation
		 * (we may truncate repeatedly). */
		static_assert(sizeof(KEY_ZONELIKE_A) == sizeof(KEY_EXACT_MATCH),
				"bad combination of constants");
		memcpy(key_data_ruleset_end, &KEY_ZONELIKE_A, sizeof(KEY_ZONELIKE_A));
		key.len = key_data + KEY_DNAME_END_OFFSET - (uint8_t *)key.data;
		const size_t lf_start_i = key_data_ruleset_end + sizeof(KEY_ZONELIKE_A)
					- (const uint8_t *)key.data;
		kr_require(lf_start_i < KEY_MAXLEN);
		knot_db_val_t key_leq = key;
		knot_db_val_t val;
		if (rrtype == KNOT_RRTYPE_DS)
			goto shorten; // parent-side type, belongs into zone closer to root
		// LATER: again, use cursor to iterate over multiple rules on the same key.
		do {
			ret = ruledb_op(read_leq, &key_leq, &val);
			if (ret == -ENOENT) break;
			if (ret < 0) return kr_error(ret);
			if (ret > 0) { // found a previous key
				size_t cs_len = key_common_subtree(key, key_leq, lf_start_i);
				if (cs_len < lf_start_i) // no suitable key can exist in DB
					break;
				if (cs_len < key_leq.len) { // retry at the common subtree
					key_leq.len = cs_len;
					continue;
				}
				kr_assert(cs_len == key_leq.len);
			}
			const knot_db_val_t zla_lf = {
				.data = key_leq.data + lf_start_i,
				.len  = key_leq.len  - lf_start_i,
			};
			// Found some good key, now check tags.
			if (!kr_rule_consume_tags(&val, qry->request)) {
				kr_assert(key_leq.len >= lf_start_i);
			shorten:
				// Shorten key_leq by one label and retry.
				if (key_leq.len <= lf_start_i) // nowhere to shorten
					break;
				const char *data = key_leq.data;
				while (key_leq.len > lf_start_i && data[--key_leq.len] != '\0') ;
				continue;
			}
			// Tags OK; get ZLA type and deal with special _FORWARD case
			val_zla_type_t ztype;
			if (deserialize_fails_assert(&val, &ztype))
				return kr_error(EILSEQ);
			if (ztype == VAL_ZLAT_FORWARD) {
				knot_dname_t apex_name[KNOT_DNAME_MAXLEN];
				ret = knot_dname_lf2wire(apex_name, zla_lf.len, zla_lf.data);
				if (kr_fails_assert(ret > 0)) return kr_error(ret);
				if (val.len > 0 // zero len -> default flags
				    && deserialize_fails_assert(&val, &qry->data_src.flags)) {
					return kr_error(EILSEQ);
				}

				qry->data_src.initialized = true;
				qry->data_src.targets_ptr = val;
				qry->data_src.rule_depth = knot_dname_labels(apex_name, NULL);
				return RET_CONT_CACHE;
			}
			// The other types optionally specify TTL.
			uint32_t ttl = RULE_TTL_DEFAULT;
			if (val.len >= sizeof(ttl)) // allow omitting -> can't kr_assert
				deserialize_fails_assert(&val, &ttl);
			if (kr_fails_assert(val.len == 0)) {
				kr_log_error(RULES, "ERROR: unused bytes: %zu\n", val.len);
				return kr_error(EILSEQ);
			}
			// Finally execute the rule.
			switch (ztype) {
			case VAL_ZLAT_EMPTY:
			case VAL_ZLAT_NXDOMAIN:
			case VAL_ZLAT_NODATA:
				ret = answer_zla_empty(ztype, qry, pkt, zla_lf, ttl);
				if (ret == kr_error(EAGAIN))
					goto shorten;
				return ret;
			case VAL_ZLAT_REDIRECT:
				ret = answer_zla_redirect(qry, pkt, ruleset_name, zla_lf, ttl);
				return ret ? kr_error(ret) : RET_ANSWERED;
			default:
				return kr_error(EILSEQ);
			}
		} while (true);
	}

	return RET_CONT_CACHE;
}

/** SOA RDATA content, used as default in negative answers.
 *
 * It's as recommended except for using a fixed mname (for simplicity):
	https://tools.ietf.org/html/rfc6303#section-3
 */
static const uint8_t soa_rdata[] = "\x09localhost\0\6nobody\7invalid\0"
	"\0\0\0\1\0\0\x0e\x10\0\0\4\xb0\0\x09\x3a\x80\0\0\x2a\x30";

#define CHECK_RET(ret) do { \
	if ((ret) < 0) { kr_assert(false); return kr_error((ret)); } \
} while (false)

static int answer_exact_match(struct kr_query *qry, knot_pkt_t *pkt, uint16_t type,
		const uint8_t *data, const uint8_t *data_bound)
{
	/* Extract ttl from data. */
	uint32_t ttl;
	if (kr_fails_assert(data + sizeof(ttl) <= data_bound))
		return kr_error(EILSEQ);
	memcpy(&ttl, data, sizeof(ttl));
	data += sizeof(ttl);

	/* Start constructing the (pseudo-)packet. */
	int ret = pkt_renew(pkt, qry->sname, qry->stype);
	CHECK_RET(ret);
	struct answer_rrset arrset;
	memset(&arrset, 0, sizeof(arrset));

	/* Materialize the base RRset.
	 * Error handling: we assume it's OK to leak a bit memory from pkt->mm. */
	arrset.set.rr = knot_rrset_new(qry->sname, type, KNOT_CLASS_IN, ttl, &pkt->mm);
	if (kr_fails_assert(arrset.set.rr))
		return kr_error(ENOMEM);
	ret = rdataset_materialize(&arrset.set.rr->rrs, data, data_bound, &pkt->mm);
	CHECK_RET(ret);
	data += ret;
	arrset.set.rank = KR_RANK_SECURE | KR_RANK_AUTH; // local data has high trust
	arrset.set.expiring = false;
	/* Materialize the RRSIG RRset for the answer in (pseudo-)packet.
	 * (There will almost never be any RRSIG.) */
	ret = rdataset_materialize(&arrset.sig_rds, data, data_bound, &pkt->mm);
	CHECK_RET(ret);
	data += ret;

	/* Sanity check: we consumed exactly all data. */
	const int unused_bytes = data_bound - data;
	if (kr_fails_assert(unused_bytes == 0)) {
		kr_log_error(RULES, "ERROR: unused bytes: %d\n", unused_bytes);
		return kr_error(EILSEQ);
	}

	/* Special NODATA sub-case. */
	knot_rrset_t *rr = arrset.set.rr;
	const int is_nodata = rr->rrs.count == 0;
	if (is_nodata) {
		if (kr_fails_assert(type == KNOT_RRTYPE_CNAME && arrset.sig_rds.count == 0))
			return kr_error(EILSEQ);
		rr->type = KNOT_RRTYPE_SOA;
		ret = knot_rrset_add_rdata(rr, soa_rdata, sizeof(soa_rdata) - 1, &pkt->mm);
		CHECK_RET(ret);
		ret = knot_pkt_begin(pkt, KNOT_AUTHORITY);
		CHECK_RET(ret);
	}

	/* Put links to the materialized data into the pkt. */
	knot_wire_set_rcode(pkt->wire, KNOT_RCODE_NOERROR);
	ret = pkt_append(pkt, &arrset);
	CHECK_RET(ret);

	/* Finishing touches. */
	qry->flags.EXPIRING = false;
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;

	VERBOSE_MSG(qry, "=> satisfied by local data (%s)\n",
			is_nodata ? "no data" : "positive");
	return kr_ok();
}

knot_db_val_t local_data_key(const knot_rrset_t *rrs, uint8_t key_data[KEY_MAXLEN],
					const char *ruleset_name)
{
	knot_db_val_t key;
	key.data = key_dname_lf(rrs->owner, key_data);
	key_data[KEY_DNAME_END_OFFSET + 1] = '\0'; // double zero

	key.data -= sizeof(KEY_EXACT_MATCH);
	memcpy(key.data, &KEY_EXACT_MATCH, sizeof(KEY_EXACT_MATCH));

	const size_t rsp_len = strlen(ruleset_name);
	key.data -= rsp_len;
	memcpy(key.data, ruleset_name, rsp_len);

	memcpy(key_data + KEY_DNAME_END_OFFSET + 2, &rrs->type, sizeof(rrs->type));
	key.len = key_data + KEY_DNAME_END_OFFSET + 2 + sizeof(rrs->type)
		- (uint8_t *)key.data;
	return key;
}
int kr_rule_local_data_ins(const knot_rrset_t *rrs, const knot_rdataset_t *sig_rds,
				kr_rule_tags_t tags)
{
	ENSURE_the_rules;
	// Construct the DB key.
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = local_data_key(rrs, key_data, RULESET_DEFAULT);
	return local_data_ins(key, rrs, sig_rds, tags);
}
int local_data_ins(knot_db_val_t key, const knot_rrset_t *rrs,
			const knot_rdataset_t *sig_rds, kr_rule_tags_t tags)
{
	// Allocate the data in DB.
	const int rr_ssize = rdataset_dematerialize_size(&rrs->rrs);
	const int to_alloc = sizeof(tags) + sizeof(rrs->ttl) + rr_ssize
			+ rdataset_dematerialize_size(sig_rds);
	knot_db_val_t val = { .data = NULL, .len = to_alloc };
	int ret = ruledb_op(write, &key, &val, 1);
	if (ret) {
		// ENOSPC seems to be the only expectable error.
		kr_assert(ret == kr_error(ENOSPC));
		return kr_error(ret);
	}

	// Write all the data.
	memcpy(val.data, &tags, sizeof(tags));
	val.data += sizeof(tags);
	memcpy(val.data, &rrs->ttl, sizeof(rrs->ttl));
	val.data += sizeof(rrs->ttl);
	rdataset_dematerialize(&rrs->rrs, val.data);
	val.data += rr_ssize;
	rdataset_dematerialize(sig_rds, val.data);
	return kr_ok();
}
int kr_rule_local_data_del(const knot_rrset_t *rrs, kr_rule_tags_t tags)
{
	ENSURE_the_rules;
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = local_data_key(rrs, key_data, RULESET_DEFAULT);
	return ruledb_op(remove, &key, 1);
}
int kr_rule_local_data_merge(const knot_rrset_t *rrs, const kr_rule_tags_t tags)
{
	ENSURE_the_rules;
	// Construct the DB key.
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = local_data_key(rrs, key_data, RULESET_DEFAULT);
	knot_db_val_t val;
	// Transaction: we assume that we're in a RW transaction already,
	// so that here we already "have a lock" on the last version.
	int ret = ruledb_op(read, &key, &val, 1);
	if (abs(ret) == abs(ENOENT))
		goto fallback;
	if (ret)
		return kr_error(ret);
	// check tags
	kr_rule_tags_t tags_old;
	if (deserialize_fails_assert(&val, &tags_old) || tags_old != tags)
		goto fallback;
	// merge TTLs
	uint32_t ttl;
	if (deserialize_fails_assert(&val, &ttl))
		goto fallback;
	if (ttl > rrs->ttl)
		ttl = rrs->ttl;
	knot_rrset_t rrs_new;
	knot_rrset_init(&rrs_new, rrs->owner, rrs->type, rrs->rclass, ttl);
	// merge the rdatasets
	knot_mm_t *mm = mm_ctx_mempool2(MM_DEFAULT_BLKSIZE); // frag. optimization
	if (!mm)
		return kr_error(ENOMEM);
	ret = rdataset_materialize(&rrs_new.rrs, val.data, val.data + val.len, mm);
	if (kr_fails_assert(ret >= 0)) { // just invalid call or rubbish data
		mm_ctx_delete(mm);
		return ret;
	}
	ret = knot_rdataset_merge(&rrs_new.rrs, &rrs->rrs, mm);
	if (ret) { // ENOMEM or hitting 64 KiB limit
		mm_ctx_delete(mm);
		return kr_error(ret);
	}
	// everything is ready to insert the merged RRset
	ret = local_data_ins(key, &rrs_new, NULL, tags);
	mm_ctx_delete(mm);
	return ret;
fallback:
	return local_data_ins(key, rrs, NULL, tags);
}

/** Empty or NXDOMAIN or NODATA.  Returning kr_error(EAGAIN) means the rule didn't match. */
static int answer_zla_empty(val_zla_type_t type, struct kr_query *qry, knot_pkt_t *pkt,
				const knot_db_val_t zla_lf, uint32_t ttl)
{
	if (kr_fails_assert(type == VAL_ZLAT_EMPTY || type == VAL_ZLAT_NXDOMAIN
				|| type == VAL_ZLAT_NODATA))
		return kr_error(EINVAL);

	knot_dname_t apex_name[KNOT_DNAME_MAXLEN];
	int ret = knot_dname_lf2wire(apex_name, zla_lf.len, zla_lf.data);
	CHECK_RET(ret);

	const bool hit_apex = knot_dname_is_equal(qry->sname, apex_name);
	if (hit_apex && type == VAL_ZLAT_NODATA)
		return kr_error(EAGAIN);

	/* Start constructing the (pseudo-)packet. */
	ret = pkt_renew(pkt, qry->sname, qry->stype);
	CHECK_RET(ret);
	struct answer_rrset arrset;
	memset(&arrset, 0, sizeof(arrset));

	/* Construct SOA or NS data (hardcoded content).  _EMPTY has a proper zone apex. */
	const bool want_NS = hit_apex && type == VAL_ZLAT_EMPTY && qry->stype == KNOT_RRTYPE_NS;
	arrset.set.rr = knot_rrset_new(apex_name, want_NS ? KNOT_RRTYPE_NS : KNOT_RRTYPE_SOA,
					KNOT_CLASS_IN, ttl, &pkt->mm);
	if (kr_fails_assert(arrset.set.rr))
		return kr_error(ENOMEM);
	if (want_NS) {
		kr_require(zla_lf.len + 2 == knot_dname_size(apex_name));
		// TODO: maybe it's weird to use this NS name, but what else?
		ret = knot_rrset_add_rdata(arrset.set.rr, apex_name, zla_lf.len + 2, &pkt->mm);
	} else {
		ret = knot_rrset_add_rdata(arrset.set.rr, soa_rdata,
						sizeof(soa_rdata) - 1, &pkt->mm);
	}
	CHECK_RET(ret);
	arrset.set.rank = KR_RANK_SECURE | KR_RANK_AUTH; // local data has high trust
	arrset.set.expiring = false;

	/* Small differences if we exactly hit the name or even type. */
	if (type == VAL_ZLAT_NODATA || (type == VAL_ZLAT_EMPTY && hit_apex)) {
		knot_wire_set_rcode(pkt->wire, KNOT_RCODE_NOERROR);
	} else {
		knot_wire_set_rcode(pkt->wire, KNOT_RCODE_NXDOMAIN);
	}
	if (type == VAL_ZLAT_EMPTY && hit_apex
			&& (qry->stype == KNOT_RRTYPE_SOA || qry->stype == KNOT_RRTYPE_NS)) {
		ret = knot_pkt_begin(pkt, KNOT_ANSWER);
	} else {
		ret = knot_pkt_begin(pkt, KNOT_AUTHORITY);
	}
	CHECK_RET(ret);

	/* Put links to the RR into the pkt. */
	ret = pkt_append(pkt, &arrset);
	CHECK_RET(ret);

	/* Finishing touches. */
	qry->flags.EXPIRING = false;
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;

	VERBOSE_MSG(qry, "=> satisfied by local data (%s zone)\n",
		     type == VAL_ZLAT_EMPTY ? "empty" : "nxdomain");
	return kr_ok();
}

static int answer_zla_redirect(struct kr_query *qry, knot_pkt_t *pkt, const char *ruleset_name,
				const knot_db_val_t zla_lf, uint32_t ttl)
{
	VERBOSE_MSG(qry, "=> redirecting by local data\n"); // lazy to get the zone name

	knot_dname_t apex_name[KNOT_DNAME_MAXLEN];
	int ret = knot_dname_lf2wire(apex_name, zla_lf.len, zla_lf.data);
	CHECK_RET(ret);
	const bool name_matches = knot_dname_is_equal(qry->sname, apex_name);
	if (name_matches || qry->stype == KNOT_RRTYPE_NS || qry->stype == KNOT_RRTYPE_SOA)
		goto nodata;

	// Reconstruct the DB key from scratch.
	knot_rrset_t rrs;
	knot_rrset_init(&rrs, apex_name, qry->stype, 0, 0); // 0 are unused
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = local_data_key(&rrs, key_data, ruleset_name);

	knot_db_val_t val;
	ret = ruledb_op(read, &key, &val, 1);
	switch (ret) {
		case -ENOENT: goto nodata;
		case 0: break;
		default: return ret;
	}
	if (kr_rule_consume_tags(&val, qry->request)) // found a match
		return answer_exact_match(qry, pkt, qry->stype,
						val.data, val.data + val.len);

nodata: // Want NODATA answer (or NOERROR if it hits apex SOA).
	// Start constructing the (pseudo-)packet.
	ret = pkt_renew(pkt, qry->sname, qry->stype);
	CHECK_RET(ret);
	struct answer_rrset arrset;
	memset(&arrset, 0, sizeof(arrset));
	arrset.set.rr = knot_rrset_new(apex_name, KNOT_RRTYPE_SOA,
					KNOT_CLASS_IN, ttl, &pkt->mm);
	if (kr_fails_assert(arrset.set.rr))
		return kr_error(ENOMEM);
	ret = knot_rrset_add_rdata(arrset.set.rr, soa_rdata,
					sizeof(soa_rdata) - 1, &pkt->mm);
	CHECK_RET(ret);
	arrset.set.rank = KR_RANK_SECURE | KR_RANK_AUTH; // local data has high trust
	arrset.set.expiring = false;

	knot_wire_set_rcode(pkt->wire, KNOT_RCODE_NOERROR);
	knot_section_t sec = name_matches && qry->stype == KNOT_RRTYPE_SOA
				? KNOT_ANSWER : KNOT_AUTHORITY;
	ret = knot_pkt_begin(pkt, sec);
	CHECK_RET(ret);

	// Put links to the RR into the pkt.
	ret = pkt_append(pkt, &arrset);
	CHECK_RET(ret);

	// Finishing touches.
	qry->flags.EXPIRING = false;
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;

	VERBOSE_MSG(qry, "=> satisfied by local data (no data)\n");
	return kr_ok();
}

knot_db_val_t zla_key(const knot_dname_t *apex, uint8_t key_data[KEY_MAXLEN])
{
	kr_require(the_rules);
	knot_db_val_t key;
	key.data = key_dname_lf(apex, key_data);

	key.data -= sizeof(KEY_ZONELIKE_A);
	memcpy(key.data, &KEY_ZONELIKE_A, sizeof(KEY_ZONELIKE_A));

	const size_t rsp_len = strlen(RULESET_DEFAULT);
	key.data -= rsp_len;
	memcpy(key.data, RULESET_DEFAULT, rsp_len);
	key.len = key_data + KEY_DNAME_END_OFFSET - (uint8_t *)key.data;
	return key;
}
int insert_trivial_zone(val_zla_type_t ztype, uint32_t ttl,
			const knot_dname_t *apex, kr_rule_tags_t tags)
{
	ENSURE_the_rules;
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = zla_key(apex, key_data);

	knot_db_val_t val = {
		.data = NULL,
		.len = sizeof(tags) + sizeof(ztype),
	};
	const bool has_ttl = ttl != RULE_TTL_DEFAULT;
	if (has_ttl)
		val.len += sizeof(ttl);
	int ret = ruledb_op(write, &key, &val, 1);
	if (ret) {
		// ENOSPC seems to be the only expectable error.
		kr_assert(ret == kr_error(ENOSPC));
		return kr_error(ret);
	}
	memcpy(val.data, &tags, sizeof(tags));
	val.data += sizeof(tags);
	memcpy(val.data, &ztype, sizeof(ztype));
	val.data += sizeof(ztype);
	if (has_ttl) {
		memcpy(val.data, &ttl, sizeof(ttl));
		val.data += sizeof(ttl);
	}
	return kr_ok();
}

int kr_rule_local_data_emptyzone(const knot_dname_t *apex, kr_rule_tags_t tags)
{
	return insert_trivial_zone(VAL_ZLAT_EMPTY, RULE_TTL_DEFAULT, apex, tags);
}
int kr_rule_local_data_nxdomain(const knot_dname_t *apex, kr_rule_tags_t tags)
{
	return insert_trivial_zone(VAL_ZLAT_NXDOMAIN, RULE_TTL_DEFAULT, apex, tags);
}
int kr_rule_local_data_nodata(const knot_dname_t *apex, kr_rule_tags_t tags)
{
	return insert_trivial_zone(VAL_ZLAT_NODATA, RULE_TTL_DEFAULT, apex, tags);
}
int kr_rule_local_data_redirect(const knot_dname_t *apex, kr_rule_tags_t tags)
{
	return insert_trivial_zone(VAL_ZLAT_REDIRECT, RULE_TTL_DEFAULT, apex, tags);
}


/** Encode a subnet into a (longer) string.
 *
 * The point is to have different encodings for different subnets,
 * with using just byte-length strings (e.g. for ::/1 vs. ::/2).
 * And we need to preserve order: FIXME description
 *  - natural partial order on subnets, one included in another
 *  - partial order on strings, one being a prefix of another
 *  - implies lexicographical order on the encoded strings
 *
 * Consequently, given a set of subnets, the t
 */
static int subnet_encode(const struct sockaddr *addr, int sub_len, uint8_t buf[32])
{
	const int len = kr_inaddr_len(addr);
	if (kr_fails_assert(len > 0))
		return kr_error(len);
	if (kr_fails_assert(sub_len >= 0 && sub_len <= 8 * len))
		return kr_error(EINVAL);
	const uint8_t *a = (const uint8_t *)/*sign*/kr_inaddr(addr);

	// Algo: interleave bits of the address.  Bit pairs:
	//  - 00 -> beyond the subnet's prefix
	//  - 10 -> zero bit within the subnet's prefix
	//  - 11 ->  one bit within the subnet's prefix
	// Multiplying one uint8_t by 01010101 (in binary) will do interleaving.
	int i;
	// Let's hope that compiler optimizes this into something reasonable.
	for (i = 0; sub_len > 0; ++i, sub_len -= 8) {
		uint16_t x = a[i] * 85; // interleave by zero bits
		uint8_t sub_mask = 255 >> (8 - MIN(sub_len, 8));
		uint16_t r = x | (sub_mask * 85 * 2);
		buf[2*i] = r / 256;
		buf[2*i + 1] = r % 256;
	}
	return i * 2;
}

// Is `a` subnet-prefix of `b`?  (a byte format of subnet_encode())
bool subnet_is_prefix(uint8_t a, uint8_t b)
{
	while (true) {
		if (a >> 6 == 0)
			return true;
		if (a >> 6 != b >> 6) {
			kr_assert(b >> 6 != 0);
			return false;
		}
		a = (a << 2) & 0xff;
		b = (b << 2) & 0xff;
	}
}

#define KEY_PREPEND(key, arr) do { \
		key.data -= sizeof(arr); \
		key.len  += sizeof(arr); \
		memcpy(key.data, arr, sizeof(arr)); \
	} while (false)

int kr_view_insert_action(const char *subnet, const char *action)
{
	ENSURE_the_rules;
	// Parse the subnet string.
	union kr_sockaddr saddr;
	saddr.ip.sa_family = kr_straddr_family(subnet);
	int bitlen = kr_straddr_subnet((char *)/*const-cast*/kr_inaddr(&saddr.ip), subnet);
	if (bitlen < 0) return kr_error(bitlen);

	// Init the addr-based part of key.
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key;
	key.data = &key_data[KEY_RULESET_MAXLEN];
	key.len = subnet_encode(&saddr.ip, bitlen, key.data);
	switch (saddr.ip.sa_family) {
		case AF_INET:  KEY_PREPEND(key, KEY_VIEW_SRC4);  break;
		case AF_INET6: KEY_PREPEND(key, KEY_VIEW_SRC6);  break;
		default:       kr_assert(false);  return kr_error(EINVAL);
	}

	{ // Write ruleset-specific prefix of the key.
		const size_t rsp_len = strlen(RULESET_DEFAULT);
		key.data -= rsp_len;
		key.len  += rsp_len;
		memcpy(key.data, RULESET_DEFAULT, rsp_len);
	}

	// Insert & commit.
	knot_db_val_t val = {
		.data = (void *)/*const-cast*/action,
		.len = strlen(action),
	};
	return ruledb_op(write, &key, &val, 1);
}

int kr_view_select_action(const struct kr_request *req, knot_db_val_t *selected)
{
	kr_require(the_rules);
	const struct sockaddr * const addr = req->qsource.addr;
	if (!addr) return kr_error(ENOENT); // internal request; LATER: act somehow?

	// Init the addr-based part of key; it's pretty static.
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key;
	key.data = &key_data[KEY_RULESET_MAXLEN];
	key.len = subnet_encode(addr, kr_inaddr_len(addr) * 8, key.data);
	switch (kr_inaddr_family(addr)) {
		case AF_INET:  KEY_PREPEND(key, KEY_VIEW_SRC4);  break;
		case AF_INET6: KEY_PREPEND(key, KEY_VIEW_SRC6);  break;
		default:       kr_assert(false);  return kr_error(EINVAL);
	}

	int ret;

	// Init code for managing the ruleset part of the key.
	// LATER(optim.): we might cache the ruleset list a bit
	uint8_t * const key_data_ruleset_end = key.data;
	knot_db_val_t rulesets = { NULL, 0 };
	{
		uint8_t key_rs[] = "\0rulesets";
		knot_db_val_t key_rsk = { .data = key_rs, .len = sizeof(key_rs) };
		ret = ruledb_op(read, &key_rsk, &rulesets, 1);
	}
	if (ret != 0) return ret; // including ENOENT: no rulesets -> no rule used
	const char *rulesets_str = rulesets.data;

	// Iterate over all rulesets.
	while (rulesets.len > 0) {
		{ // Write ruleset-specific prefix of the key.
			const size_t rsp_len = strnlen(rulesets_str, rulesets.len);
			kr_require(rsp_len <= KEY_RULESET_MAXLEN - 1);
			key.data = key_data_ruleset_end - rsp_len;
			memcpy(key.data, rulesets_str, rsp_len);
			rulesets_str += rsp_len + 1;
			rulesets.len -= rsp_len + 1;
		}

		static_assert(sizeof(KEY_VIEW_SRC4) == sizeof(KEY_VIEW_SRC6),
				"bad combination of constants");
		const size_t addr_start_i = key_data_ruleset_end + sizeof(KEY_VIEW_SRC4)
					- (const uint8_t *)key.data;

		knot_db_val_t key_leq = {
			.data = key.data,
			.len = key.len + (key_data_ruleset_end - (uint8_t *)key.data),
		};
		knot_db_val_t val;
		ret = ruledb_op(read_leq, &key_leq, &val);
		for (; true; ret = ruledb_op(read_less, &key_leq, &val)) {
			if (ret == -ENOENT) break;
			if (ret < 0) return kr_error(ret);
			if (ret > 0) { // found a previous key
				ssize_t i = key_common_prefix(key, key_leq);
				if (i < addr_start_i) // no suitable key can exist in DB
					break;
				if (i != key_leq.len) {
					if (kr_fails_assert(i < key.len && i < key_leq.len))
						break;
					if (!subnet_is_prefix(((uint8_t *)key_leq.data)[i],
							      ((uint8_t *)key.data)[i])) {
						// the key doesn't match
						// We can shorten the key to potentially
						// speed up by skipping over whole subtrees.
						key_leq.len = i + 1;
						continue;
					}
				}
			}
			// We certainly have a matching key (join of various sub-cases).
			if (kr_log_is_debug(RULES, NULL)) {
				// it's complex to get zero-terminated string for the action
				char act_0t[val.len + 1];
				memcpy(act_0t, val.data, val.len);
				act_0t[val.len] = 0;
				VERBOSE_MSG(req->rplan.initial, "=> view selected action: %s\n",
					act_0t);
			}
			*selected = val;
			return kr_ok();
		}
	}
	return kr_error(ENOENT);
}
