/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/rules/api.h"
#include "lib/rules/impl.h"

#include "lib/cache/cdb_lmdb.h"

#include <stdlib.h>

#include "lib/cache/impl.h"
#undef VERBOSE_MSG
#define VERBOSE_MSG(qry, ...) QRVERBOSE((qry), "rule",  ## __VA_ARGS__)

struct kr_rules {
	/* Database for storing the rules (LMDB). */
	const struct kr_cdb_api *cdb_api;
	knot_db_t *db;
	struct kr_cdb_stats db_stats;
};

struct kr_rules *the_rules = NULL;
#define ruledb_op(op, ...) \
	the_rules->cdb_api->op(the_rules->db, &the_rules->db_stats, ## __VA_ARGS__)

/* DB key-space summary

 - "\0" starts special keys like "\0rulesets" or "\0stamp"
 - some future additions?
 - otherwise it's rulesets - each has a prefix, e.g. RULESET_DEFAULT,
   its length is bounded by KEY_RULESET_MAXLEN - 1; after that prefix:
    - KEY_EXACT_MATCH + dname_lf ended by double '\0' + KNOT_RRTYPE_FOO
	-> exact-match rule (for the given name)
    - KEY_ZONELIKE_A  + dname_lf (no '\0' at end)
	-> zone-like apex (on the given name)
 */

const int KEY_RULESET_MAXLEN = 16; /**< max. len of ruleset ID + 1(for kind) */
static /*const*/ char RULESET_DEFAULT[] = "d";

static const uint8_t KEY_EXACT_MATCH[1] = "e";
static const uint8_t KEY_ZONELIKE_A [1] = "a";

/** The first byte of zone-like apex value is its type. */
typedef uint8_t val_zla_type_t;
enum {
	/** Empty zone. No data in DB value after this byte. */
	VAL_ZLAT_EMPTY = 1,
};


static int answer_exact_match(struct kr_query *qry, knot_pkt_t *pkt, uint16_t type,
		const uint8_t *data, const uint8_t *data_bound);
static int answer_zla_empty(struct kr_query *qry, knot_pkt_t *pkt,
		const knot_db_val_t zla_lf, const knot_db_val_t val);

int kr_rules_init()
{
	if (the_rules) abort();
	the_rules = calloc(1, sizeof(*the_rules));
	if (!the_rules) abort();
	the_rules->cdb_api = kr_cdb_lmdb(false);

	struct kr_cdb_opts opts = {
		.path = "ruledb", // under current workdir
		.maxsize = 10 * 1024*1024,
	};
	int ret = the_rules->cdb_api->open(&the_rules->db, &the_rules->db_stats, &opts, NULL);
	/* No persistence - we always refill from config for now.
	 * LATER: "\0stamp" key when loading config(s). Also make it include versioning? */
	if (ret == 0) ret = ruledb_op(clear);
	if (ret != 0) goto failure;
	assert(the_rules->db);

	ret = rules_defaults_insert();
	if (ret != 0) goto failure;

	/* Activate one default ruleset. */
	uint8_t key_rs[] = "\0rulesets";
	knot_db_val_t key = { .data = key_rs, .len = sizeof(key_rs) };
	knot_db_val_t rulesets = { .data = &RULESET_DEFAULT, .len = strlen(RULESET_DEFAULT) + 1 };
	ret = ruledb_op(write, &key, &rulesets, 1);
	if (ret == 0) ret = ruledb_op(commit);
	if (ret == 0) return kr_ok();
failure:
	free(the_rules);
	the_rules = NULL;
	return ret;
}

void kr_rules_deinit()
{
	if (!the_rules) return;
	ruledb_op(close);
	free(the_rules);
	the_rules = NULL;
}

struct kr_request;
bool kr_rule_consume_tags(knot_db_val_t *val, const struct kr_request *req)
{
	const size_t tl = sizeof(kr_rule_tags_t);
	if (val->len < tl) {
		val->len = 0;
		assert(false);
		/* We may not fail immediately, but further processing
		 * will fail anyway due to zero remaining length. */
		return false;
	}
	kr_rule_tags_t tags;
	memcpy(&tags, val->data, tl);
	val->data += tl;
	val->len  -= tl;
	return tags == KR_RULE_TAGS_ALL || (tags & req->rule_tags);
}






/** When constructing a key, it's convenient that the dname_lf ends on a fixed offset.
 * Convention: the end here is before the final '\0' byte (if any). */
const int KEY_DNAME_END_OFFSET = KEY_RULESET_MAXLEN + KNOT_DNAME_MAXLEN;
const int KEY_MAXLEN = KEY_DNAME_END_OFFSET + 64; //TODO: most of 64 is unused ATM

/** Add name lookup format on the fixed end-position inside key_data.
 *
 * Note: key_data[KEY_DNAME_END_OFFSET] = '\0' even though
 * not always used as a part of the key. */
static inline uint8_t * key_dname_lf(const knot_dname_t *name, uint8_t *key_data)
{
	return knot_dname_lf(name, key_data + KEY_RULESET_MAXLEN + 1)
		+ 1/*drop length*/;
}

/** Return length of the common prefix of two strings (knot_db_val_t). */
static size_t key_common_prefix(knot_db_val_t k1, knot_db_val_t k2)
{
	const size_t maxlen = MAX(k1.len, k2.len);
	const uint8_t *data1 = k1.data, *data2 = k2.data;
	assert(maxlen == 0 || (data1 && data2));
	ssize_t i;
	for (i = 0; i < maxlen; ++i) {
		if (data1[i] != data2[i])
			break;
	}
	return i;
}

/** Find common "subtree" of two strings that both end in a dname_lf ('\0' terminator excluded).
 *
 * Note: return value < lf_start can happen - mismatch happened before LF. */
static size_t key_common_subtree(knot_db_val_t k1, knot_db_val_t k2, size_t lf_start_i)
{
	ssize_t i = key_common_prefix(k1, k2);
	if (i == k1.len || i == k2.len)
		return i;
	const char *data = k1.data;
	while (i > lf_start_i && data[i] != '\0')
		--i;
	return i;
}

int kr_rule_local_data_answer(struct kr_query *qry, knot_pkt_t *pkt)
{
	const uint16_t rrtype = qry->stype;

	// LATER(optim.): we might cache the ruleset list a bit
	uint8_t key_rs[] = "\0rulesets";
	knot_db_val_t rulesets = { NULL, 0 };
	int ret;
	{
		knot_db_val_t key = { .data = key_rs, .len = sizeof(key_rs) };
		ret = ruledb_op(read, &key, &rulesets, 1);
	}
	if (ret != 0) return ret; /* including ENOENT: no rulesets -> no rule used */
	const char *rulesets_str = rulesets.data;

	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key;
	key.data = key_dname_lf(qry->sname, key_data);
	key_data[KEY_DNAME_END_OFFSET + 1] = '\0'; // double zero

	key.data -= sizeof(KEY_EXACT_MATCH);
	uint8_t * const key_data_ruleset_end = key.data;

	/* Iterate over all rulesets. */
	while (rulesets.len > 0) {
		{ /* Write ruleset-specific prefix of the key. */
			const size_t rsp_len = strnlen(rulesets_str, rulesets.len);
			assert(rsp_len <= KEY_RULESET_MAXLEN - 1);
			key.data -= rsp_len;
			memcpy(key.data, rulesets_str, rsp_len);
			rulesets_str += rsp_len + 1;
			rulesets.len -= rsp_len + 1;
		}

		/* Probe for exact and CNAME rule. */
		memcpy(key_data_ruleset_end, &KEY_EXACT_MATCH, sizeof(KEY_EXACT_MATCH));
		key.len = key_data + KEY_DNAME_END_OFFSET + 2 + sizeof(rrtype)
			- (uint8_t *)key.data;
		const uint16_t types[] = { rrtype, KNOT_RRTYPE_CNAME };
		for (int i = 0; i < (2 - (rrtype == KNOT_RRTYPE_CNAME)); ++i) {
			memcpy(key_data + KEY_DNAME_END_OFFSET + 2, &types[i], sizeof(rrtype));
			knot_db_val_t val;
			// LATER: use cursor to iterate over multiple rules on the same key,
			// testing tags on each
			ret = ruledb_op(read, &key, &val, 1);
			switch (ret) {
				case -ENOENT: continue;
				case 0: break;
				default: return ret;
			}
			if (!kr_rule_consume_tags(&val, qry->request)) continue;

			/* We found a rule that applies to the dname+rrtype+req. */
			return answer_exact_match(qry, pkt, types[i],
							val.data, val.data + val.len);
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
		assert(lf_start_i < KEY_MAXLEN);
		knot_db_val_t key_leq = key;
		knot_db_val_t val;
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
			}
			const knot_db_val_t zla_lf = {
				.data = key_leq.data + lf_start_i,
				.len  = key_leq.len  - lf_start_i,
			};
			/* Found some good key, now check tags. */
			if (!kr_rule_consume_tags(&val, qry->request)) {
				/* Shorten key_leq by one label and retry. */
				if (key_leq.len <= lf_start_i) { // nowhere to shorten
					assert(key_leq.len == lf_start_i);
					break;
				}
				const char *data = key_leq.data;
				while (key_leq.len > lf_start_i && data[key_leq.len] != '\0')
					--key_leq.len;
				continue;
			}
			/* Tags OK; execute the rule. */
			val_zla_type_t ztype;
			if (val.len < sizeof(ztype))
				return kr_error(EILSEQ);
			memcpy(&ztype, val.data, sizeof(ztype));
			++val.data; --val.len;
			switch (ztype) {
			case VAL_ZLAT_EMPTY:
				return answer_zla_empty(qry, pkt, zla_lf, val);
			default:
				return kr_error(EILSEQ);
			}
		} while (true);
	}

	return kr_error(ENOENT);
}

#define CHECK_RET(ret) do { \
	if ((ret) < 0) { assert(false); return kr_error((ret)); } \
} while (false)

static int answer_exact_match(struct kr_query *qry, knot_pkt_t *pkt, uint16_t type,
		const uint8_t *data, const uint8_t *data_bound)
{
	/* Extract ttl from data. */
	uint32_t ttl;
	if (data + sizeof(ttl) > data_bound) {
		assert(!EILSEQ);
		return kr_error(EILSEQ);
	}
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
	if (!arrset.set.rr) {
		assert(!ENOMEM);
		return kr_error(ENOMEM);
	}
	ret = rdataset_materialize(&arrset.set.rr->rrs, data, data_bound, &pkt->mm);
	CHECK_RET(ret);
	const size_t data_off = ret;
	arrset.set.rank = KR_RANK_SECURE | KR_RANK_AUTH; // local data has high trust
	arrset.set.expiring = false;
	/* Materialize the RRSIG RRset for the answer in (pseudo-)packet.
	 * (There will almost never be any RRSIG.) */
	ret = rdataset_materialize(&arrset.sig_rds, data + data_off, data_bound, &pkt->mm);
	CHECK_RET(ret);

	/* Sanity check: we consumed exactly all data. */
	int unused_bytes = data_bound - data - data_off - ret;
	if (unused_bytes) {
		kr_log_error("[rule] ERROR: unused bytes: %d\n", unused_bytes);
		assert(!EILSEQ);
		return kr_error(EILSEQ);
	}

	/* Put links to the materialized data into the pkt. */
	ret = pkt_append(pkt, &arrset);
	CHECK_RET(ret);

	/* Finishing touches. */
	qry->flags.EXPIRING = false;
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;

	VERBOSE_MSG(qry, "=> satisfied by local data (positive)\n");
	return kr_ok();
}

int kr_rule_local_data_ins(const knot_rrset_t *rrs, const knot_rdataset_t *sig_rds,
				kr_rule_tags_t tags)
{
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key;
	key.data = key_dname_lf(rrs->owner, key_data);
	key_data[KEY_DNAME_END_OFFSET + 1] = '\0'; // double zero

	key.data -= sizeof(KEY_EXACT_MATCH);
	memcpy(key.data, &KEY_EXACT_MATCH, sizeof(KEY_EXACT_MATCH));

	const size_t rsp_len = strlen(RULESET_DEFAULT);
	key.data -= rsp_len;
	memcpy(key.data, RULESET_DEFAULT, rsp_len);

	memcpy(key_data + KEY_DNAME_END_OFFSET + 2, &rrs->type, sizeof(rrs->type));
	key.len = key_data + KEY_DNAME_END_OFFSET + 2 + sizeof(rrs->type)
		- (uint8_t *)key.data;

	const int rr_ssize = rdataset_dematerialize_size(&rrs->rrs);
	const int to_alloc = sizeof(tags) + sizeof(rrs->ttl) + rr_ssize
			+ rdataset_dematerialize_size(sig_rds);
	knot_db_val_t val = { .data = NULL, .len = to_alloc };
	int ret = ruledb_op(write, &key, &val, 1);
	CHECK_RET(ret);

	memcpy(val.data, &tags, sizeof(tags));
	val.data += sizeof(tags);
	memcpy(val.data, &rrs->ttl, sizeof(rrs->ttl));
	val.data += sizeof(rrs->ttl);
	ret = rdataset_dematerialize(&rrs->rrs, val.data);
	CHECK_RET(ret);
	val.data += rr_ssize;
	ret = rdataset_dematerialize(sig_rds, val.data);
	CHECK_RET(ret);

	return kr_ok();
}


static int answer_zla_empty(struct kr_query *qry, knot_pkt_t *pkt,
				const knot_db_val_t zla_lf, const knot_db_val_t val)
{
	if (val.len) {
		kr_log_error("[rule] ERROR: unused bytes: %zu\n", val.len);
		assert(!EILSEQ);
		return kr_error(EILSEQ);
	}

	knot_dname_t apex_name[KNOT_DNAME_MAXLEN];
	int ret = knot_dname_lf2wire(apex_name, zla_lf.len, zla_lf.data);
	CHECK_RET(ret);

	/* Start constructing the (pseudo-)packet. */
	ret = pkt_renew(pkt, qry->sname, qry->stype);
	CHECK_RET(ret);
	struct answer_rrset arrset;
	memset(&arrset, 0, sizeof(arrset));

	/* Construct SOA or NS data (hardcoded content).  The SOA content is
	 * as recommended except for using a fixed mname (for simplicity):
		https://tools.ietf.org/html/rfc6303#section-3
	 */
	static const uint8_t soa_rdata[] = "\6nobody\7invalid\0\6nobody\7invalid\0"
		"\0\0\0\1\0\0\x0e\x10\0\0\4\xb0\0\x09\x3a\x80\0\0\x2a\x30";
	const bool name_matches = knot_dname_is_equal(qry->sname, apex_name);
	const bool want_NS = name_matches && qry->stype == KNOT_RRTYPE_NS;
	arrset.set.rr = knot_rrset_new(apex_name, want_NS ? KNOT_RRTYPE_NS : KNOT_RRTYPE_SOA,
					KNOT_CLASS_IN, 10800, &pkt->mm);
	if (!arrset.set.rr) {
		assert(!ENOMEM);
		return kr_error(ENOMEM);
	}
	if (want_NS) {
		assert(zla_lf.len + 2 == knot_dname_size(apex_name));
		ret = knot_rrset_add_rdata(arrset.set.rr, apex_name, zla_lf.len + 2, &pkt->mm);
	} else {
		ret = knot_rrset_add_rdata(arrset.set.rr, soa_rdata,
						sizeof(soa_rdata) - 1, &pkt->mm);
	}
	CHECK_RET(ret);
	arrset.set.rank = KR_RANK_SECURE | KR_RANK_AUTH; // local data has high trust
	arrset.set.expiring = false;

	/* Small differences if we exactly hit the name or even type. */
	if (name_matches) {
		knot_wire_set_rcode(pkt->wire, KNOT_RCODE_NOERROR);
	} else {
		knot_wire_set_rcode(pkt->wire, KNOT_RCODE_NXDOMAIN);
	}
	if (want_NS || (name_matches && qry->stype == KNOT_RRTYPE_SOA)) {
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

	VERBOSE_MSG(qry, "=> satisfied by local data (empty zone)\n");
	return kr_ok();
}

int kr_rule_local_data_emptyzone(const knot_dname_t *apex, kr_rule_tags_t tags)
{
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key;
	key.data = key_dname_lf(apex, key_data);

	key.data -= sizeof(KEY_ZONELIKE_A);
	memcpy(key.data, &KEY_ZONELIKE_A, sizeof(KEY_ZONELIKE_A));

	const size_t rsp_len = strlen(RULESET_DEFAULT);
	key.data -= rsp_len;
	memcpy(key.data, RULESET_DEFAULT, rsp_len);
	key.len = key_data + KEY_DNAME_END_OFFSET - (uint8_t *)key.data;

	val_zla_type_t ztype = VAL_ZLAT_EMPTY;
	knot_db_val_t val = {
		.data = NULL,
		.len = sizeof(tags) + sizeof(ztype),
	};
	int ret = ruledb_op(write, &key, &val, 1);
	CHECK_RET(ret);
	memcpy(val.data, &tags, sizeof(tags));
	val.data += sizeof(tags);
	memcpy(val.data, &ztype, sizeof(ztype));
	val.data += sizeof(ztype);
	return ret;
}

