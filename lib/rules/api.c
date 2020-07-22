/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/rules/api.h"

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

static /*const*/ char RULESET_DEFAULT[] = "d";


static int answer_rule_hit(struct kr_query *qry, knot_pkt_t *pkt, uint16_t type,
		const uint8_t *data, const uint8_t *data_bound);


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
	 * LATER: "\0stamp" key when loading config(s). */
	if (ret == 0) ret = ruledb_op(clear);
	if (ret != 0) goto failure;
	assert(the_rules->db);

	/* Activate one default ruleset. */
	uint8_t key_rs[] = "\0rulesets";
	knot_db_val_t key = { .data = key_rs, .len = sizeof(key_rs) };
	knot_db_val_t rulesets = { .data = &RULESET_DEFAULT, .len = strlen(RULESET_DEFAULT) + 1 };
	ret = ruledb_op(write, &key, &rulesets, 1);
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
	val->data += sizeof(uint64_t);
	val->len  -= sizeof(uint64_t);
	return true; // FIXME, also length check
}


const int KEY_RULESET_MAXLEN = 16; /**< max. len of ruleset ID */
const int KEY_DNAME_END_OFFSET = KNOT_DNAME_MAXLEN + KEY_RULESET_MAXLEN;
const int KEY_MAXLEN = KEY_DNAME_END_OFFSET + 64;
//FIXME: cleanup design of the key space

int kr_rule_local_data(struct kr_query *qry, knot_pkt_t *pkt)
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
	key.data = knot_dname_lf(qry->sname, key_data + KEY_RULESET_MAXLEN);
	key_data[KEY_DNAME_END_OFFSET] = '\0';

	/* Iterate over all rulesets. */
	while (rulesets.len > 0) {
		{ /* Write ruleset-specific prefix of the key. */
			const size_t rsp_len = strnlen(rulesets_str, rulesets.len);
			key.data -= rsp_len;
			memcpy(key.data, rulesets_str, rsp_len);
			rulesets_str += rsp_len + 1;
			rulesets.len -= rsp_len + 1;
		}

		/* Probe for exact and CNAME rule. */
		key.len = key_data + KEY_DNAME_END_OFFSET + 1 + sizeof(rrtype)
			- (uint8_t *)key.data;
		const uint16_t types[] = { rrtype, KNOT_RRTYPE_CNAME };
		for (int i = 0; i < (2 - (rrtype == KNOT_RRTYPE_CNAME)); ++i) {
			memcpy(key_data + KEY_DNAME_END_OFFSET + 1, &types[i], sizeof(rrtype));
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
			return answer_rule_hit(qry, pkt, types[i], val.data, val.data + val.len);
		}

		/* LATER: find the closest zone-like apex that applies. */
	}

	return kr_error(ENOENT);
}

#define CHECK_RET(ret) do { \
	if ((ret) < 0) { assert(false); return kr_error((ret)); } \
} while (false)

static int answer_rule_hit(struct kr_query *qry, knot_pkt_t *pkt, uint16_t type,
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

	VERBOSE_MSG(qry, "=> satisfied by local data\n");
	return kr_ok();
}

int kr_rule_local_data_ins(const knot_rrset_t *rrs, const knot_rdataset_t *sig_rds,
				kr_rule_tags_t tags)
{
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key;
	key.data = knot_dname_lf(rrs->owner, key_data + KEY_RULESET_MAXLEN);
	key_data[KEY_DNAME_END_OFFSET] = '\0';

	const size_t rsp_len = strlen(RULESET_DEFAULT);
	key.data -= rsp_len;
	memcpy(key.data, RULESET_DEFAULT, rsp_len);

	memcpy(key_data + KEY_DNAME_END_OFFSET + 1, &rrs->type, sizeof(rrs->type));
	key.len = key_data + KEY_DNAME_END_OFFSET + 1 + sizeof(rrs->type)
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

