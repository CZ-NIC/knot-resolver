/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/rules/api.h"
#include "lib/rules/impl.h"

#include "lib/cache/cdb_lmdb.h"

#include <stdlib.h>


struct kr_rules *the_rules = NULL;

/* The default TTL value is a compromise and probably of little practical impact.
 * - answering from local rules should be quite cheap,
 *   so very high values are not expected to bring any improvements
 * - on the other hand, rules are not expected to change very dynamically
 */
const uint32_t KR_RULE_TTL_DEFAULT = 300;

const kr_rule_opts_t KR_RULE_OPTS_DEFAULT = { .score = KR_RULE_SCORE_DEFAULT, /*and zeros*/ };

/* DB key-space summary

 - "\0" starts special keys like "\0rulesets" or "\0stamp"
  - "\0tagBits" -> kr_rule_tags_t denoting the set of tags that have a name in DB
  - "\0tag_" + tag name -> one byte with the tag's number
  - "\0tagI_" + one byte with the tag's number -> tag name (incl. final zero)
 - some future additions?
 - otherwise it's rulesets - each has a prefix, e.g. RULESET_DEFAULT,
   its length is bounded by KEY_RULESET_MAXLEN - 1; after that prefix:
    - KEY_EXACT_MATCH + dname_lf ended by double '\0' + KNOT_RRTYPE_FOO
	-> exact-match rule (for the given name)
    - KEY_ZONELIKE_A  + dname_lf (no '\0' at end)
	-> zone-like apex (on the given name)
    - KEY_VIEW_SRC4 or KEY_VIEW_SRC6 + subnet_encode()
	-> conditions + action-rule string; see kr_view_insert_action()
 */

/// We put basically everything into this ruleset.
/*const*/ char RULESET_DEFAULT[] = "d";
/// _START is only used for VAL_ZLAT_UNBLOCK (in KEY_ZONELIKE_A) and only once per kr_request.
/*const*/ char RULESET_START[] = "1";
/*const*/ char RULESETS_ALL[] = "1\0d";

static const uint8_t KEY_EXACT_MATCH[1] = "e";
static const uint8_t KEY_ZONELIKE_A [1] = "a";

static const uint8_t KEY_VIEW_SRC4[1] = "4";
static const uint8_t KEY_VIEW_SRC6[1] = "6";


/// Returns for functions below: RET_ANSWERED, RET_CONTINUE, negative error codes for bugs
enum ret_codes_ {
	RET_CONT_CACHE = 0,
	RET_ANSWERED = 1,
	RET_CONTINUE = 2,
};

static int answer_exact_match(struct kr_query *qry, knot_pkt_t *pkt, uint16_t type,
		knot_db_val_t *val);
static int answer_zla_empty(val_zla_type_t type, struct kr_query *qry, knot_pkt_t *pkt,
				const knot_dname_t apex_name[], uint32_t ttl);
static int answer_zla_dname(val_zla_type_t type, struct kr_query *qry, knot_pkt_t *pkt,
				const knot_dname_t apex_name[], uint32_t ttl, knot_db_val_t *val);
static int answer_zla_redirect(struct kr_query *qry, knot_pkt_t *pkt, const char *ruleset_name,
				/*const*/ knot_dname_t apex_name[], uint32_t ttl);
static int rule_local_subtree(const knot_dname_t *apex, enum kr_rule_sub_t type,
				const knot_dname_t *target, uint32_t ttl,
				kr_rule_tags_t tags, kr_rule_opts_t opts);

static void qry_set_action(struct kr_query *qry, enum kr_request_rule_action action)
{
	// We only set the action if applying on the original QNAME
	// or the CNAME chain leading from it, not on any other sub-queries.
	const struct kr_query *q = qry;
	while (q->cname_parent)
		q = q->cname_parent;
	if (q->parent)
		return;
	qry->request->rule.action = action;
}

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
	return ruledb_op(write, &key, &val, 1); // we got ENOENT, so simple write is OK
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
		*tagset |= ((kr_rule_tags_t)1 << *tindex_p);
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
	const int ix = ffsll(~bmp) - 1;
	if (ix < 0 || ix >= 8 * sizeof(bmp))
		return kr_error(E2BIG);
	const kr_rule_tags_t tag_new = (kr_rule_tags_t)1 << ix;
	kr_require((tag_new & bmp) == 0);

	// Update the bitmap.  ATM ruledb does not overwrite, so we `remove` before `write`.
	bmp |= tag_new;
	val.data = &bmp;
	val.len = sizeof(bmp);
	ret = ruledb_op(remove, &key_tb, 1);  kr_assert(ret == 1);
	ret = ruledb_op(write, &key_tb, &val, 1);
	if (ret != 0)
		return kr_error(ret);
	// Record this tag's mapping.
	uint8_t ix_8t = ix;
	val.data = &ix_8t;
	val.len = sizeof(ix_8t);
	ret = ruledb_op(write, &key, &val, 1); // key remained correct since ENOENT
	if (ret != 0)
		return kr_error(ret);
	// Record this tag's reverse mapping (bit-index -> name).
	uint8_t key2_buf[] = "\0tagI_";
	key2_buf[sizeof(key2_buf) -1] = ix_8t; // rewrite the terminating '\0'
	knot_db_val_t key2 = { .data = key2_buf, .len = sizeof(key2_buf) };
	knot_db_val_t val2 = {
		.data = (char *)/*const-cast*/tag,
		.len = tag_len + 1, // include the final '\0'
	};
	ret = ruledb_op(write, &key2, &val2, 1);
	if (ret != 0)
		return kr_error(ret);
	// Success!
	*tagset |= tag_new;
	return kr_ok();
}

/// Get a tag's name by its index (bitmap with value 1 means index 0).
static const char * kr_rule_tag_ix2name(uint8_t tag_ix)
{
	uint8_t key2_buf[] = "\0tagI_";
	key2_buf[sizeof(key2_buf) -1] = tag_ix; // rewrite the terminating '\0'
	knot_db_val_t key2 = { .data = key2_buf, .len = sizeof(key2_buf) };
	knot_db_val_t val2;
	int ret = ruledb_op(read, &key2, &val2, 1);
	const char *name = val2.data;
	bool ok = ret == 0
		&& !kr_fails_assert(val2.len > 0 && strnlen(name, val2.len) == val2.len - 1);
	if (!ok) {
		errno = abs(ret);
		return NULL;
	}
	return name;
}
char * kr_rule_tags2str(kr_rule_tags_t tagset)
{
	if (tagset == KR_RULE_TAGS_ALL)
		return calloc(1, 1); // new empty string
	int ix = ffsll(tagset) - 1;
	if (kr_fails_assert(ix >= 0))
		return NULL;
	const char *name = kr_rule_tag_ix2name(ix);
	if (!name)
		return NULL;
	return strdup(name);
}

int kr_rules_init_ensure(void)
{
	if (the_rules)
		return kr_ok();
	return kr_rules_init(NULL, 0, true);
}
int kr_rules_init(const char *path, size_t maxsize, bool overwrite)
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
		.maxsize = !overwrite ? 0 :
			(maxsize ? maxsize : (size_t)(sizeof(size_t) > 4 ? 2048 : 500) * 1024*1024),
	};
	int ret = the_rules->api->open(&the_rules->db, &the_rules->stats, &opts, NULL);

	if (ret == 0 && overwrite) ret = ruledb_op(clear);
	if (ret != 0) goto failure;
	kr_require(the_rules->db);

	if (!overwrite) return kr_ok(); // we assume that the caller ensured OK contents

	ret = tag_names_default();
	if (ret != 0) goto failure;

	ret = rules_defaults_insert();
	if (ret != 0) goto failure;

	/* Activate one default ruleset. */
	uint8_t key_rs[] = "\0rulesets";
	knot_db_val_t key = { .data = key_rs, .len = sizeof(key_rs) };
	knot_db_val_t rulesets = { .data = &RULESETS_ALL, .len = sizeof(RULESETS_ALL) };
	ret = ruledb_op(remove, &key, 1);  kr_assert(ret == 0 || ret == 1);
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
	return ruledb_op(commit, accept, false);
}

int kr_rules_reset(void)
{
	if (!the_rules) return kr_error(EINVAL);
	return ruledb_op(commit, false, true);
}

/** Eat and process tags from *val.
 *
 * Returning true means that the rule should apply,
 * and it requires the caller to fill req->rule.action later.
 */
static bool kr_rule_consume_tags(knot_db_val_t *val, struct kr_request *req, bool allow_audit)
{
	kr_rule_tags_t tags;
	if (deserialize_fails_assert(val, &tags)) {
		val->len = 0;
		/* We may not fail immediately, but further processing
		 * will fail anyway due to zero remaining length. */
		return false;
	}
	// _apply tags take precendence, and we store the last one
	kr_rule_tags_t const tags_apply = tags & req->rule_tags_apply;
	if (tags == KR_RULE_TAGS_ALL || tags_apply) {
		req->rule.tags = tags_apply;
		return true;
	}
	// _audit: we fill everything iff we're the very first action
	kr_rule_tags_t const tags_audit = tags & req->rule_tags_audit;
	if (allow_audit && tags_audit && !req->rule.action) {
		req->rule.tags = tags_audit;
		req->rule.action = KREQ_ACTION_AUDIT;
	}
	return false;
}






/// Log that we apply a local-data rule (if desired)
// TODO: we might parametrize by some log string that expresses e.g. the type of rule
static void log_rule(kr_rule_opts_t opts, const struct kr_query *qry)
{
	const struct kr_request *req = qry->request;
	const int level = map_log_level(opts.log_level);
	bool do_log = opts.score >= req->rule_score_log
		&& (kr_log_is_debug(RULES, req) || KR_LOG_LEVEL_IS(level));
	if (!do_log)
		return;
	bool applied = opts.score >= req->rule_score_apply;

	//// Let's construct the log message, piece by piece in `s**` variables.
	const char * s1a = "=> local data ",
		*s1b = applied ? "applied" : "dry-run";

	const char *s2a = "";
	char s2b[INET6_ADDRSTRLEN + 1] = "";
	if (opts.log_ip) {
		s2a = ", user: ";
		const struct sockaddr *addr = req->qsource.addr;
		if (addr) {
			bool ok = inet_ntop(addr->sa_family, kr_inaddr(addr), s2b, sizeof(s2b));
			kr_assert(ok);
		} else {
			strcpy(s2b, "internal");
		}
	}

	const char *s3a = "";
	char s3b[KR_DNAME_STR_MAXLEN] = "";
	if (opts.log_name) {
		s3a = ", name: ";
		knot_dname_to_str(s3b, qry->sname, sizeof(s3b));
		s3b[sizeof(s3b) - 1] = 0;
	}

	kr_log_fmt(LOG_GRP_RULES, level, SD_JOURNAL_METADATA,
		"[%-6s] %s%s%s%s%s%s\n",
		LOG_GRP_RULES_TAG, s1a, s1b, s2a, s2b, s3a, s3b);
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

/// FIXME: describe?  For now, just a part of the call site, torn out separately.
static int subtree_search(const size_t lf_start_i, const knot_db_val_t key,
				const char * const ruleset_name,
			 	struct kr_query *qry, knot_pkt_t *pkt)
{
	struct kr_request * const req = qry->request;
	kr_require(lf_start_i < KEY_MAXLEN);
	knot_db_val_t key_leq = key;
	knot_db_val_t val;
	if (qry->stype == KNOT_RRTYPE_DS)
		goto shorten; // parent-side type, belongs into zone closer to root
	// LATER: again, use cursor to iterate over multiple rules on the same key.
	do {
		int ret = ruledb_op(read_leq, &key_leq, &val);
		if (ret == -ENOENT) return RET_CONTINUE;
		if (ret < 0) return kr_error(ret);
		if (ret > 0) { // found a previous key
			size_t cs_len = key_common_subtree(key, key_leq, lf_start_i);
			if (cs_len < lf_start_i) // no suitable key can exist in DB
				return RET_CONTINUE;
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

		// Found some good key, now get the ZLA type,
		// and deal with the special _FORWARD case.
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

		// Let's never audit _UNBLOCK actions.
		const bool allow_audit = ztype != VAL_ZLAT_UNBLOCK;
		// The other ztype possibilities are similar; check the tags now.
		if (!kr_rule_consume_tags(&val, req, allow_audit)) {
			kr_assert(key_leq.len >= lf_start_i);
		shorten:
			// Shorten key_leq by one label and retry.
			if (key_leq.len <= lf_start_i) // nowhere to shorten
				return RET_CONTINUE;
			const char *data = key_leq.data;
			while (key_leq.len > lf_start_i && data[--key_leq.len] != '\0') ;
			continue;
		}

		// Unblock rules also don't have opts+ttl.
		if (ztype == VAL_ZLAT_UNBLOCK) {
			kr_request_unblock(req);
			VERBOSE_MSG(qry, "=> unblocked\n");
			if (kr_fails_assert(val.len == 0))
				kr_log_error(RULES, "ERROR: unused bytes: %zu\n", val.len);
			// nothing to search, as RULESET_START is dedicated to all _UNBLOCK
			return RET_CONTINUE;
		}

		// Process opts.
		kr_rule_opts_t opts;
		if (deserialize_fails_assert(&val, &opts))
			return kr_error(EILSEQ);
		if (opts.is_block && kr_request_unblocked(req))
			goto shorten; // continue looking for rules
		log_rule(opts, qry);
		if (opts.score < req->rule_score_apply)
			goto shorten; // continue looking for rules

		// The non-forward types optionally specify TTL.
		uint32_t ttl = KR_RULE_TTL_DEFAULT;
		if (val.len >= sizeof(ttl)) // allow omitting -> can't kr_assert
			deserialize_fails_assert(&val, &ttl);

		knot_dname_t apex_name[KNOT_DNAME_MAXLEN];
		ret = knot_dname_lf2wire(apex_name, zla_lf.len, zla_lf.data);
		// kr_require(zla_lf.len + 2 == knot_dname_size(apex_name));
		if (ret < 0) return kr_error(ret);

		// Finally execute the rule.
		switch (ztype) {
		case KR_RULE_SUB_EMPTY:
		case KR_RULE_SUB_NXDOMAIN:
		case KR_RULE_SUB_NODATA:
			ret = answer_zla_empty(ztype, qry, pkt, apex_name, ttl);
			break;
		case KR_RULE_SUB_REDIRECT:
			ret = answer_zla_redirect(qry, pkt, ruleset_name, apex_name, ttl);
			break;
		case KR_RULE_SUB_DNAME:
			ret = answer_zla_dname(ztype, qry, pkt, apex_name, ttl, &val);
			break;
		default:
			return kr_error(EILSEQ);
		}
		if (kr_fails_assert(val.len == 0)) {
			kr_log_error(RULES, "ERROR: unused bytes: %zu\n", val.len);
			return kr_error(EILSEQ);
		}
		if (ret == kr_error(EAGAIN))
			goto shorten;
		return ret ? kr_error(ret) : RET_ANSWERED;
	} while (true);
}

int rule_local_data_answer(struct kr_query *qry, knot_pkt_t *pkt)
{
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

		// RULESET_START only applies once per kr_request,
		// and it doesn't do exact matches
		if (strcmp(ruleset_name, RULESET_START) == 0) {
			if (qry->parent) {
				continue;
			} else {
				goto skip_exact;
			}
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
			// Multiple variants are possible, with different tags.
			for (ret = ruledb_op(it_first, &key, &val);
					ret == 0;
					ret = ruledb_op(it_next, &val)) {
				if (!kr_rule_consume_tags(&val, qry->request, true))
					continue;

				// We found a rule that applies to the dname+rrtype+req.
				ret = answer_exact_match(qry, pkt, types[i], &val);
				if (ret != RET_CONTINUE)
					return ret;
			}
			if (kr_fails_assert(ret == 0 || ret == -ENOENT))
				return kr_error(ret);
		}
	skip_exact:;
		/* Find the closest zone-like apex that applies.
		 * Now the key needs one byte change and a little truncation */
		static_assert(sizeof(KEY_ZONELIKE_A) == sizeof(KEY_EXACT_MATCH),
				"bad combination of constants");
		memcpy(key_data_ruleset_end, &KEY_ZONELIKE_A, sizeof(KEY_ZONELIKE_A));
		key.len = key_data + KEY_DNAME_END_OFFSET - (uint8_t *)key.data;
		const size_t lf_start_i = key_data_ruleset_end + sizeof(KEY_ZONELIKE_A)
					- (const uint8_t *)key.data;

		ret = subtree_search(lf_start_i, key, ruleset_name, qry, pkt);
		if (ret != RET_CONTINUE)
			return ret;
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
		knot_db_val_t *val)
{
	/* Process opts. */
	kr_rule_opts_t opts;
	if (deserialize_fails_assert(val, &opts))
		return kr_error(EILSEQ);
	if (opts.is_block && kr_request_unblocked(qry->request))
		return RET_CONTINUE;
	log_rule(opts, qry);
	if (opts.score < qry->request->rule_score_apply)
		return RET_CONTINUE;

	uint32_t ttl;
	if (deserialize_fails_assert(val, &ttl))
		return kr_error(EILSEQ);

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
	ret = rdataset_materialize_val(&arrset.set.rr->rrs, val, &pkt->mm);
	CHECK_RET(ret);
	arrset.set.rank = KR_RANK_SECURE | KR_RANK_AUTH; // local data has high trust
	arrset.set.expiring = false;
	/* Materialize the RRSIG RRset for the answer in (pseudo-)packet.
	 * (There will almost never be any RRSIG.) */
	ret = rdataset_materialize_val(&arrset.sig_rds, val, &pkt->mm);
	CHECK_RET(ret);

	/* Sanity check: we consumed exactly all data. */
	if (kr_fails_assert(val->len == 0)) {
		kr_log_error(RULES, "ERROR: unused bytes: %zu\n", val->len);
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
	qry_set_action(qry, is_nodata ? KREQ_ACTION_NODATA : KREQ_ACTION_LOCAL_DATA);
	return RET_ANSWERED;
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
				kr_rule_tags_t tags, kr_rule_opts_t opts)
{
	ENSURE_the_rules;
	// Construct the DB key.
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = local_data_key(rrs, key_data, RULESET_DEFAULT);
	return local_data_ins(key, rrs, sig_rds, tags, opts);
}
int local_data_ins(knot_db_val_t key, const knot_rrset_t *rrs, const knot_rdataset_t *sig_rds,
			kr_rule_tags_t tags, kr_rule_opts_t opts)
{
	// Prepare the data into a temporary buffer.
	const int rr_ssize = rdataset_dematerialize_size(&rrs->rrs);
	const int val_len = sizeof(tags) + sizeof(opts) + sizeof(rrs->ttl) + rr_ssize
				+ rdataset_dematerialize_size(sig_rds);
	uint8_t buf[val_len], *data = buf;
	memcpy(data, &tags, sizeof(tags));
	data += sizeof(tags);
	memcpy(data, &opts, sizeof(opts));
	data += sizeof(opts);
	memcpy(data, &rrs->ttl, sizeof(rrs->ttl));
	data += sizeof(rrs->ttl);
	rdataset_dematerialize(&rrs->rrs, data);
	data += rr_ssize;
	rdataset_dematerialize(sig_rds, data);

	knot_db_val_t val = { .data = buf, .len = val_len };
	int ret = ruledb_op(write, &key, &val, 1); // TODO: overwriting on ==tags?
	// ENOSPC seems to be the only expectable error.
	kr_assert(ret == 0 || ret == kr_error(ENOSPC));

	if (ret || rrs->type != KNOT_RRTYPE_DNAME)
		return ret;
	// Now we do special handling for DNAMEs
	//  - we inserted as usual, so that it works with QTYPE == DNAME
	//  - now we insert a ZLA to handle generating CNAMEs
	//  - yes, some edge cases won't work as in real DNS zones (e.g. occlusion)
	if (kr_fails_assert(rrs->rrs.count))
		return kr_error(EINVAL);
	return rule_local_subtree(rrs->owner, KR_RULE_SUB_DNAME,
				knot_dname_target(rrs->rrs.rdata), rrs->ttl, tags, opts);
}
int kr_rule_local_data_del(const knot_rrset_t *rrs, kr_rule_tags_t tags)
{
	ENSURE_the_rules;
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = local_data_key(rrs, key_data, RULESET_DEFAULT);
	return ruledb_op(remove, &key, 1);
}
int kr_rule_local_data_merge(const knot_rrset_t *rrs, const kr_rule_tags_t tags, kr_rule_opts_t opts)
{
	ENSURE_the_rules;
	// Construct the DB key.
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = local_data_key(rrs, key_data, RULESET_DEFAULT);
	knot_db_val_t val;
	// Transaction: we assume that we're in a RW transaction already,
	// so that here we already "have a lock" on the last version.
	// FIXME: iterate over multiple tags, once iterator supports RW TXN
	int ret = ruledb_op(read, &key, &val, 1);
	if (abs(ret) == abs(ENOENT))
		goto fallback;
	if (ret)
		return kr_error(ret);
	// check tags
	kr_rule_tags_t tags_old;
	if (deserialize_fails_assert(&val, &tags_old) || tags_old != tags)
		goto fallback;
	kr_rule_opts_t opts_old;
	if (deserialize_fails_assert(&val, &opts_old))
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
	ret = local_data_ins(key, &rrs_new, NULL, tags, opts);
	mm_ctx_delete(mm);
	return ret;
fallback:
	return local_data_ins(key, rrs, NULL, tags, opts);
}

/** Empty or NXDOMAIN or NODATA.  Returning kr_error(EAGAIN) means the rule didn't match. */
static int answer_zla_empty(val_zla_type_t type, struct kr_query *qry, knot_pkt_t *pkt,
				const knot_dname_t apex_name[], uint32_t ttl)
{
	if (kr_fails_assert(type == KR_RULE_SUB_EMPTY || type == KR_RULE_SUB_NXDOMAIN
				|| type == KR_RULE_SUB_NODATA))
		return kr_error(EINVAL);

	const bool hit_apex = knot_dname_is_equal(qry->sname, apex_name);
	if (hit_apex && type == KR_RULE_SUB_NODATA)
		return kr_error(EAGAIN);

	/* Start constructing the (pseudo-)packet. */
	int ret = pkt_renew(pkt, qry->sname, qry->stype);
	CHECK_RET(ret);
	struct answer_rrset arrset;
	memset(&arrset, 0, sizeof(arrset));

	/* Construct SOA or NS data (hardcoded content).  _EMPTY has a proper zone apex. */
	const bool want_NS = hit_apex && type == KR_RULE_SUB_EMPTY
				&& qry->stype == KNOT_RRTYPE_NS;
	arrset.set.rr = knot_rrset_new(apex_name, want_NS ? KNOT_RRTYPE_NS : KNOT_RRTYPE_SOA,
					KNOT_CLASS_IN, ttl, &pkt->mm);
	if (kr_fails_assert(arrset.set.rr))
		return kr_error(ENOMEM);
	if (want_NS) {
		// TODO: maybe it's weird to use this NS name, but what else?
		ret = knot_rrset_add_rdata(arrset.set.rr,
					   apex_name, knot_dname_size(apex_name), &pkt->mm);
	} else {
		ret = knot_rrset_add_rdata(arrset.set.rr, soa_rdata,
						sizeof(soa_rdata) - 1, &pkt->mm);
	}
	CHECK_RET(ret);
	arrset.set.rank = KR_RANK_SECURE | KR_RANK_AUTH; // local data has high trust
	arrset.set.expiring = false;

	/* Small differences if we exactly hit the name or even type. */
	if (type == KR_RULE_SUB_NODATA || (type == KR_RULE_SUB_EMPTY && hit_apex)) {
		knot_wire_set_rcode(pkt->wire, KNOT_RCODE_NOERROR);
	} else {
		knot_wire_set_rcode(pkt->wire, KNOT_RCODE_NXDOMAIN);
	}
	if (type == KR_RULE_SUB_EMPTY && hit_apex
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

	if (knot_wire_get_rcode(pkt->wire) == KNOT_RCODE_NXDOMAIN) {
		qry_set_action(qry, KREQ_ACTION_NXDOMAIN);
	} else if (pkt->current == KNOT_ANSWER) {
		qry_set_action(qry, KREQ_ACTION_LOCAL_DATA);
	} else {
		qry_set_action(qry, KREQ_ACTION_NODATA);
	}

	VERBOSE_MSG(qry, "=> satisfied by local data (%s zone)\n",
		     type == KR_RULE_SUB_EMPTY ? "empty" : "nxdomain");
	return kr_ok();
}
int kr_rule_do_answer(enum kr_rule_sub_t type, struct kr_query *qry, knot_pkt_t *pkt,
				const knot_dname_t apex_name[])
{
	return answer_zla_empty(type, qry, pkt, apex_name, KR_RULE_TTL_DEFAULT);
}

static int answer_zla_dname(val_zla_type_t type, struct kr_query *qry, knot_pkt_t *pkt,
				const knot_dname_t apex_name[], uint32_t ttl, knot_db_val_t *val)
{
	if (kr_fails_assert(type == KR_RULE_SUB_DNAME))
		return kr_error(EINVAL);
	
	const knot_dname_t *dname_target = val->data;
	// Theoretically this check could overread the val->len, but that's OK,
	// as the policy DB contents wouldn't be directly written by a malicious party.
	// Moreover, an overread shouldn't cause worse than a clean segfault.
	if (kr_fails_assert(knot_dname_size(dname_target) == val->len))
		return kr_error(EILSEQ);
	{ // update *val; avoiding void* arithmetics complicates this
		char *tmp = val->data;
		tmp += val->len;
		val->data = tmp;

		val->len = 0;
	}

	const bool hit_apex = knot_dname_is_equal(qry->sname, apex_name);
	if (hit_apex && type == KR_RULE_SUB_DNAME)
		return kr_error(EAGAIN); // LATER: maybe a type that matches apex

	// Start constructing the (pseudo-)packet.
	int ret = pkt_renew(pkt, qry->sname, qry->stype);
	CHECK_RET(ret);
	struct answer_rrset arrset;
	memset(&arrset, 0, sizeof(arrset));

	arrset.set.rr = knot_rrset_new(qry->sname, KNOT_RRTYPE_CNAME,
					KNOT_CLASS_IN, ttl, &pkt->mm);
	if (kr_fails_assert(arrset.set.rr))
		return kr_error(ENOMEM);
	const knot_dname_t *cname_target = knot_dname_replace_suffix(qry->sname,
			knot_dname_labels(apex_name, NULL), dname_target, &pkt->mm);
	const int rdata_len = knot_dname_size(cname_target);
	const bool cname_fits = rdata_len <= KNOT_DNAME_MAXLEN;
	if (cname_fits) {
		ret = knot_rrset_add_rdata(arrset.set.rr, cname_target,
					  knot_dname_size(cname_target), &pkt->mm);
		CHECK_RET(ret);
	}

	arrset.set.rank = KR_RANK_SECURE | KR_RANK_AUTH; // local data has high trust
	arrset.set.expiring = false;

	if (cname_fits) {
		knot_wire_set_rcode(pkt->wire, KNOT_RCODE_NOERROR);
		ret = knot_pkt_begin(pkt, KNOT_ANSWER);
		CHECK_RET(ret);

		// Put links to the RR into the pkt.
		ret = pkt_append(pkt, &arrset);
		CHECK_RET(ret);
	} else {
		knot_wire_set_rcode(pkt->wire, KNOT_RCODE_YXDOMAIN);
	}

	// Finishing touches.
	qry->flags.EXPIRING = false;
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;
	qry_set_action(qry, KREQ_ACTION_LOCAL_DATA);

	VERBOSE_MSG(qry, "=> satisfied by local data (DNAME)\n");
	return kr_ok();
}

static int answer_zla_redirect(struct kr_query *qry, knot_pkt_t *pkt, const char *ruleset_name,
				knot_dname_t apex_name[], uint32_t ttl)
{
	VERBOSE_MSG(qry, "=> redirecting by local data\n"); // lazy to get the zone name

	const bool name_matches = knot_dname_is_equal(qry->sname, apex_name);
	if (name_matches || qry->stype == KNOT_RRTYPE_NS || qry->stype == KNOT_RRTYPE_SOA)
		goto nodata;

	// Reconstruct the DB key from scratch.
	knot_rrset_t rrs;
	knot_rrset_init(&rrs, apex_name, qry->stype, 0, 0); // 0 are unused
	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = local_data_key(&rrs, key_data, ruleset_name);

	knot_db_val_t val;
	int ret;
	// Multiple variants are possible, with different tags.
	for (ret = ruledb_op(it_first, &key, &val); ret == 0; ret = ruledb_op(it_next, &val)) {
		const bool allow_audit = false; // we just audited at _REDIRECT root
		if (kr_rule_consume_tags(&val, qry->request, allow_audit)) {
			int ret2 = answer_exact_match(qry, pkt, qry->stype, &val);
			if (ret2 != RET_CONTINUE)
				return ret2;
		}
	}
	if (ret && ret != -ENOENT)
		return ret;

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

	if (sec == KNOT_ANSWER) {
		qry_set_action(qry, KREQ_ACTION_LOCAL_DATA);
	} else {
		qry_set_action(qry, KREQ_ACTION_NODATA);
	}

	VERBOSE_MSG(qry, "=> satisfied by local data (no data)\n");
	return kr_ok();
}

int kr_rule_local_subtree(const knot_dname_t *apex, enum kr_rule_sub_t type,
			  uint32_t ttl, kr_rule_tags_t tags, kr_rule_opts_t opts)
{
	return rule_local_subtree(apex, type, NULL, ttl, tags, opts);
}
knot_db_val_t zla_key(const knot_dname_t *apex, uint8_t key_data[KEY_MAXLEN], const char ruleset[])
{
	kr_require(the_rules);
	knot_db_val_t key;
	key.data = key_dname_lf(apex, key_data);

	key.data -= sizeof(KEY_ZONELIKE_A);
	memcpy(key.data, &KEY_ZONELIKE_A, sizeof(KEY_ZONELIKE_A));

	const size_t rsp_len = strlen(ruleset);
	key.data -= rsp_len;
	memcpy(key.data, ruleset, rsp_len);
	key.len = key_data + KEY_DNAME_END_OFFSET - (uint8_t *)key.data;
	return key;
}
static int rule_local_subtree(const knot_dname_t *apex, enum kr_rule_sub_t type,
				const knot_dname_t *target, uint32_t ttl,
				kr_rule_tags_t tags, kr_rule_opts_t opts)
{
	// type-check
	const bool has_target = (type == KR_RULE_SUB_DNAME);
	switch (type) {
	case KR_RULE_SUB_DNAME:
		if (kr_fails_assert(!!target == has_target))
			return kr_error(EINVAL);
		break;
	case KR_RULE_SUB_EMPTY:
	case KR_RULE_SUB_NXDOMAIN:
	case KR_RULE_SUB_NODATA:
	case KR_RULE_SUB_REDIRECT:
		break;
	default:
		kr_assert(false);
		return kr_error(EINVAL);
	}
	const val_zla_type_t ztype = type;

	ENSURE_the_rules;

	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = zla_key(apex, key_data, RULESET_DEFAULT);

	// Prepare the data into a temporary buffer.
	const int target_len = has_target ? knot_dname_size(target) : 0;
	const bool has_ttl = ttl != KR_RULE_TTL_DEFAULT || has_target;
	const int val_len = sizeof(ztype) + sizeof(tags) + sizeof(opts)
			  + (has_ttl ? sizeof(ttl) : 0) + target_len;
	uint8_t buf[val_len], *data = buf;
	memcpy(data, &ztype, sizeof(ztype));
	data += sizeof(ztype);
	memcpy(data, &tags, sizeof(tags));
	data += sizeof(tags);
	memcpy(data, &opts, sizeof(opts));
	data += sizeof(opts);
	if (has_ttl) {
		memcpy(data, &ttl, sizeof(ttl));
		data += sizeof(ttl);
	}
	if (has_target) {
		memcpy(data, target, target_len);
		data += target_len;
	}
	kr_require(data == buf + val_len);

	knot_db_val_t val = { .data = buf, .len = val_len };
	int ret = ruledb_op(write, &key, &val, 1); // TODO: overwriting on ==tags?
	// ENOSPC seems to be the only expectable error.
	kr_assert(ret == 0 || ret == kr_error(ENOSPC));
	return ret;
}

int kr_rule_local_unblock(const knot_dname_t *apex, kr_rule_tags_t tags)
{
	ENSURE_the_rules;

	const val_zla_type_t ztype = VAL_ZLAT_UNBLOCK;
	enum { val_len = sizeof(ztype) + sizeof(tags) };

	uint8_t key_data[KEY_MAXLEN];
	knot_db_val_t key = zla_key(apex, key_data, RULESET_START);

	// Maybe the name is there already?  Read it and combine the tags.
	knot_db_val_t val = { 0 };
	int ret = ruledb_op(read, &key, &val, 1);
	kr_assert(ret == 0 || ret == kr_error(ENOENT));
	if (ret == 0) {
		if (kr_fails_assert(val.len == val_len))
			return kr_error(EINVAL);
		kr_rule_tags_t tags_old;
		uint8_t *data = val.data + sizeof(ztype);
		memcpy(&tags_old, data, sizeof(tags_old));
		tags = kr_rule_tags_combine(tags, tags_old);
		// ATM ruledb does not overwrite, so we `remove` before `write`.
		ret = ruledb_op(remove, &key, 1);
		kr_assert(ret == 1);
	}

	// Construct the data to write
	uint8_t buf[val_len], *data = buf;
	memcpy(data, &ztype, sizeof(ztype));
	data += sizeof(ztype);
	memcpy(data, &tags, sizeof(tags));
	data += sizeof(tags);
	kr_require(data == buf + val_len);

	val.data = buf;
	val.len = val_len;
	ret = ruledb_op(write, &key, &val, 1);
	// ENOSPC seems to be the only expectable error.
	kr_assert(ret == 0 || ret == kr_error(ENOSPC));
	return ret;
}


/** Encode a subnet into a (longer) string.  The result is in `buf` with returned length.
 *
 * The point is to have different encodings for different subnets,
 * with using just byte-length strings (e.g. for ::/1 vs. ::/2).
 * You might imagine this as the space of all nodes of a binary trie.
 *
 * == Key properties ==
 * We're utilizing the order on the encoded strings.  LMDB uses lexicographical order.
 * Optimization: the properties should cut down LMDB operation count when searching
 * for rule sets typical in practice.  Some properties:
 *  - full address is just a subnet containing only that address (/128 and /32)
 *  - order of full addresses is kept the same as before encoding
 *  - ancestor first: if subnet B is included inside subnet A, we get A < B
 *  - subnet mixing: if two subnets do not share any address, all addresses of one
 *    of them are ordered before all addresses of the other one
 *
 * == The encoding ==
 * The encoding replaces each address bit by a pair of bits:
 *  - 00 -> beyond the subnet's prefix
 *  - 10 -> zero bit within the subnet's prefix
 *  - 11 ->  one bit within the subnet's prefix
 *  - we cut the byte-length - no need for all-zero suffixes
 */
static int subnet_encode(const struct sockaddr *addr, int sub_len, uint8_t buf[32])
{
	const int len = kr_inaddr_len(addr);
	if (kr_fails_assert(len > 0))
		return kr_error(len);
	if (kr_fails_assert(sub_len >= 0 && sub_len <= 8 * len))
		return kr_error(EINVAL);
	const uint8_t *a = (const uint8_t *)/*sign*/kr_inaddr(addr);

	int i;
	// Let's hope that compiler optimizes this into something reasonable.
	for (i = 0; sub_len > 0; ++i, sub_len -= 8) {
		// r = a[i] interleaved by 1 bits (with 1s on the higher-value positions)
		// https://graphics.stanford.edu/~seander/bithacks.html#Interleave64bitOps
		// but we modify it slightly: no need for the 0x5555 mask (==0b0101010101010101)
		// or the y-part - we instead just set all odd bits to 1s.
		uint16_t r = (
			(a[i] * 0x0101010101010101ULL & 0x8040201008040201ULL)
				* 0x0102040810204081ULL >> 49
		        ) | 0xAAAAU/* = 0b1010'1010'1010'1010 */;
		// now r might just need clipping
		if (sub_len < 8) {
			uint16_t mask = 0xFFFFffffU << (2 * (8 - sub_len));
			r &= mask;
		}
		buf[(ssize_t)2*i] = r / 256;
		buf[(ssize_t)2*i + 1] = r % 256;
	}
	return i * 2;
}

// Is `a` subnet-prefix of `b`?  (a byte format of subnet_encode())
static bool subnet_is_prefix(uint8_t a, uint8_t b)
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
		(key).data -= sizeof(arr); \
		(key).len  += sizeof(arr); \
		memcpy((key).data, arr, sizeof(arr)); \
	} while (false)

int kr_view_insert_action(const char *subnet, const char *dst_subnet,
			kr_proto_set protos, const char *action)
{
	if (*dst_subnet == '\0') dst_subnet = NULL; // convenience for the API
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

	// We have the key; start constructing the value to insert.
	const int dst_maxlen = 1 + (dst_subnet ? kr_family_len(saddr.ip.sa_family) : 0);
	const int action_len = strlen(action);
	uint8_t buf[sizeof(protos) + dst_maxlen + action_len];
	uint8_t *data = buf;
	int dlen = 0;

	memcpy(data, &protos, sizeof(protos));
	data += sizeof(protos);
	dlen += sizeof(protos);

	uint8_t dst_bitlen = 0;
	if (dst_subnet) {
		// For simplicity, we always write the whole address,
		// even if some bytes at the end are useless (keep it iff dst_bitlen > 0).
		int ret = kr_straddr_subnet(data + sizeof(dst_bitlen), dst_subnet);
		if (ret < 0) {
			kr_log_error(RULES, "failed to parse destination subnet: %s\n",
					dst_subnet);
			return kr_error(ret);
		}
		if (saddr.ip.sa_family != kr_straddr_family(dst_subnet)) {
			kr_log_error(RULES,
				"destination subnet mismatching IPv4 vs. IPv6: %s\n",
				dst_subnet);
			return kr_error(EINVAL);
		}
		dst_bitlen = ret;
	}
	memcpy(data, &dst_bitlen, sizeof(dst_bitlen));
	if (dst_bitlen > 0) {
		data += dst_maxlen; // address bytes already written above
		dlen += dst_maxlen;
	} else {
		data += sizeof(dst_bitlen);
		dlen += sizeof(dst_bitlen);
	}

	memcpy(data, action, action_len);
	data += action_len;
	dlen += action_len;

	kr_require(data <= buf + dlen);
	knot_db_val_t val = { .data = buf, .len = dlen };
	return ruledb_op(write, &key, &val, 1);
}

static enum kr_proto req_proto(const struct kr_request *req)
{
	if (!req->qsource.addr)
		return KR_PROTO_INTERNAL;
	const struct kr_request_qsource_flags fl = req->qsource.flags;
	if (fl.http)
		return KR_PROTO_DOH;
	if (fl.tcp)
		return fl.tls ? KR_PROTO_DOT : KR_PROTO_TCP53;
	// UDP in some form
	return fl.tls ? KR_PROTO_DOQ : KR_PROTO_UDP53;
}
static bool req_proto_matches(const struct kr_request *req, kr_proto_set proto_set)
{
	if (!proto_set) // empty set always matches
		return true;
	kr_proto_set mask = 1 << req_proto(req);
	return mask & proto_set;
}
static void log_action(const struct kr_request *req, knot_db_val_t act)
{
	if (!kr_log_is_debug(RULES, req))
		return;
	// it's complex to get zero-terminated string for the action
	char act_0t[act.len + 1];
	memcpy(act_0t, act.data, act.len);
	act_0t[act.len] = 0;
	VERBOSE_MSG(req->rplan.initial, "=> view selected action: %s\n", act_0t);
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
	uint8_t * const key_data_end = key.data + key.len;
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
			key.len = key_data_end - (uint8_t *)key.data;
			memcpy(key.data, rulesets_str, rsp_len);
			rulesets_str += rsp_len + 1;
			rulesets.len -= rsp_len + 1;
		}

		static_assert(sizeof(KEY_VIEW_SRC4) == sizeof(KEY_VIEW_SRC6),
				"bad combination of constants");
		const size_t addr_start_i = key_data_ruleset_end + sizeof(KEY_VIEW_SRC4)
					- (const uint8_t *)key.data;

		knot_db_val_t key_leq = key;
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
			// But multiple variants are possible, and conditions inside values.
			for (ret = ruledb_op(it_first, &key_leq, &val);
					ret == 0;
					ret = ruledb_op(it_next, &val)) {
				kr_proto_set protos;
				if (deserialize_fails_assert(&val, &protos))
					continue;
				if (!req_proto_matches(req, protos))
					continue;
				uint8_t dst_bitlen;
				if (deserialize_fails_assert(&val, &dst_bitlen))
					continue;
				if (dst_bitlen) {
					const int abytes = kr_inaddr_len(addr);
					const char *dst_a = kr_inaddr(req->qsource.dst_addr);
					if (kr_fails_assert(val.len >= abytes))
						continue;
					if (kr_bitcmp(val.data, dst_a, dst_bitlen) != 0)
						continue;
					val.data += abytes;
					val.len  -= abytes;
				}
				// we passed everything; `val` contains just the action
				log_action(req, val);
				*selected = val;
				return kr_ok();
			}
			// Key matched but none of the condition variants;
			// we may still get a match with a wider subnet rule -> continue.
			// LATER(optim.): it's possible that something could be made
			//   somewhat faster in this various jumping around keys.
		}
	}
	return kr_error(ENOENT);
}
