/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include "lib/defines.h"
#include "lib/proto.h"
struct kr_query;
struct kr_request;
struct knot_pkt;
struct sockaddr;
#include <syslog.h>
#include <lib/utils.h>
#include <libknot/db/db.h>

/// Storage for a tag-set.  It's a bitmap, so 64 tags are supported now.
typedef uint64_t kr_rule_tags_t;
#define KR_RULE_TAGS_ALL ((kr_rule_tags_t)0)
/// Tags "capacity", i.e. numbered from 0 to _CAP - 1.
#define KR_RULE_TAGS_CAP (sizeof(kr_rule_tags_t) * 8)

/// Extra options for a rule (not for forwarding)
struct kr_rule_opts {
	/// Degree of severity for the rule;  FIXME: granularity, defaults, etc.
	uint8_t score : 4;

	bool log_ip : 1, log_name : 1;
	// +maybe log rule/QNAME/something
	/// Log level: 0 = debug, 1 = info, ...
	uint8_t log_level : 2;

	/** Maybe 2 bits: (unset), blocked, censored, filtered
	    https://www.rfc-editor.org/rfc/rfc8914.html#name-extended-dns-error-code-15-
	*/
	uint8_t ede_code : 2;
	/** Maybe 3 bits: (unset), Malware, Phishing, ... from
	    https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-structured-dns-error#name-new-registry-for-dns-sub-er
	*/
	uint8_t ede_sub : 3;
};
typedef struct kr_rule_opts kr_rule_opts_t;
static_assert(sizeof(kr_rule_opts_t) == 2, "kr_rule_opts_t size changed unexpectedly");
/// Default opts; in particular used for the RFC-mandated special-use names
KR_EXPORT extern const kr_rule_opts_t KR_RULE_OPTS_DEFAULT;
enum { // Default minimal score of a rule to log/apply it.
	KR_RULE_SCORE_LOG     =  3,
	KR_RULE_SCORE_APPLY   =  6,
	KR_RULE_SCORE_DEFAULT = 10,
};

static inline int map_log_level(uint8_t ll)
{
	switch (ll) {
	case 0: return LOG_DEBUG;
	case 1: return LOG_INFO;
	case 2: return LOG_NOTICE;
	case 3: return LOG_WARNING;
	}
	return LOG_DEBUG; // shouldn't happen
}

/** Open the rule DB.
 *
 * You can call this to override the path or size (NULL/0 -> default)
 * or choose not to overwrite the DB with just the defaults.
 *
 * \return error code.  Not allowed if already open (EINVAL),
 * so this optional call has to come before writing anything into the DB. */
KR_EXPORT
int kr_rules_init(const char *path, size_t maxsize, bool overwrite);
/** kr_rules_init() but OK if already open, and not allowing to override defaults. */
KR_EXPORT
int kr_rules_init_ensure(void);

KR_EXPORT
void kr_rules_deinit(void);

/** Commit or abort changes done to the rule DB so far.
 *
 * Normally commit happens only on successfully loading a config file.
 * However, an advanced user may get in trouble e.g. if calling resolve() from there,
 * causing even an assertion failure.  In that case they might want to commit explicitly.
 *
 * If only read-only transaction is open, this will NOT reset it to the newest data.
 */
KR_EXPORT
int kr_rules_commit(bool accept);

/** Reset to the latest version of rules committed in the DB.
 *
 * Note that this is not always a good idea.  For example, the `forward` rules
 * now use data from both the DB and lua config, so reloading only the DB
 * may lead to weird behavior in some cases.
 * (Modifications will also do this, as you can only modify the latest DB.)
 */
KR_EXPORT
int kr_rules_reset(void);

/** Try answering the query from local data; WIP: otherwise determine data source overrides.
 *
 * \return kr_error() on errors, >0 if answered, 0 otherwise (also when forwarding)
 *
 * FIXME: we probably want to ensure AA flags in answer as appropriate.
 *   Perhaps approach it like AD?  Tweak flags in ranked_rr_array_entry
 *   and at the end decide whether to set AA=1?
 */
int kr_rule_local_data_answer(struct kr_query *qry, struct knot_pkt *pkt);

/** Set up nameserver+cut if overridden by policy.  \return kr_error() */
int kr_rule_data_src_check(struct kr_query *qry, struct knot_pkt *pkt);

/** Select the view action to perform.
 *
 * \param selected The action string from kr_view_insert_action()
 * \return 0 or negative error code, in particular kr_error(ENOENT)
 */
KR_EXPORT
int kr_view_select_action(const struct kr_request *req, knot_db_val_t *selected);


/** Default TTL for answers from local data rules.
 *
 * This applies to rules defined by the user, not the default rules.
 * Some types of rules save space when using this default.
 * This definition exists mainly for usage from lua.
 */
KR_EXPORT extern
const uint32_t KR_RULE_TTL_DEFAULT;

/* APIs to modify the rule DB.
 *
 * FIXME:
 *  - overwriting semantics; often even the API docs is wrong here ATM
 *  - a way to read/modify a rule?
 */

/** Add a local data rule.
 *
 * Into the default rule-set ATM.
 * Special NODATA case: use a CNAME type with zero records (TTL matters). */
KR_EXPORT
int kr_rule_local_data_ins(const knot_rrset_t *rrs, const knot_rdataset_t *sig_rds,
				kr_rule_tags_t tags, kr_rule_opts_t opts);
/** Merge RRs into a local data rule.
 *
 * - FIXME: with multiple tags variants for the same name-type pair,
 *     you typically end up with a single RR per RRset
 * - RRSIGs get dropped, if any were attached.
 * - We assume that this is called with a RW transaction open already,
 *   which is always true in normal usage (long RW txn covering whole config).
 * - TODO: what if opts don't match?
 */
KR_EXPORT
int kr_rule_local_data_merge(const knot_rrset_t *rrs, kr_rule_tags_t tags, kr_rule_opts_t opts);

/** Add a name-address pair into rules.
 *
 * - both forward and reverse mapping is added
 * - merging is used; see kr_rule_local_data_merge()
 * - NODATA is optionally inserted
 */
KR_EXPORT
int kr_rule_local_address(const char *name, const char *addr, bool use_nodata,
				uint32_t ttl, kr_rule_tags_t tags, kr_rule_opts_t opts);

/** For a given name, remove one address  ##or all of them (if == NULL).
 *
 * Also remove the corresponding reverse record and (optionally) NODATA mark.
 * Bug: it removes the whole forward RRset.
 */
KR_EXPORT
int kr_rule_local_address_del(const char *name, const char *addr,
				bool use_nodata, kr_rule_tags_t tags);

/** Load name-address pairs into rules from a hosts-like file.
 *
 * Same as kr_rule_data_address() but from a file.
 */
KR_EXPORT
int kr_rule_local_hosts(const char *path, bool use_nodata, uint32_t ttl,
			kr_rule_tags_t tags, kr_rule_opts_t opts);

/** Remove a local data rule.
 *
 * \return the number of deleted rules or error < 0
 *
 * TODO: some other matching than name+type?  Currently `tags` is unused; match all types?
 * (would be useful in del_pair)
 */
KR_EXPORT
int kr_rule_local_data_del(const knot_rrset_t *rrs, kr_rule_tags_t tags);


enum kr_rule_sub_t {
	/// Empty zone, i.e. with SOA and NS
	KR_RULE_SUB_EMPTY = 1,
	/// NXDOMAIN for everything; TODO: SOA owner is hard.
	KR_RULE_SUB_NXDOMAIN,
	/// NODATA answers but not on exact name (e.g. it's similar to DNAME)
	KR_RULE_SUB_NODATA,
	/// Redirect: anything beneath has the same data as apex (except NS+SOA).
	KR_RULE_SUB_REDIRECT,
	/// Act similar to DNAME: rebase everything underneath by generated CNAMEs.
	KR_RULE_SUB_DNAME,
};
/** Insert a simple sub-tree rule.
 *
 * - into the default rule-set
 * - SOA and NS for generated answers aren't overridable.
 * - type: you can't use _DNAME via this function; insert it by kr_rule_local_data_ins()
 */
KR_EXPORT
int kr_rule_local_subtree(const knot_dname_t *apex, enum kr_rule_sub_t type,
			  uint32_t ttl, kr_rule_tags_t tags, kr_rule_opts_t opts);

/** Insert a view action into the default ruleset.
 *
 * \param subnet String specifying a subnet, e.g. "192.168.0.0/16".
 * \param dst_subnet String specifying a subnet to be matched by the destination address. (or empty/NULL)
 * \param protos Set of transport protocols. (or 0 to always match)
 * \param action Currently a string to execute, like in old policies, e.g. `policy.REFUSE`
 *
 * TODO: improve? (return code, warning, ...)  Internal queries never get matched.
 *
 * The concept of chain actions isn't respected; at most one action is chosen.
 * The winner needs to fulfill all conditions.  Closer subnet match is preferred,
 * but otherwise the priority is unspecified (it is deterministic, though).
 *
 * There's no detection of action rules that clash in this way,
 * even if all conditions match exactly.
 * TODO we might consider some overwriting semantics,
 *   but the additional conditions make that harder.
 */
KR_EXPORT
int kr_view_insert_action(const char *subnet, const char *dst_subnet,
			kr_proto_set protos, const char *action);

/** Add a tag by name into a tag-set variable.
 *
 * It also ensures allocation of tag names in the DB, etc.
 */
KR_EXPORT
int kr_rule_tag_add(const char *tag, kr_rule_tags_t *tagset);


struct kr_rule_zonefile_config {
	const char *filename; /// NULL if specifying input_str instead
	const char *input_str; /// NULL if specifying filename instead
	size_t input_len; /// 0 for strlen(input_str)

	bool is_rpz; /// interpret either as RPZ or as plain RRsets
	bool nodata; /// TODO: implement
	kr_rule_tags_t tags; /// tag-set for the generated rule
	const char *origin; /// NULL or zone origin if known
	uint32_t ttl; /// default TTL
	kr_rule_opts_t opts; /// options for these rules
};
/** Load rules from some zonefile format, e.g. RPZ.  Code in ./zonefile.c */
KR_EXPORT
int kr_rule_zonefile(const struct kr_rule_zonefile_config *c);

/** FIXME docs */
KR_EXPORT
void kr_rule_coalesce_targets(const struct sockaddr * targets[], void *data);

struct kr_rule_fwd_flags {
	/// Beware of ABI: this struct is memcpy'd to/from rule DB.
	bool
		is_auth : 1,
		is_tcp  : 1, /// forced TCP; unused, not needed for DoT
		is_nods : 1; /// disable local DNSSEC validation
};
typedef struct kr_rule_fwd_flags kr_rule_fwd_flags_t;
/** Insert/overwrite a forwarding rule.
 *
 * Into the default rule-set ATM.
 * \param targets NULL-terminated array.
 *
 * For is_auth == true we only support address, e.g. not specifying port or %interface.
 */
KR_EXPORT
int kr_rule_forward(const knot_dname_t *apex, kr_rule_fwd_flags_t flags,
			const struct sockaddr * targets[]);

