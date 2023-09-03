/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include "lib/defines.h"
struct kr_query;
struct kr_request;
struct knot_pkt;
struct sockaddr;
#include <libknot/db/db.h>

/// Storage for a tag-set.  It's a bitmap, so 64 tags are supported now.
typedef uint64_t kr_rule_tags_t;
#define KR_RULE_TAGS_ALL ((kr_rule_tags_t)0)
/// Tags "capacity", i.e. numbered from 0 to _CAP - 1.
#define KR_RULE_TAGS_CAP (sizeof(kr_rule_tags_t) * 8)

/** DNS protocol set - mutually exclusive options, contrary to kr_request_qsource_flags
 *
 * The XDP flag is not discerned here, as it could apply to any protocol.
 *  (not right now, but libknot does support it for TCP, so that would complete everything)
 *
 * TODO: probably unify with enum protolayer_grp.
 */
enum kr_proto {
	KR_PROTO_INTERNAL = 0, /// no protocol, e.g. useful to mark internal requests
	KR_PROTO_UDP53,
	KR_PROTO_TCP53,
	KR_PROTO_DOT,
	KR_PROTO_DOH,
	KR_PROTO_DOQ, /// unused for now
	KR_PROTO_COUNT,
};
/** Bitmap of enum kr_proto options. */
typedef uint8_t kr_proto_set;
static_assert(sizeof(kr_proto_set) * 8 >= KR_PROTO_COUNT, "bad combination of type sizes");


/** Open the rule DB.
 *
 * You can call this to override the path or size (NULL/0 -> default).
 * Not allowed if already open (EINVAL), so this optional call has to come
 * before writing anything into the DB. */
KR_EXPORT
int kr_rules_init(const char *path, size_t maxsize);
/** kr_rules_init() but OK if already open, and not allowing to override defaults. */
KR_EXPORT
int kr_rules_init_ensure(void);

KR_EXPORT
void kr_rules_deinit(void);

/** Commit or abort changes done to the rule DB so far. */
KR_EXPORT
int kr_rules_commit(bool accept);

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
				kr_rule_tags_t tags);
/** Merge RRs into a local data rule.
 *
 * - FIXME: with multiple tags variants for the same name-type pair,
 *     you typically end up with a single RR per RRset
 * - RRSIGs get dropped, if any were attached.
 * - We assume that this is called with a RW transaction open already,
 *   which is always true in normal usage (long RW txn covering whole config).
 */
KR_EXPORT
int kr_rule_local_data_merge(const knot_rrset_t *rrs, kr_rule_tags_t tags);

/** Add a name-address pair into rules.
 *
 * - both forward and reverse mapping is added
 * - merging is used; see kr_rule_local_data_merge()
 * - NODATA is optionally inserted
 */
KR_EXPORT
int kr_rule_local_address(const char *name, const char *addr,
				bool use_nodata, uint32_t ttl, kr_rule_tags_t tags);

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
int kr_rule_local_hosts(const char *path, bool use_nodata, uint32_t ttl, kr_rule_tags_t tags);

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
};
/** Insert a simple sub-tree rule.
 *
 * - into the default rule-set
 * - SOA and NS for generated answers aren't overridable.
 */
KR_EXPORT
int kr_rule_local_subtree(const knot_dname_t *apex, enum kr_rule_sub_t type,
			  uint32_t ttl, kr_rule_tags_t tags);

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
};
/** Load rules from some zonefile format, e.g. RPZ.  Code in ./zonefile.c */
KR_EXPORT
int kr_rule_zonefile(const struct kr_rule_zonefile_config *c);


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
 * \param targets NULL-terminated array. */
KR_EXPORT
int kr_rule_forward(const knot_dname_t *apex, kr_rule_fwd_flags_t flags,
			const struct sockaddr * targets[]);

