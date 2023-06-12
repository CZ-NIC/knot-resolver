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

typedef uint64_t kr_rule_tags_t;
#define KR_RULE_TAGS_ALL ((kr_rule_tags_t)0)
/// Tags "capacity", i.e. numbered from 0 to _CAP - 1.
#define KR_RULE_TAGS_CAP (sizeof(kr_rule_tags_t) * 8)

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



/* APIs to modify the rule DB.
 *
 * FIXME:
 *  - a way to read/modify a rule?
 */

/** Insert/overwrite a local data rule.
 *
 * Into the default rule-set ATM.
 * Special NODATA case: use a CNAME type with zero records (TTL matters). */
KR_EXPORT
int kr_rule_local_data_ins(const knot_rrset_t *rrs, const knot_rdataset_t *sig_rds,
				kr_rule_tags_t tags);

/** Remove a local data rule.
 *
 * \return the number of deleted rules or error < 0
 *
 * TODO: some other matching than name+type?  Currently `tags` is unused; match all types?
 * (would be useful in del_pair)
 */
KR_EXPORT
int kr_rule_local_data_del(const knot_rrset_t *rrs, kr_rule_tags_t tags);

// TODO: perhaps expose an enum to unify these simple subtree rules?

/** Insert an empty zone.
 *
 * - into the default rule-set
 * - SOA and NS for generated answers aren't overridable.
 * - TTL is RULE_TTL_DEFAULT
 */
KR_EXPORT
int kr_rule_local_data_emptyzone(const knot_dname_t *apex, kr_rule_tags_t tags);

/** Insert an "NXDOMAIN zone".  TODO: SOA owner is hard. */
KR_EXPORT
int kr_rule_local_data_nxdomain(const knot_dname_t *apex, kr_rule_tags_t tags);
/** Insert a "NODATA zone".  These functions are all similar. */
KR_EXPORT
int kr_rule_local_data_nodata(const knot_dname_t *apex, kr_rule_tags_t tags);

/** Insert a redirect zone.
 * Into the default rule-set ATM.  SOA for generated NODATA answers isn't overridable. */
KR_EXPORT
int kr_rule_local_data_redirect(const knot_dname_t *apex, kr_rule_tags_t tags);

/** Insert a view action into the default ruleset.
 *
 * \param subnet String specifying a subnet, e.g. "192.168.0.0/16".
 * \param action Currently a string to execute, like in old policies, e.g. `policy.REFUSE`
 *
 * The concept of chain actions isn't respected; the most prioritized rule wins.
 * If exactly the same subnet is specified repeatedly, that rule gets overwritten silently.
 * TODO: improve? (return code, warning, ...)
 * TODO: some way to do multiple actions?  Will be useful e.g. with option-setting actions.
 *    On implementation side this would probably be multi-value LMDB, cf. local_data rules.
 */
KR_EXPORT
int kr_view_insert_action(const char *subnet, const char *action);

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

