/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include "lib/defines.h"
struct kr_query;
struct kr_request;
struct knot_pkt;
#include <libknot/db/db.h>

typedef uint64_t kr_rule_tags_t;
#define KR_RULE_TAGS_ALL ((kr_rule_tags_t)0)
/// Tags "capacity", i.e. numbered from 0 to _CAP - 1.
#define KR_RULE_TAGS_CAP (sizeof(kr_rule_tags_t) * 8)

KR_EXPORT
int kr_rules_init(void);

KR_EXPORT
void kr_rules_deinit(void);

/** Try answering the query from local data.
 *
 * FIXME: we probably want to ensure AA flags in answer as appropriate.
 *   Perhaps approach it like AD?  Tweak flags in ranked_rr_array_entry
 *   and at the end decide whether to set AA=1?
 */
int kr_rule_local_data_answer(struct kr_query *qry, struct knot_pkt *pkt);

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
 *  - what about transactions in this API?
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

/** Insert an empty zone.
 * Into the default rule-set ATM.  SOA for generated NODATA isn't overridable. */
KR_EXPORT
int kr_rule_local_data_emptyzone(const knot_dname_t *apex, kr_rule_tags_t tags);

/** Insert a redirect zone.
 * Into the default rule-set ATM.  SOA for generated NODATA isn't overridable. */
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

