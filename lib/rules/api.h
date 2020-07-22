/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include "lib/defines.h"
struct kr_query;
struct knot_pkt;

typedef uint64_t kr_rule_tags_t;
#define KR_RULE_TAGS_ALL ((kr_rule_tags_t)0)

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

/** Insert/overwrite a local data rule.
 * Into the default rule-set ATM. */
KR_EXPORT
int kr_rule_local_data_ins(const knot_rrset_t *rrs, const knot_rdataset_t *sig_rds,
				kr_rule_tags_t tags);

/** Insert an empty zone.
 * Into the default rule-set ATM. */
KR_EXPORT
int kr_rule_local_data_emptyzone(const knot_dname_t *apex, kr_rule_tags_t tags);

