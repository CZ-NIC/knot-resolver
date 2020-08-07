/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include "lib/defines.h"
struct kr_query;
struct knot_pkt;

typedef uint64_t kr_rule_tags_t;
#define KR_RULE_TAGS_ALL ((uint64_t)0)

KR_EXPORT
int kr_rules_init();

KR_EXPORT
void kr_rules_deinit();

/** Try answering the query from local data. */
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

