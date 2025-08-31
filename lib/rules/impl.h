/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include "lib/rules/api.h"
#include "lib/utils.h"
#include <libknot/packet/pkt.h>

#include "lib/cache/impl.h"
#undef VERBOSE_MSG
#define VERBOSE_MSG(qry, ...) kr_log_q((qry), RULES,  ## __VA_ARGS__)

/** Insert all the default rules. in ./defaults.c */
int rules_defaults_insert(void);

/** Singleton struct used by the code in ./. */
struct kr_rules;
extern struct kr_rules *the_rules;

#define ENSURE_the_rules \
	if (!the_rules) { \
		int ret = kr_rules_init(NULL, 0, true); \
		if (ret) return ret; \
	}

#define KEY_RULESET_MAXLEN 16 /**< max. len of ruleset ID + 1(for kind) */
/** When constructing a key, it's convenient that the dname_lf ends on a fixed offset.
 * Convention: the end here is before the final '\0' byte (if any). */
#define KEY_DNAME_END_OFFSET (KEY_RULESET_MAXLEN + KNOT_DNAME_MAXLEN)
#define KEY_MAXLEN (KEY_DNAME_END_OFFSET + 64) //TODO: most of 64 is unused ATM

/** Construct key for local_data_ins().  It's stored in `key_data`. */
knot_db_val_t local_data_key(const knot_rrset_t *rrs, uint8_t key_data[KEY_MAXLEN],
					const char *ruleset_name);
/** Same as kr_rule_local_data_ins() but with precomputed `key`. */
int local_data_ins(knot_db_val_t key, const knot_rrset_t *rrs, const knot_rdataset_t *sig_rds,
			kr_rule_tags_t tags, kr_rule_opts_t opts);
/** Construct key for a zone-like-apex entry.  It's stored in `key_data`. */
knot_db_val_t zla_key(const knot_dname_t *apex, uint8_t key_data[KEY_MAXLEN], const char ruleset[]);

/** Almost the whole kr_rule_local_data_answer() */
int rule_local_data_answer(struct kr_query *qry, knot_pkt_t *pkt);

/** The first byte of zone-like apex value is its type. */
typedef uint8_t val_zla_type_t;
/** This effectively contains enum kr_rule_sub_t */
enum {
	/** Unblock (i.e. allow-list) this subtree. */
	VAL_ZLAT_UNBLOCK = 8,
	/** Forward, i.e. override upstream for this subtree (resolver or auth). */
	VAL_ZLAT_FORWARD = 128,
};

extern /*const*/ char RULESET_DEFAULT[];

/// Fill *variable_ptr from a knot_db_val_t and advance it (and kr_assert it fits).
#define deserialize_fails_assert(val_ptr, variable_ptr) \
	deserialize_fails_assert_f_(val_ptr, (variable_ptr), sizeof(*(variable_ptr)))
static inline bool deserialize_fails_assert_f_(knot_db_val_t *val, void *var, size_t size)
{
	if (kr_fails_assert(val->len >= size))
		return true;
	memcpy(var, val->data, size);
	val->len -= size;
	// avoiding void* arithmetics complicates this
	char *tmp = val->data;
	tmp += size;
	val->data = tmp;
	return false;
}

struct kr_rules {
	/* Database for storing the rules (LMDB). */
	kr_cdb_pt db;                 /**< Storage instance */
	const struct kr_cdb_api *api; /**< Storage engine */
	struct kr_cdb_stats stats;
};
#define ruledb_op(op, ...) \
	the_rules->api->op(the_rules->db, &the_rules->stats, ## __VA_ARGS__)

//TODO later, maybe.  ATM it would be cumbersome to avoid void* arithmetics.
#pragma GCC diagnostic ignored "-Wpointer-arith"

