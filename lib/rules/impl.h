/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include "lib/rules/api.h"

#define RULE_TTL_DEFAULT ((uint32_t)10800)

/** Insert all the default rules. in ./defaults.c */
int rules_defaults_insert(void);

/** Singleton struct used by the code in ./. */
struct kr_rules;
extern struct kr_rules *the_rules;

#define KEY_RULESET_MAXLEN 16 /**< max. len of ruleset ID + 1(for kind) */
/** When constructing a key, it's convenient that the dname_lf ends on a fixed offset.
 * Convention: the end here is before the final '\0' byte (if any). */
#define KEY_DNAME_END_OFFSET (KEY_RULESET_MAXLEN + KNOT_DNAME_MAXLEN)
#define KEY_MAXLEN (KEY_DNAME_END_OFFSET + 64) //TODO: most of 64 is unused ATM

/** Construct key for local_data_ins().  It's stored in `key_data`. */
knot_db_val_t local_data_key(const knot_rrset_t *rrs, uint8_t key_data[KEY_MAXLEN],
					const char *ruleset_name);
/** Same as kr_rule_local_data_ins() but with precomputed `key`. */
int local_data_ins(knot_db_val_t key, const knot_rrset_t *rrs,
			const knot_rdataset_t *sig_rds, kr_rule_tags_t tags);


/** The first byte of zone-like apex value is its type. */
typedef uint8_t val_zla_type_t;
enum {
	/** Empty zone. No data in DB value after this byte.
	 *
	 * TODO: add
	 *  - SOA rdata (maybe, optional, remainder of DB value)
	 *  Same for _NXDOMAIN and _NODATA, too.
	 */
	VAL_ZLAT_EMPTY = 1,
	/** Forced NXDOMAIN. */
	VAL_ZLAT_NXDOMAIN,
	/** Forced NODATA.  Does not apply on exact name (e.g. it's similar to DNAME) */
	VAL_ZLAT_NODATA,
	/** Redirect: anything beneath has the same data as apex (except NS+SOA). */
	VAL_ZLAT_REDIRECT,
};
/** For now see kr_rule_local_data_emptyzone() and friends.
 *
 * TODO: probably make something like this the preferred API. */
int insert_trivial_zone(val_zla_type_t ztype, uint32_t ttl,
			const knot_dname_t *apex, kr_rule_tags_t tags);

extern /*const*/ char RULESET_DEFAULT[];


