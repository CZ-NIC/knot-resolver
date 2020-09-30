/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
*/

#pragma once

#include <stdint.h>

#include <libknot/db/db.h>

/* Cache options. */
struct kr_cdb_opts {
	const char *path; /*!< Cache URI path. */
	size_t maxsize;   /*!< Suggested cache size in bytes; pass 0 to keep unchanged/default. */
};

struct kr_cdb_stats {
	uint64_t open;
	uint64_t close;
	uint64_t count;
	uint64_t count_entries;
	uint64_t clear;
	uint64_t commit;
	uint64_t read;
	uint64_t read_miss;
	uint64_t write;
	uint64_t remove;
	uint64_t remove_miss;
	uint64_t match;
	uint64_t match_miss;
	uint64_t read_leq;
	uint64_t read_leq_miss;
	double usage_percent;
};

/*! Pointer to a cache structure.
 *
 * This struct is opaque and never defined; the purpose is to get better
 * type safety than with void *.
 */
typedef struct kr_cdb *kr_cdb_pt;

/*! Cache database API.
  * This is a simplified version of generic DB API from libknot,
  * that is tailored to caching purposes.
  */
struct kr_cdb_api {
	const char *name;

	/* Context operations */

	int (*open)(kr_cdb_pt *db, struct kr_cdb_stats *stat, struct kr_cdb_opts *opts, knot_mm_t *mm);
	void (*close)(kr_cdb_pt db, struct kr_cdb_stats *stat);
	int (*count)(kr_cdb_pt db, struct kr_cdb_stats *stat);
	int (*clear)(kr_cdb_pt db, struct kr_cdb_stats *stat);

	/** Run after a row of operations to release transaction/lock if needed. */
	int (*commit)(kr_cdb_pt db, struct kr_cdb_stats *stat);

	/* Data access */

	int (*read)(kr_cdb_pt db, struct kr_cdb_stats *stat,
			const knot_db_val_t *key, knot_db_val_t *val, int maxcount);
	int (*write)(kr_cdb_pt db, struct kr_cdb_stats *stat, const knot_db_val_t *key,
			knot_db_val_t *val, int maxcount);

	/** Remove maxcount keys.
	 * \returns the number of succesfully removed keys or the first error code
	 * It returns on first error, but ENOENT is not considered an error. */
	int (*remove)(kr_cdb_pt db, struct kr_cdb_stats *stat,
			knot_db_val_t keys[], int maxcount);

	/* Specialised operations */

	/** Find key-value pairs that are prefixed by the given key, limited by maxcount.
	 * \return the number of pairs or negative error. */
	int (*match)(kr_cdb_pt db, struct kr_cdb_stats *stat,
			knot_db_val_t *key, knot_db_val_t keyval[][2], int maxcount);

	/** Less-or-equal search (lexicographic ordering).
	 * On successful return, key->data and val->data point to DB-owned data.
	 * return: 0 for equality, > 0 for less, < 0 kr_error */
	int (*read_leq)(kr_cdb_pt db, struct kr_cdb_stats *stat,
			knot_db_val_t *key, knot_db_val_t *val);

	/** Return estimated space usage (0--100). */
	double (*usage_percent)(kr_cdb_pt db);

	/** Return the current cache size limit in bytes; could be cached by check_health(). */
	size_t (*get_maxsize)(kr_cdb_pt db);

	/** Perform maintenance.
	 * In LMDB case it checks whether data.mdb is still the same
	 * and reopens it if it isn't; it errors out if the file doesn't exist anymore.
	 * \return 0 if OK, 1 if reopened OK, < 0 kr_error */
	int (*check_health)(kr_cdb_pt db, struct kr_cdb_stats *stat);
};
