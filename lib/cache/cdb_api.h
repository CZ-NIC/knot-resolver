/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#pragma once

#include <libknot/db/db.h>

/* Cache options. */
struct kr_cdb_opts {
	const char *path; /*!< Cache URI path. */
	size_t maxsize;   /*!< Suggested cache size in bytes. */
};

/*! Cache database API.
  * This is a simplified version of generic DB API from libknot,
  * that is tailored to caching purposes.
  */
struct kr_cdb_api {
	const char *name;

	/* Context operations */

	int (*open)(knot_db_t **db, struct kr_cdb_opts *opts, knot_mm_t *mm);
	void (*close)(knot_db_t *db);
	int (*count)(knot_db_t *db);
	int (*clear)(knot_db_t *db);

	/** Run after a row of operations to release transaction/lock if needed. */
	int (*sync)(knot_db_t *db);

	/* Data access */

	int (*read)(knot_db_t *db, const knot_db_val_t *key, knot_db_val_t *val,
			int maxcount);
	int (*write)(knot_db_t *db, const knot_db_val_t *key, knot_db_val_t *val,
			int maxcount);

	/** Remove maxcount keys.
	 * \returns the number of succesfully removed keys or the first error code
	 * It returns on first error, but ENOENT is not considered an error. */
	int (*remove)(knot_db_t *db, knot_db_val_t keys[], int maxcount);

	/* Specialised operations */

	/** Find key-value pairs that are prefixed by the given key, limited by maxcount.
	 * \return the number of pairs or negative error. */
	int (*match)(knot_db_t *db, knot_db_val_t *key, knot_db_val_t keyval[][2], int maxcount);

	/** Less-or-equal search (lexicographic ordering).
	 * On successful return, key->data and val->data point to DB-owned data.
	 * return: 0 for equality, > 0 for less, < 0 kr_error */
	int (*read_leq)(knot_db_t *db, knot_db_val_t *key, knot_db_val_t *val);
};
