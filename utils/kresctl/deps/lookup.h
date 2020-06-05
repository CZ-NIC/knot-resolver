/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <histedit.h>

#include "libknot/mm_ctx.h"
#include "qp-trie/trie.h"

/*! Lookup context. */
typedef struct {
	/*! Memory pool context. */
	knot_mm_t mm;
	/*! Main trie storage. */
	trie_t *trie;

	/*! Current (iteration) data context. */
	struct {
		/*! Stored key. */
		char *key;
		/*! Corresponding key data. */
		void *data;
	} found;

	/*! Iteration context. */
	struct {
		/*! Total number of possibilies. */
		size_t count;
		/*! The first possibility. */
		char *first_key;
		/*! Hat-trie iterator. */
		trie_it_t *it;
	} iter;
} lookup_t;

/*!
 * Initializes the lookup context.
 *
 * \param[in] lookup  Lookup context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int lookup_init(lookup_t *lookup);

/*!
 * Deinitializes the lookup context.
 *
 * \param[in] lookup  Lookup context.
 */
void lookup_deinit(lookup_t *lookup);

/*!
 * Inserts given key and data into the lookup.
 *
 * \param[in] lookup  Lookup context.
 * \param[in] str     Textual key.
 * \param[in] data    Key textual data.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int lookup_insert(lookup_t *lookup, const char *str, void *data);

/*!
 * Searches the lookup container for the given key.
 *
 * \note If one candidate, lookup.found contains the key/data,
 *       if more candidates, lookup.found contains the common key prefix and
 *       lookup.iter.first_key is the first candidate key.
 *
 * \param[in] lookup   Lookup context.
 * \param[in] str      Textual key.
 * \param[in] str_len  Textual key length.
 *
 * \return Error code, KNOT_EOK if 1 candidate, KNOT_ENOENT if no candidate,
 *         and KNOT_EFEWDATA if more candidates are possible.
 */
int lookup_search(lookup_t *lookup, const char *str, size_t str_len);

/*!
 * Moves the lookup iterator to the next key candidate.
 *
 * \note lookup.found is updated.
 *
 * \param[in] lookup   Lookup context.
 */
void lookup_list(lookup_t *lookup);

/*!
 * Completes the string based on the lookup content or prints all candidates.
 *
 * \param[in] lookup     Lookup context.
 * \param[in] str        Textual key.
 * \param[in] str_len    Textual key length.
 * \param[in] el         Editline context.
 * \param[in] add_space  Add one space after completed string flag.
 */
void lookup_complete(lookup_t *lookup, const char *str, size_t str_len,
					 EditLine *el, bool add_space);