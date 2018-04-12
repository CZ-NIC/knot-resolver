/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <libknot/mm_ctx.h>

/*!
 * \brief Native API of QP-tries:
 *
 * - keys are char strings, not necessarily zero-terminated,
 *   the structure copies the contents of the passed keys
 * - values are void* pointers, typically you get an ephemeral pointer to it
 * - key lengths are limited by 2^32-1 ATM
 *
 * XXX EDITORS: trie.{h,c} are synced from
 * https://gitlab.labs.nic.cz/knot/knot-dns/tree/68352fc969/src/contrib/qp-trie
 * only with tiny adjustments, mostly #includes.
 */

/*! \brief Element value. */
typedef void* trie_val_t;

/*! \brief Opaque structure holding a QP-trie. */
typedef struct trie trie_t;

/*! \brief Opaque type for holding a QP-trie iterator. */
typedef struct trie_it trie_it_t;

/*! \brief Create a trie instance. */
trie_t* trie_create(knot_mm_t *mm);

/*! \brief Free a trie instance. */
void trie_free(trie_t *tbl);

/*! \brief Clear a trie instance (make it empty). */
void trie_clear(trie_t *tbl);

/*! \brief Return the number of keys in the trie. */
size_t trie_weight(const trie_t *tbl);

/*! \brief Search the trie, returning NULL on failure. */
trie_val_t* trie_get_try(trie_t *tbl, const char *key, uint32_t len);

/*! \brief Search the trie, inserting NULL trie_val_t on failure. */
trie_val_t* trie_get_ins(trie_t *tbl, const char *key, uint32_t len);

/*!
 * \brief Search for less-or-equal element.
 *
 * \param tbl  Trie.
 * \param key  Searched key.
 * \param len  Key length.
 * \param val  Must be valid; it will be set to NULL if not found or errored.
 * \return KNOT_EOK for exact match, 1 for previous, KNOT_ENOENT for not-found,
 *         or KNOT_E*.
 */
int trie_get_leq(trie_t *tbl, const char *key, uint32_t len, trie_val_t **val);

/*!
 * \brief Apply a function to every trie_val_t, in order.
 *
 * \return KNOT_EOK if success or KNOT_E* if error.
 */
int trie_apply(trie_t *tbl, int (*f)(trie_val_t *, void *), void *d);

/*!
 * \brief Remove an item, returning KNOT_EOK if succeeded or KNOT_ENOENT if not found.
 *
 * If val!=NULL and deletion succeeded, the deleted value is set.
 */
int trie_del(trie_t *tbl, const char *key, uint32_t len, trie_val_t *val);

/*! \brief Create a new iterator pointing to the first element (if any). */
trie_it_t* trie_it_begin(trie_t *tbl);

/*!
 * \brief Advance the iterator to the next element.
 *
 * Iteration is in ascending lexicographical order.
 * In particular, the empty string would be considered as the very first.
 */
void trie_it_next(trie_it_t *it);

/*! \brief Test if the iterator has gone past the last element. */
bool trie_it_finished(trie_it_t *it);

/*! \brief Free any resources of the iterator. It's OK to call it on NULL. */
void trie_it_free(trie_it_t *it);

/*!
 * \brief Return pointer to the key of the current element.
 *
 * \note The len is uint32_t internally but size_t is better for our usage
 *       as it is without an additional type conversion.
 */
const char* trie_it_key(trie_it_t *it, size_t *len);

/*! \brief Return pointer to the value of the current element (writable). */
trie_val_t* trie_it_val(trie_it_t *it);
