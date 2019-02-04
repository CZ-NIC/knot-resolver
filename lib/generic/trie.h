/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
    Copyright (C) 2018 Tony Finch <dot@dotat.at>

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

#include <stdbool.h>
#include <stdint.h>

#include <libknot/mm_ctx.h>
#include "lib/defines.h"

/*!
 * \brief Native API of QP-tries:
 *
 * - keys are char strings, not necessarily zero-terminated,
 *   the structure copies the contents of the passed keys
 * - values are void* pointers, typically you get an ephemeral pointer to it
 * - key lengths are limited by 2^32-1 ATM
 *
 * XXX EDITORS: trie.{h,c} are synced from
 * https://gitlab.labs.nic.cz/knot/knot-dns src/contrib/qp-trie tree 0193b76f03
 * only with tiny adjustments, mostly #includes and KR_EXPORT.
 */

/*! \brief Element value. */
typedef void* trie_val_t;

/*! \brief Opaque structure holding a QP-trie. */
typedef struct trie trie_t;

/*! \brief Opaque type for holding a QP-trie iterator. */
typedef struct trie_it trie_it_t;

/*! \brief Callback for cloning trie values. */
typedef trie_val_t (*trie_dup_cb)(const trie_val_t val, knot_mm_t *mm);

/*! \brief Callback for performing actions on a trie leaf
 *
 * Used during copy-on-write transactions
 *
 * \param val	The value of the element to be altered
 * \param key	The key of the element to be altered
 * \param len	The length of key
 * \param d	Additional user data
 */
typedef void trie_cb(trie_val_t val, const char *key, size_t len, void *d);

/*! \brief Opaque type for holding the copy-on-write state for a QP-trie. */
typedef struct trie_cow trie_cow_t;

/*! \brief Create a trie instance. */
KR_EXPORT
trie_t* trie_create(knot_mm_t *mm);

/*! \brief Free a trie instance. */
KR_EXPORT
void trie_free(trie_t *tbl);

/*! \brief Clear a trie instance (make it empty). */
KR_EXPORT
void trie_clear(trie_t *tbl);

/*! \brief Create a clone of existing trie. */
trie_t* trie_dup(const trie_t *orig, trie_dup_cb dup_cb, knot_mm_t *mm);

/*! \brief Return the number of keys in the trie. */
KR_EXPORT
size_t trie_weight(const trie_t *tbl);

/*! \brief Search the trie, returning NULL on failure. */
KR_EXPORT
trie_val_t* trie_get_try(trie_t *tbl, const char *key, uint32_t len);

/*! \brief Search the trie, inserting NULL trie_val_t on failure. */
KR_EXPORT
trie_val_t* trie_get_ins(trie_t *tbl, const char *key, uint32_t len);

/*!
 * \brief Search for less-or-equal element.
 *
 * \param tbl  Trie.
 * \param key  Searched key.
 * \param len  Key length.
 * \param val  (optional) Value found; it will be set to NULL if not found or errored.
 * \return KNOT_EOK for exact match, 1 for previous, KNOT_ENOENT for not-found,
 *         or KNOT_E*.
 */
KR_EXPORT
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
KR_EXPORT
int trie_del(trie_t *tbl, const char *key, uint32_t len, trie_val_t *val);


/*! \brief Create a new iterator pointing to the first element (if any).
 *
 * trie_it_* functions deal with these iterators capable of walking and jumping
 * over the trie.  Note that any modification to key-set stored by the trie
 * will in general invalidate all iterators and you will need to begin anew.
 * (It won't be detected - you may end up reading freed memory, etc.)
 */
KR_EXPORT
trie_it_t* trie_it_begin(trie_t *tbl);

/*! \brief Test if the iterator has gone "past the end" (and points nowhere). */
KR_EXPORT
bool trie_it_finished(trie_it_t *it);

/*! \brief Free any resources of the iterator. It's OK to call it on NULL. */
KR_EXPORT
void trie_it_free(trie_it_t *it);

/*! \brief Copy the iterator.  See the warning in trie_it_begin(). */
trie_it_t *trie_it_clone(const trie_it_t *it);

/*!
 * \brief Return pointer to the key of the current element.
 *
 * \note The len is uint32_t internally but size_t is better for our usage
 *       as it is without an additional type conversion.
 */
KR_EXPORT
const char* trie_it_key(trie_it_t *it, size_t *len);

/*! \brief Return pointer to the value of the current element (writable). */
KR_EXPORT
trie_val_t* trie_it_val(trie_it_t *it);

/*!
 * \brief Advance the iterator to the next element.
 *
 * Iteration is in ascending lexicographical order.
 * In particular, the empty string would be considered as the very first.
 *
 * \TODO: in most iterator operations, ENOMEM is very unlikely
 * but it leads to a _finished() iterator (silently).
 * Perhaps the functions should simply return KNOT_E*
 */
KR_EXPORT
void trie_it_next(trie_it_t *it);
/*! \brief Advance the iterator to the previous element.  See trie_it_next(). */
void trie_it_prev(trie_it_t *it);

/*! \brief Advance iterator to the next element, looping to first after last. */
void trie_it_next_loop(trie_it_t *it);
/*! \brief Advance iterator to the previous element, looping to last after first. */
void trie_it_prev_loop(trie_it_t *it);

/*! \brief Advance iterator to the next element while ignoring the subtree.
 *
 * \note Another formulation: skip keys that are prefixed by the current key.
 * \TODO: name, maybe _noprefixed?  The thing is that in the "subtree" meaning
 * doesn't correspond to how the pointers go in the implementation,
 * but we may not care much for implementation in the API...
 */
void trie_it_next_nosub(trie_it_t *it);

/*! \brief Advance iterator to the longest prefix of the current key.
 *
 * \TODO: name, maybe _prefix?  Arguments similar to _nosub vs. _noprefixed.
 */
void trie_it_parent(trie_it_t *it);

/*! \brief trie_get_leq() but with an iterator. */
int trie_it_get_leq(trie_it_t *it, const char *key, uint32_t len);

/*! \brief Remove the current element.  The iterator will get trie_it_finished() */
KR_EXPORT
void trie_it_del(trie_it_t *it);


/*! \brief Start a COW transaction
 *
 * A copy-on-write transaction starts by obtaining a write lock (in
 * your application code) followed by a call to trie_cow(). This
 * creates a shared clone of the trie and saves both old and new roots
 * in the COW context.
 *
 * During the COW transaction, you call trie_cow_ins() or
 * trie_cow_del() as necessary. These calls ensure that the relevant
 * parts of the (new) trie are copied so that they can be modified
 * freely.
 *
 * Your trie_val_t objects must be able to distinguish their
 * reachability, either shared, or old-only, or new-only. Before a COW
 * transaction the reachability of your objects is indeterminate.
 * During a transaction, any trie_val_t objects that might be affected
 * (because they are adjacent to a trie_get_cow() or trie_del_cow())
 * are first marked as shared using the callback you pass to
 * trie_cow().
 *
 * When the transaction is complete, to commit, call trie_cow_new() to
 * get the new root, swap the old and new trie roots (e.g. with
 * rcu_xchg_pointer()), wait for readers to finish with the old trie
 * (e.g. using synchronize_rcu()), then call trie_cow_commit(). For a
 * rollback, you can just call trie_cow_rollback() without waiting
 * since that doesn't conflict with readers. After trie_cow_commit()
 * or trie_cow_rollback() have finished, you can release your write
 * lock.
 *
 * Concurrent reading of the old trie is allowed during a transaction
 * provided that it is known when all readers have finished with the
 * old version, e.g. using rcu_read_lock() and rcu_read_unlock().
 * There must be only one write transaction at a time.
 *
 * \param old		the old trie
 * \param mark_shared	callback to mark a leaf as shared
 * \param d		extra data for the callback
 * \return		a pointer to a COW context,
 *			or NULL if there was a failure
 */
trie_cow_t* trie_cow(trie_t *old, trie_cb *mark_shared, void *d);

/*! \brief get the new trie from a COW context */
trie_t* trie_cow_new(trie_cow_t *cow);

/*! \brief variant of trie_get_ins() for use during COW transactions
 *
 * As necessary, this copies path from the root of the trie to the
 * leaf, so that it is no longer shared. Any leaves adjacent to this
 * path are marked as shared using the mark_shared callback passed to
 * trie_cow().
 *
 * It is your responsibility to COW your trie_val_t objects. If you copy an
 * object you must change the original's reachability from shared to old-only.
 * New objects (including copies) must have new-only reachability.
 */
trie_val_t* trie_get_cow(trie_cow_t *cow, const char *key, uint32_t len);

/*!
 * \brief variant of trie_del() for use during COW transactions
 *
 * The mark_shared callback is invoked as necessary, in the same way
 * as trie_get_cow().
 *
 * Returns KNOT_EOK if the key was removed or KNOT_ENOENT if not found.
 * If val!=NULL and deletion succeeded, the *val is set to the deleted
 * value pointer.
 */
int trie_del_cow(trie_cow_t *cow, const char *key, uint32_t len, trie_val_t *val);

/*! \brief clean up the old trie after committing a COW transaction
 *
 * Your callback is invoked for any trie_val_t objects that might need
 * cleaning up; you must free any objects you have marked as old-only
 * and retain objects with shared reachability.
 *
 * The cow object is free()d, and the new trie root is returned.
 */
trie_t* trie_cow_commit(trie_cow_t *cow, trie_cb *cb, void *d);

/*! \brief clean up the new trie after rolling back a COW transaction
 *
 * Your callback is invoked for any trie_val_t objects that might need
 * cleaning up; you must free any objects you have marked as new-only
 * and retain objects with shared reachability.
 *
 * The cow object is free()d, and the old trie root is returned.
 */
trie_t* trie_cow_rollback(trie_cow_t *cow, trie_cb *cb, void *d);
