/*  Copyright (C) 2017-2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
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
 * https://gitlab.nic.cz/knot/knot-dns/tree/68352fc969/src/contrib/qp-trie
 * only with simple adjustments, mostly include lines, KR_EXPORT and assertions.
 */

/*! \brief Element value. */
typedef void* trie_val_t;

/*! \brief Opaque structure holding a QP-trie. */
typedef struct trie trie_t;

/*! \brief Opaque type for holding a QP-trie iterator. */
typedef struct trie_it trie_it_t;

/*! \brief Create a trie instance.  Pass NULL to use malloc+free. */
KR_EXPORT
trie_t* trie_create(knot_mm_t *mm);

/*! \brief Free a trie instance. */
KR_EXPORT
void trie_free(trie_t *tbl);

/*! \brief Clear a trie instance (make it empty). */
KR_EXPORT
void trie_clear(trie_t *tbl);

/*! \brief Return the number of keys in the trie. */
KR_EXPORT
size_t trie_weight(const trie_t *tbl);

/*! \brief Search the trie, returning NULL on failure. */
KR_EXPORT
trie_val_t* trie_get_try(trie_t *tbl, const char *key, uint32_t len);

/*!
 * \brief Return pointer to the minimum.  Optionally with key and its length. */
KR_EXPORT
trie_val_t* trie_get_first(trie_t *tbl, char **key, uint32_t *len);

/*! \brief Search the trie, inserting NULL trie_val_t on failure. */
KR_EXPORT
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
KR_EXPORT
int trie_get_leq(trie_t *tbl, const char *key, uint32_t len, trie_val_t **val);

/*!
 * \brief Apply a function to every trie_val_t, in order.
 *
 * \param d Parameter passed as the second argument to f().
 * \return First nonzero from f() or zero (i.e. KNOT_EOK).
 */
KR_EXPORT
int trie_apply(trie_t *tbl, int (*f)(trie_val_t *, void *), void *d);

/*!
 * \brief Apply a function to every trie_val_t, in order.
 *
 * It's like trie_apply() but additionally passes keys and their lengths.
 *
 * \param d Parameter passed as the second argument to f().
 * \return First nonzero from f() or zero (i.e. KNOT_EOK).
 */
KR_EXPORT
int trie_apply_with_key(trie_t *tbl, int (*f)(const char *, uint32_t, trie_val_t *, void *), void *d);

/*!
 * \brief Remove an item, returning KNOT_EOK if succeeded or KNOT_ENOENT if not found.
 *
 * If val!=NULL and deletion succeeded, the deleted value is set.
 */
KR_EXPORT
int trie_del(trie_t *tbl, const char *key, uint32_t len, trie_val_t *val);

/*!
 * \brief Remove the first item, returning KNOT_EOK on success.
 *
 * You may optionally get the key and/or value.
 * The key is copied, so you need to pass sufficient len,
 * otherwise kr_error(ENOSPC) is returned.
 */
KR_EXPORT
int trie_del_first(trie_t *tbl, char *key, uint32_t *len, trie_val_t *val);

/*! \brief Create a new iterator pointing to the first element (if any). */
KR_EXPORT
trie_it_t* trie_it_begin(trie_t *tbl);

/*!
 * \brief Advance the iterator to the next element.
 *
 * Iteration is in ascending lexicographical order.
 * In particular, the empty string would be considered as the very first.
 *
 * \note You may not use this function if the trie's key-set has been modified
 * during the lifetime of the iterator (modifying values only is OK).
 */
KR_EXPORT
void trie_it_next(trie_it_t *it);

/*! \brief Test if the iterator has gone past the last element. */
KR_EXPORT
bool trie_it_finished(trie_it_t *it);

/*! \brief Free any resources of the iterator. It's OK to call it on NULL. */
KR_EXPORT
void trie_it_free(trie_it_t *it);

/*!
 * \brief Return pointer to the key of the current element.
 *
 * \note The optional len is uint32_t internally but size_t is better for our usage,
 *       as it is without an additional type conversion.
 */
KR_EXPORT
const char* trie_it_key(trie_it_t *it, size_t *len);

/*! \brief Return pointer to the value of the current element (writable). */
KR_EXPORT
trie_val_t* trie_it_val(trie_it_t *it);
