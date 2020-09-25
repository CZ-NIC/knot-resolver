/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 *
 * @file array.h
 * @brief A set of simple macros to make working with dynamic arrays easier.
 *
 * @note The C has no generics, so it is implemented mostly using macros.
 * Be aware of that, as direct usage of the macros in the evaluating macros
 * may lead to different expectations:
 *
 * @code{.c}
 *     MIN(array_push(arr, val), other)
 * @endcode
 *
 * May evaluate the code twice, leading to unexpected behaviour.
 * This is a price to pay for the absence of proper generics.
 *
 * # Example usage:
 *
 * @code{.c}
 *      array_t(const char*) arr;
 *      array_init(arr);
 *
 *      // Reserve memory in advance
 *      if (array_reserve(arr, 2) < 0) {
 *          return ENOMEM;
 *      }
 *
 *      // Already reserved, cannot fail
 *      array_push(arr, "princess");
 *      array_push(arr, "leia");
 *
 *      // Not reserved, may fail
 *      if (array_push(arr, "han") < 0) {
 *          return ENOMEM;
 *      }
 *
 *      // It does not hide what it really is
 *      for (size_t i = 0; i < arr.len; ++i) {
 *          printf("%s\n", arr.at[i]);
 *      }
 *
 *      // Random delete
 *      array_del(arr, 0);
 * @endcode
 * \addtogroup generics
 * @{
 */

#pragma once
#include <stdlib.h>

/** Simplified Qt containers growth strategy. */
static inline size_t array_next_count(size_t want)
{
	if (want < 2048) {
		return (want < 20) ? want + 4 : want * 2;
	} else {
		return want + 2048;
	}
}

/** @internal Incremental memory reservation */
static inline int array_std_reserve(void *baton, void **mem, size_t elm_size, size_t want, size_t *have)
{
	if (*have >= want) {
		return 0;
	}
	/* Simplified Qt containers growth strategy */
	size_t next_size = array_next_count(want);
	void *mem_new = realloc(*mem, next_size * elm_size);
	if (mem_new != NULL) {
		*mem = mem_new;
		*have = next_size;
		return 0;
	}
	return -1;
}

/** @internal Wrapper for stdlib free. */
static inline void array_std_free(void *baton, void *p)
{
	free(p);
}

/** Declare an array structure. */
#define array_t(type) struct {type * at; size_t len; size_t cap; }

/** Zero-initialize the array. */
#define array_init(array) ((array).at = NULL, (array).len = (array).cap = 0)

/** Free and zero-initialize the array (plain malloc/free). */
#define array_clear(array) \
	array_clear_mm(array, array_std_free, NULL)

/** Make the array empty and free pointed-to memory.
 * Mempool usage: pass mm_free and a knot_mm_t* . */
#define array_clear_mm(array, free, baton) \
	(free)((baton), (array).at), array_init(array)

/** Reserve capacity for at least n elements.
 * @return 0 if success, <0 on failure */
#define array_reserve(array, n) \
	array_reserve_mm(array, n, array_std_reserve, NULL)

/** Reserve capacity for at least n elements.
 * Mempool usage: pass kr_memreserve and a knot_mm_t* .
 * @return 0 if success, <0 on failure */
#define array_reserve_mm(array, n, reserve, baton) \
	(reserve)((baton), (void **) &(array).at, sizeof((array).at[0]), (n), &(array).cap)

/**
 * Push value at the end of the array, resize it if necessary.
 * Mempool usage: pass kr_memreserve and a knot_mm_t* .
 * @note May fail if the capacity is not reserved.
 * @return element index on success, <0 on failure
 */
#define array_push_mm(array, val, reserve, baton) \
	(int)((array).len < (array).cap ? ((array).at[(array).len] = val, (array).len++) \
		: (array_reserve_mm(array, ((array).cap + 1), reserve, baton) < 0 ? -1 \
			: ((array).at[(array).len] = val, (array).len++)))

/**
 * Push value at the end of the array, resize it if necessary (plain malloc/free).
 * @note May fail if the capacity is not reserved.
 * @return element index on success, <0 on failure
 */
#define array_push(array, val) \
	array_push_mm(array, val, array_std_reserve, NULL)

/**
 * Pop value from the end of the array.
 */
#define array_pop(array) \
 	(array).len -= 1

/**
 * Remove value at given index.
 * @return 0 on success, <0 on failure
 */
#define array_del(array, i) \
	(int)((i) < (array).len ? ((array).len -= 1,(array).at[i] = (array).at[(array).len], 0) : -1)

/**
 * Return last element of the array.
 * @warning Undefined if the array is empty.
 */
#define array_tail(array) \
    (array).at[(array).len - 1]

/** @} */
