/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/**
 * Generics - simple dynamic array.
 *
 * \note The C has no generics, so it is implemented mostly using macros.
 * Be aware of that, as direct usage of the macros in the evaluating macros
 * may lead to different expectations, i.e.
 * 
 *     MIN(array_push(arr, val))
 *
 *  May evaluate the code twice, leading to unexpected behaviour.
 *  This is a price to pay for absence of proper generics.
 *
 *  Example usage:
 *  
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
 * 
 * \addtogroup generics
 * @{ 
 */

#pragma once

/** @todo Implement mreserve over custom memory context. */
#include <libknot/internal/mem.h>

/** Declare an array structure. */
#define array_t(type) struct {type * at; size_t len; size_t cap; }

/** Zero-initialize the array. */
#define array_init(array) ((array).at = NULL, (array).len = (array).cap = 0)

/** Free and zero-initialize the array. */
#define array_clear(array) \
	free((array).at), array_init(array)

/**
 * Reserve capacity up to 'n' bytes.
 * @return >=0 if success
 */
#define array_reserve(array, n) \
	mreserve((char **) &(array).at, sizeof((array).at[0]), n, 0, &(array).cap)

/**
 * Push value at the end of the array, resize it if necessary.
 * @note May fail if the capacity is not reserved.
 * @return element index on success, <0 on failure
 */
#define array_push(array, val) \
	(array).len < (array).cap ? ((array).at[(array).len] = val, (array).len++) \
		: (array_reserve(array, ((array).cap + 1) * 2) < 0 ? -1 \
			: ((array).at[(array).len] = val, (array).len++))

/**
 * Pop value from the end of the array.
 * @return 0 on success, <0 on failure
 */
#define array_pop(array) \
	array_del((array), (array).len - 1)

/**
 * Remove value at given index.
 * @return 0 on success, <0 on failure
 */
#define array_del(array, i) \
	(i) < (array).len ? ((array).len -= 1,(array).at[i] = (array).at[(array).len], 0) : -1

/**
 * Return last element of the array.
 * @warning Undefined if the array is empty.
 */
#define array_tail(array) \
    (array).at[(array).len - 1]

/** @} */
