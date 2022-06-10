/*  Copyright (C) 2015-2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>

#include <libknot/mm_ctx.h>
#include "lib/defines.h"
#include "lib/utils.h"

/** A managed weak pointer to dynamic memory. Its actual pointer value may
 * be retrieved using `weakptr_get()`.
 *
 * Like a normal pointer, a weak pointer may have a special value
 * of 0 (WEAKPTR_NULL), indicating that the pointer represents no valid memory.
 *
 * For readability, it is encouraged to create own `typedef` declarations
 * for weak pointers to particular data types. Consider `weakptr_t`
 * an equivalent of `void *`. */
typedef unsigned long weakptr_t;

/** Special value for `weakptr_t` indicating that it represents no valid memory. */
#define WEAKPTR_NULL ((weakptr_t) 0)

/** Initializes the weak pointer manager structure. Must be deinitialized
 * using `weakptr_manager_deinit()`. */
KR_EXPORT
int weakptr_manager_init();

/** Deinitializes the weak pointer manager structure. */
KR_EXPORT
void weakptr_manager_deinit();

/** Allocates weak-pointer-managed dynamic memory of `size` using the memory
 * pool `mm`. `mm` may be `NULL`, `malloc()` will then be used instead of a memory
 * pool.
 *
 * If `naked_ptr` is not `NULL`, its target is assigned the naked (non-weak)
 * pointer to the newly allocated memory on success. On error, `*naked_ptr`
 * remains unchanged.
 *
 * Returns `WEAKPTR_NULL` on error. */
KR_EXPORT
weakptr_t weakptr_mm_alloc(knot_mm_t *mm, size_t size, void **naked_ptr);

/** Allocates weak-pointer-managed dynamic memory of `size` using `malloc()`.
 *
 * If `naked_ptr` is not `NULL`, its target is assigned the naked (non-weak)
 * pointer to the newly allocated memory on success. On error, `*naked_ptr`
 * remains unchanged.
 *
 * Returns `WEAKPTR_NULL` on error. */
static inline weakptr_t weakptr_malloc(size_t size, void **naked_ptr)
{
	return weakptr_mm_alloc(NULL, size, naked_ptr);
}

/** Frees the specified `ptr` using the memory pool `mm`. `mm` may be `NULL`,
 * `free()` will then be used instead of a memory pool. */
KR_EXPORT
void weakptr_mm_free(knot_mm_t *mm, weakptr_t ptr);

/** Frees the specified `ptr` using `free()`. If `ptr` is `WEAKPTR_NULL`,
 * no operation is performed. */
static inline void weakptr_free(weakptr_t ptr)
{
	weakptr_mm_free(NULL, ptr);
}

/** Retrieves the value of the `ptr`. Returns `NULL` if the memory pointed to
 * by `ptr` has already been freed, or if `ptr` itself is `WEAKPTR_NULL`. */
KR_EXPORT
void *weakptr_get(weakptr_t ptr);
