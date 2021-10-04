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

/*!
 * \brief Memory allocation related functions.
 */

#pragma once

#include <libknot/mm_ctx.h>
#include "contrib/ucw/mempool.h"
#include "lib/defines.h"
#include <assert.h>
#include <stdint.h>

/*! \brief Default memory block size. */
#define MM_DEFAULT_BLKSIZE 4096

/*! \brief Allocs using 'mm' if any, uses system malloc() otherwise. */
KR_EXPORT
void *mm_alloc(knot_mm_t *mm, size_t size);

/*! \brief Callocs using 'mm' if any, uses system calloc() otherwise. */
void *mm_calloc(knot_mm_t *mm, size_t nmemb, size_t size);

/*! \brief Reallocs using 'mm' if any, uses system realloc() otherwise. */
KR_EXPORT
void *mm_realloc(knot_mm_t *mm, void *what, size_t size, size_t prev_size);

/*! \brief Strdups using 'mm' if any, uses system strdup() otherwise. */
char *mm_strdup(knot_mm_t *mm, const char *s);

/*! \brief Free using 'mm' if any, uses system free() otherwise. */
KR_EXPORT
void mm_free(knot_mm_t *mm, void *what);

/*! \brief Initialize default memory allocation context. */
void mm_ctx_init(knot_mm_t *mm);

/*! \brief Memory pool context. */
void mm_ctx_mempool(knot_mm_t *mm, size_t chunk_size);


/* API in addition to Knot's mempattern. */

/*! \brief New memory pool context, allocated on itself. */
KR_EXPORT knot_mm_t * mm_ctx_mempool2(size_t chunk_size);

/*! \brief Delete a memory pool.  OK to call on a non-pool. */
static inline void mm_ctx_delete(knot_mm_t *mm)
{
	/* The mp_alloc comparison bears a risk of missing the private symbol from knot. */
	if (mm && mm->ctx && mm->alloc == (knot_mm_alloc_t)mp_alloc)
		mp_delete(mm->ctx);
}

/*! \brief Readability: avoid const-casts in code. */
static inline void free_const(const void *what)
{
	free((void *)what);
}

/*! \brief posix_memalign() wrapper. */
void *mm_malloc_aligned(void *ctx, size_t n);

/*! \brief Initialize mm with malloc+free with specified alignment (a power of two). */
static inline void mm_ctx_init_aligned(knot_mm_t *mm, size_t alignment)
{
	assert(__builtin_popcount(alignment) == 1);
	mm_ctx_init(mm);
	mm->ctx = (uint8_t *)NULL + alignment; /*< roundabout to satisfy linters */
	/* posix_memalign() doesn't allow alignment < sizeof(void*),
	 * and there's no point in using it for small values anyway,
	 * as plain malloc() guarantees at least max_align_t. */
	if (alignment > sizeof(max_align_t)) {
		mm->alloc = mm_malloc_aligned;
	}
}

