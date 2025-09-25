/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>

#include "contrib/mempattern.h"
#include "contrib/ucw/mempool.h"

static void mm_nofree(void *p)
{
	/* nop */
}

static void *mm_malloc(void *ctx, size_t n)
{
	(void)ctx;
	return malloc(n);
}

void *mm_alloc(knot_mm_t *mm, size_t size)
{
	if (mm) {
		return mm->alloc(mm->ctx, size);
	} else {
		return malloc(size);
	}
}

void *mm_calloc(knot_mm_t *mm, size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0) {
		return NULL;
	}
	if (mm) {
		size_t total_size = nmemb * size;
		if (total_size / nmemb != size) { // Overflow check
			return NULL;
		}
		void *mem = mm_alloc(mm, total_size);
		if (mem == NULL) {
			return NULL;
		}
		return memset(mem, 0, total_size);
	} else {
		return calloc(nmemb, size);
	}
}

void *mm_realloc(knot_mm_t *mm, void *what, size_t size, size_t prev_size)
{
	if (mm) {
		void *p = mm->alloc(mm->ctx, size);
		if (p == NULL) {
			return NULL;
		} else {
			if (what) {
				memcpy(p, what,
				       prev_size < size ? prev_size : size);
			}
			mm_free(mm, what);
			return p;
		}
	} else {
		return realloc(what, size);
	}
}

char *mm_strdup(knot_mm_t *mm, const char *s)
{
	if (s == NULL) {
		return NULL;
	}
	if (mm) {
		size_t len = strlen(s) + 1;
		void *mem = mm_alloc(mm, len);
		if (mem == NULL) {
			return NULL;
		}
		return memcpy(mem, s, len);
	} else {
		return strdup(s);
	}
}

void mm_free(knot_mm_t *mm, void *what)
{
	if (mm) {
		if (mm->free) {
			mm->free(what);
		}
	} else {
		free(what);
	}
}

void mm_ctx_init(knot_mm_t *mm)
{
	mm->ctx = NULL;
	mm->alloc = mm_malloc;
	mm->free = free;
}

// UBSAN type punning workaround
static void *mp_alloc_wrap(void *ctx, size_t size)
{
	return mp_alloc(ctx, size);
}

void mm_ctx_mempool(knot_mm_t *mm, size_t chunk_size)
{
	mm->ctx = mp_new(chunk_size);
	mm->alloc = mp_alloc_wrap;
	mm->free = mm_nofree;
}


/* Code in addition to Knot's mempattern. */

void *mm_malloc_aligned(void *ctx, size_t n)
{
	size_t alignment = (uintptr_t)ctx;
	void *res;
	int err = posix_memalign(&res, alignment, n);
	if (err == 0) {
		return res;
	} else {
		assert(err == -1 && errno == ENOMEM);
		return NULL;
	}
}

knot_mm_t * mm_ctx_mempool2(size_t chunk_size)
{
	knot_mm_t pool_tmp;
	mm_ctx_mempool(&pool_tmp, chunk_size);
	knot_mm_t *pool = mm_alloc(&pool_tmp, sizeof(*pool));
	if (!pool) {
		mp_delete(pool_tmp.ctx);
		return NULL;
	}
	memcpy(pool, &pool_tmp, sizeof(*pool));
	return pool;
}

