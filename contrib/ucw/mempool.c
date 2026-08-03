/*
 *  UCW Library -- Memory Pools (One-Time Allocation)
 *
 *  (c) 1997--2014 Martin Mares <mj@ucw.cz>
 *  (c) 2007--2015 Pavel Charvat <pchar@ucw.cz>
 *  (c) 2015, 2017, 2026 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  Source: https://www.ucw.cz/libucw/
 */

#undef LOCAL_DEBUG

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <ucw/config.h>
#include <ucw/lib.h>
#include <ucw/mempool.h>
#include <lib/log.h>

#pragma GCC diagnostic ignored "-Wpointer-arith"

#define MP_CHUNK_TAIL ALIGN_TO(sizeof(struct mempool_chunk), CPU_STRUCT_ALIGN)
#define MP_SIZE_MAX (UINT32_MAX - MP_CHUNK_TAIL - CPU_PAGE_SIZE)

#define CONFIG_UCW_POOL_IS_MMAP       // use mmap backend (for normal chunks instead of malloc)
#define CONFIG_UCW_POOL_IS_REUSABLE   // reuse chunks across pools

/** \note Imported MMAP backend from bigalloc.c */
#ifdef CONFIG_UCW_POOL_IS_MMAP
#include <sys/mman.h>
static void *
page_alloc(size_t len)
{
	if (!len) {
		return NULL;
	}
	if (len > UINT32_MAX) {
		return NULL;
	}
	assert(!(len & (CPU_PAGE_SIZE-1)));
	uint8_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (p == (uint8_t*) MAP_FAILED) {
		return NULL;
	}
	return p;
}

static void
page_free(void *start, size_t len)
{
	assert(!(len & (CPU_PAGE_SIZE-1)));
	assert(!((uintptr_t) start & (CPU_PAGE_SIZE-1)));
	munmap(start, len);
}
#endif

static size_t
mp_align_size(size_t size)
{
	size = MAX(size, 64 + MP_CHUNK_TAIL);
#ifdef CONFIG_UCW_POOL_IS_MMAP
	return ALIGN_TO(size, CPU_PAGE_SIZE) - MP_CHUNK_TAIL;
#else
	return ALIGN_TO(size, CPU_STRUCT_ALIGN) - MP_CHUNK_TAIL;
#endif
}

void
mp_init(struct mempool *pool, size_t chunk_size)
{
	chunk_size = mp_align_size(MAX(sizeof(struct mempool), chunk_size));
	*pool = (struct mempool) {
		.chunk_size = chunk_size,
	};
}

#ifndef CONFIG_UCW_POOL_IS_REUSABLE
static void *
mp_new_big_chunk(size_t size)
{
	uint8_t *data = malloc(size + MP_CHUNK_TAIL);
	if (!data) {
		return NULL;
	}
	MEMCHECK_NOACCESS(data, size);
	struct mempool_chunk *chunk = (struct mempool_chunk *)(data + size);
	chunk->size = size;
	return chunk;
}

static void
mp_free_big_chunk(struct mempool_chunk *chunk)
{
	void *ptr = (uint8_t *)chunk - chunk->size;
	MEMCHECK_UNDEFINED(ptr, chunk->size);
	free(ptr);
}
#endif

static void *
mp_new_chunk(size_t size)
{
#ifdef CONFIG_UCW_POOL_IS_MMAP
	uint8_t *data = page_alloc(size + MP_CHUNK_TAIL);
	if (!data) {
		return NULL;
	}
	MEMCHECK_NOACCESS(data, size);
	struct mempool_chunk *chunk = (struct mempool_chunk *)(data + size);
	chunk->size = size;
	return chunk;
#else
	return mp_new_big_chunk(size);
#endif
}

static void
mp_free_chunk(struct mempool_chunk *chunk)
{
#ifdef CONFIG_UCW_POOL_IS_MMAP
	uint8_t *data = (uint8_t *)chunk - chunk->size;
	MEMCHECK_UNDEFINED(data, chunk->size);
	page_free(data, chunk->size + MP_CHUNK_TAIL);
#else
	mp_free_big_chunk(chunk);
#endif
}

// --- reusable chunks ---
#ifdef  CONFIG_UCW_POOL_IS_REUSABLE
const uint32_t mp_reusable_sizes[] = { 4 * 1024 - MP_CHUNK_TAIL, 16 * 1024 - MP_CHUNK_TAIL, 68 * 1024 - MP_CHUNK_TAIL};
#define MP_REUSABLE_CNT ARRAY_SIZE(mp_reusable_sizes)
struct mp_reusable {
	size_t unused_cnt, total_cnt;
	struct mempool_chunk *chunk;
} mp_reusable[MP_REUSABLE_CNT] = {0};

struct mp_reusable *mp_get_reusable(uint32_t *size) {
	for (int i = 0; i < MP_REUSABLE_CNT; i++) {
		if (*size <= mp_reusable_sizes[i]) {
			*size = mp_reusable_sizes[i];
			return mp_reusable + i;
		}
	}
	return NULL;
}

static void *
mp_new_reusable_chunk(uint32_t size) {
	struct mempool_chunk *chunk = NULL;
	struct mp_reusable *reusable = mp_get_reusable(&size);
	if (reusable) {
		chunk = reusable->chunk;
		if (chunk) {
			reusable->unused_cnt--;
			reusable->chunk = chunk->next;
			return chunk;
		}
		reusable->total_cnt++;
	}
	return mp_new_chunk(size);
}

static void
mp_free_reusable_chunk(struct mempool_chunk *chunk) {
	uint32_t size = chunk->size;
	struct mp_reusable *reusable = mp_get_reusable(&chunk->size);
	if (reusable) {
		reusable->unused_cnt++;
		chunk->next = reusable->chunk;
		reusable->chunk = chunk;
	} else {
		mp_free_chunk(chunk);
	}
}

static void
mp_balance_reusable(void) {
	// just free all unused chunks for now
	for (int i = 0; i < MP_REUSABLE_CNT; i++) {
		for (struct mempool_chunk *chunk = mp_reusable[i].chunk; chunk; ) {
			struct mempool_chunk *next = chunk->next;
			mp_free_chunk(chunk);
			chunk = next;
		}
		mp_reusable[i].chunk = NULL;
		mp_reusable[i].total_cnt -= mp_reusable[i].unused_cnt;
		mp_reusable[i].unused_cnt = 0;
	}
}

#define mp_new_chunk       mp_new_reusable_chunk
#define mp_free_chunk      mp_free_reusable_chunk
#define mp_new_big_chunk   mp_new_reusable_chunk
#define mp_free_big_chunk  mp_free_reusable_chunk
#define CONFIG_UCW_POOL_ACTIVE_CHUNKS (ARRAY_SIZE(mp_reusable) + 1)
#else
#define CONFIG_UCW_POOL_ACTIVE_CHUNKS 2
#endif
// ------


struct mempool *
mp_new(size_t chunk_size)
{
	chunk_size = mp_align_size(MAX(sizeof(struct mempool), chunk_size));
	struct mempool_chunk *chunk = mp_new_chunk(chunk_size);
	struct mempool *pool = (void *)chunk - chunk->size;
	MEMCHECK_UNDEFINED(pool, sizeof(*pool));
	DBG("Creating mempool %p with %zu bytes long chunks", pool, chunk_size);
	chunk->next = NULL;
#ifdef CONFIG_DEBUG
	chunk->pool = pool;
#endif
	chunk->free = chunk_size - sizeof(*pool);
	MEMCHECK_NOACCESS(chunk, MP_CHUNK_TAIL);
	*pool = (struct mempool) {
		.last = chunk,
		.chunk_size = chunk_size,
	};
	return pool;
}

static void
mp_free_chain(struct mempool_chunk *chunk)
{
	while (chunk) {
		MEMCHECK_DEFINED(chunk, MP_CHUNK_TAIL);
		struct mempool_chunk *next = chunk->next;
		mp_free_chunk(chunk);
		chunk = next;
	}
}

void
mp_delete(struct mempool *pool)
{
	if (pool == NULL) {
		return;
	}
	DBG("Deleting mempool %p", pool);
	mp_free_chain(pool->last); // can contain the mempool structure
}

void
mp_flush(struct mempool *pool)
{
	struct mempool_chunk *chunk = pool->last, *next, *poolchunk = NULL;
	while (chunk) {
		MEMCHECK_DEFINED(chunk, MP_CHUNK_TAIL);
		next = chunk->next;
		if ((uint8_t *)chunk - chunk->size == (uint8_t *)pool) {
			poolchunk = chunk;
			chunk->next = NULL;
		} else {
			mp_free_chunk(chunk);
		}
		chunk = next;
	}
	if (poolchunk) {
		chunk = poolchunk;
		chunk->free = chunk->size - sizeof(*pool);
		MEMCHECK_NOACCESS((uint8_t *)chunk - chunk->size + sizeof(struct mempool),
				chunk->size - sizeof(struct mempool) + MP_CHUNK_TAIL);
	}
	pool->last = chunk;
}

static void
mp_stats_chain(struct mempool *pool, struct mempool_chunk *chunk, struct mempool_stats *stats)
{
	struct mempool_chunk *next;
	while (chunk) {
		MEMCHECK_DEFINED(chunk, MP_CHUNK_TAIL);
		stats->total_size += chunk->size + MP_CHUNK_TAIL;
		stats->chunks_count++;
		stats->used_size += chunk->size - chunk->free;
		if ((uint8_t *)pool == (uint8_t *)chunk - chunk->size)
			stats->used_size -= sizeof(*pool);
		next = chunk->next;
		MEMCHECK_NOACCESS(chunk, MP_CHUNK_TAIL);
		chunk = next;
	}
}

void
mp_stats(struct mempool *pool, struct mempool_stats *stats)
{
	bzero(stats, sizeof(*stats));
	mp_stats_chain(pool, pool->last, stats);
	assert(stats->used_size <= stats->total_size);
}

size_t
mp_total_size(struct mempool *pool)
{
	struct mempool_stats stats;
	mp_stats(pool, &stats);
	return stats.total_size;
}

static void *
mp_alloc_internal(struct mempool *pool, size_t size)
{
	if (likely(size <= MP_SIZE_MAX)) {
		// try finding space within CONFIG_UCW_POOL_ACTIVE_CHUNKS chunks (excl. the first one)
		if (pool->last) {
			struct mempool_chunk **pchunk, **pfullest;
			pfullest = pchunk = &pool->last;
			MEMCHECK_DEFINED(*pchunk, MP_CHUNK_TAIL);
			for (int i = 1; *(pchunk = &(*pchunk)->next) && (i < CONFIG_UCW_POOL_ACTIVE_CHUNKS) ; i++) {
				MEMCHECK_DEFINED(*pchunk, MP_CHUNK_TAIL);
				size_t avail = (*pchunk)->free & ~(size_t)(CPU_STRUCT_ALIGN - 1);
				if (size <= avail) {
					struct mempool_chunk *chunk = *pchunk;
					chunk->free = avail - size;
					uint8_t *ptr = (uint8_t *)chunk - avail;

					// make pchunk the last one
					*pchunk = chunk->next;
					chunk->next = pool->last;
					pool->last = chunk;

					for (struct mempool_chunk *c = pool->last; MEMCHECK_ACTIVE && c != *pchunk; c = c->next) {
						MEMCHECK_NOACCESS(c, MP_CHUNK_TAIL);
					}
					MEMCHECK_UNDEFINED(ptr, size);
					return ptr;
				}
				if ((*pchunk)->free < (*pfullest)->free) {
					pfullest = pchunk;
				}
			}

			// make pfullest the farthest chunk out of the active ones (no-op if satisfied); it becomes inactive shortly
			struct mempool_chunk *chunk = *pchunk, *fullest = *pfullest;
			*pchunk = fullest;
			*pfullest = fullest->next;
			fullest->next = chunk;

			for (struct mempool_chunk *c = pool->last; MEMCHECK_ACTIVE && c != chunk; c = c->next) {
				MEMCHECK_NOACCESS(c, MP_CHUNK_TAIL);
			}
		}

		// allocate a new chunk
		struct mempool_chunk *chunk = mp_new_chunk(size <= pool->chunk_size ? pool->chunk_size : mp_align_size(size));
		if (!chunk) {
			return NULL;
		}
#ifdef CONFIG_DEBUG
		chunk->pool = pool;
#endif
		chunk->next = pool->last;
		chunk->free = chunk->size - size;
		void *ptr = (uint8_t *)chunk - chunk->size;
		MEMCHECK_NOACCESS(chunk, MP_CHUNK_TAIL);
		pool->last = chunk;
		return ptr;
	} else {
		fprintf(stderr, "Cannot allocate %zu bytes from a mempool", size);
		assert(0);
		return NULL;
	}
}

void *
mp_alloc(struct mempool *pool, size_t size)
{
	MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
	size_t avail = pool->last ? pool->last->free & ~(size_t)(CPU_STRUCT_ALIGN - 1) : 0;
	void *ptr = NULL;
	if (size <= avail) {
		pool->last->free = avail - size;
		ptr = (uint8_t *)pool->last - avail;
		MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
	} else {
		MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
		ptr = mp_alloc_internal(pool, size);
	}
	if (ptr) MEMCHECK_UNDEFINED(ptr, size);
	return ptr;
}

static void *
mp_start_internal(struct mempool *pool, size_t size)
{
	void *ptr = mp_alloc_internal(pool, size);
	if (!ptr)
		return NULL;
	pool->last->free += size;
	return ptr;
}

void *
mp_start(struct mempool *pool, size_t size)
{
	size_t avail = pool->last ? pool->last->free & ~(size_t)(CPU_STRUCT_ALIGN - 1) : 0;
	void *ptr = NULL;
	if (size <= avail) {
		pool->last->free = avail;
		ptr = (uint8_t *)pool->last - avail;
	} else {
		ptr = mp_start_internal(pool, size);
	}
	MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
	MEMCHECK_UNDEFINED(ptr, pool->last->free);
	MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
	return ptr;
}

void *
mp_grow_internal(struct mempool *pool, size_t size)
{
	if (unlikely(size > MP_SIZE_MAX))
		return NULL;
	size_t avail = mp_avail(pool);
	void *ptr = mp_ptr(pool);
	size = MAX(size, likely(avail <= MP_SIZE_MAX / 2) ? avail * 2 : MP_SIZE_MAX);
	void *p = mp_start_internal(pool, size);
	MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
	MEMCHECK_UNDEFINED(p, pool->last->free);
	MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
	memcpy(p, ptr, avail);
	MEMCHECK_NOACCESS(ptr, avail);
	return p;
}

size_t
mp_open(struct mempool *pool, void *ptr)
{
	size_t size = ((uint8_t *)pool->last - (uint8_t *)ptr) - pool->last->free;
	pool->last->free += size;
	MEMCHECK_UNDEFINED(ptr, pool->last->free);
	return size;
}

void *
mp_realloc(struct mempool *pool, void *ptr, size_t size)
{
	mp_open(pool, ptr);
	ptr = mp_grow(pool, size);
	mp_end(pool, (uint8_t *)ptr + size);
	return ptr;
}

void *
mp_spread_internal(struct mempool *pool, void *p, size_t size)
{
	void *old = mp_ptr(pool);
	void *new = mp_grow_internal(pool, p-old+size);
	if (!new) {
		return NULL;
	}
	return p-old+new;
}
