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

#pragma GCC diagnostic ignored "-Wpointer-arith"

#define MP_CHUNK_TAIL ALIGN_TO(sizeof(struct mempool_chunk), CPU_STRUCT_ALIGN)
#define MP_SIZE_MAX (SIZE_MAX - MP_CHUNK_TAIL - CPU_PAGE_SIZE)

/** \note Imported MMAP backend from bigalloc.c */
//#define CONFIG_UCW_POOL_IS_MMAP
#ifdef CONFIG_UCW_POOL_IS_MMAP
#include <sys/mman.h>
static void *
page_alloc(uint64_t len)
{
	if (!len) {
		return NULL;
	}
	if (len > SIZE_MAX) {
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
page_free(void *start, uint64_t len)
{
	assert(!(len & (CPU_PAGE_SIZE-1)));
	assert(!((uintptr_t) start & (CPU_PAGE_SIZE-1)));
	munmap(start, len);
}
#endif

struct mempool_chunk {
#ifdef CONFIG_DEBUG
	struct mempool *pool;         // Can be useful when analysing coredump for memory leaks
#endif
	struct mempool_chunk *next;
	size_t size;
};

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
		.threshold = chunk_size >> 1,
		.last_big = &pool->last_big
	};
}

static void *
mp_new_big_chunk(size_t size)
{
	uint8_t *data = malloc(size + MP_CHUNK_TAIL);
	if (!data) {
		return NULL;
	}
	ASAN_POISON_MEMORY_REGION(data, size);
	struct mempool_chunk *chunk = (struct mempool_chunk *)(data + size);
	chunk->size = size;
	return chunk;
}

static void
mp_free_big_chunk(struct mempool_chunk *chunk)
{
	void *ptr = (uint8_t *)chunk - chunk->size;
	ASAN_UNPOISON_MEMORY_REGION(ptr, chunk->size);
	free(ptr);
}

static void *
mp_new_chunk(size_t size)
{
#ifdef CONFIG_UCW_POOL_IS_MMAP
	uint8_t *data = page_alloc(size + MP_CHUNK_TAIL);
	if (!data) {
		return NULL;
	}
	ASAN_POISON_MEMORY_REGION(data, size);
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
	ASAN_UNPOISON_MEMORY_REGION(data, chunk->size);
	page_free(data, chunk->size + MP_CHUNK_TAIL);
#else
	mp_free_big_chunk(chunk);
#endif
}

struct mempool *
mp_new(size_t chunk_size)
{
	chunk_size = mp_align_size(MAX(sizeof(struct mempool), chunk_size));
	struct mempool_chunk *chunk = mp_new_chunk(chunk_size);
	struct mempool *pool = (void *)chunk - chunk_size;
	ASAN_UNPOISON_MEMORY_REGION(pool, sizeof(*pool));
	DBG("Creating mempool %p with %zu bytes long chunks", pool, chunk_size);
	chunk->next = NULL;
#ifdef CONFIG_DEBUG
	chunk->pool = pool;
#endif
	ASAN_POISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
	*pool = (struct mempool) {
		.state = { .free = { chunk_size - sizeof(*pool) }, .last = { chunk } },
		.chunk_size = chunk_size,
		.threshold = chunk_size >> 1,
		.last_big = &pool->last_big
	};
	return pool;
}

static void
mp_free_chain(struct mempool_chunk *chunk)
{
	while (chunk) {
		ASAN_UNPOISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
		struct mempool_chunk *next = chunk->next;
		mp_free_chunk(chunk);
		chunk = next;
	}
}

static void
mp_free_big_chain(struct mempool_chunk *chunk)
{
	while (chunk) {
		ASAN_UNPOISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
		struct mempool_chunk *next = chunk->next;
		mp_free_big_chunk(chunk);
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
	mp_free_big_chain(pool->state.last[1]);
	mp_free_chain(pool->unused);
	mp_free_chain(pool->state.last[0]); // can contain the mempool structure
}

void
mp_flush(struct mempool *pool)
{
	mp_free_big_chain(pool->state.last[1]);
	struct mempool_chunk *chunk = pool->state.last[0], *next;
	while (chunk) {
		ASAN_UNPOISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
		if ((uint8_t *)chunk - chunk->size == (uint8_t *)pool) {
			break;
		}
		next = chunk->next;
		chunk->next = pool->unused;
		ASAN_POISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
		pool->unused = chunk;
		chunk = next;
	}
	pool->state.last[0] = chunk;
	if (chunk) {
		pool->state.free[0] = chunk->size - sizeof(*pool);
		ASAN_POISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
	} else {
		pool->state.free[0] = 0;
	}
	pool->state.last[1] = NULL;
	pool->state.free[1] = 0;
	pool->last_big = &pool->last_big;
}

static void
mp_stats_chain(struct mempool *pool, struct mempool_chunk *chunk, struct mempool_stats *stats, unsigned idx)
{
	struct mempool_chunk *next;
	while (chunk) {
		ASAN_UNPOISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
		stats->chain_size[idx] += chunk->size + MP_CHUNK_TAIL;
		stats->chain_count[idx]++;
		if (idx < 2) {
			stats->used_size += chunk->size;
			if ((uint8_t *)pool == (uint8_t *)chunk - chunk->size)
				stats->used_size -= sizeof(*pool);
		}
		next = chunk->next;
		ASAN_POISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
		chunk = next;
	}
	stats->total_size += stats->chain_size[idx];
}

void
mp_stats(struct mempool *pool, struct mempool_stats *stats)
{
	bzero(stats, sizeof(*stats));
	mp_stats_chain(pool, pool->state.last[0], stats, 0);
	mp_stats_chain(pool, pool->state.last[1], stats, 1);
	mp_stats_chain(pool, pool->unused, stats, 2);
	stats->used_size -= pool->state.free[0] + pool->state.free[1];
	assert(stats->used_size <= stats->total_size);
}

uint64_t
mp_total_size(struct mempool *pool)
{
	struct mempool_stats stats;
	mp_stats(pool, &stats);
	return stats.total_size;
}

void
mp_shrink(struct mempool *pool, uint64_t min_total_size)
{
	size_t total_size = mp_total_size(pool);
	while (pool->unused) {
		struct mempool_chunk *chunk = pool->unused;
		ASAN_UNPOISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
		total_size -= chunk->size + MP_CHUNK_TAIL;
		if (total_size < min_total_size) {
			ASAN_POISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
			break;
		}
		pool->unused = chunk->next;
		mp_free_chunk(chunk);
	}
}

static void *
mp_alloc_internal(struct mempool *pool, size_t size)
{
	struct mempool_chunk *chunk;
	if (size <= pool->threshold) {
		pool->idx = 0;
		if (pool->unused) {
			chunk = pool->unused;
			ASAN_UNPOISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
			pool->unused = chunk->next;
		} else {
			chunk = mp_new_chunk(pool->chunk_size);
			if (!chunk) {
				return NULL;
			}
#ifdef CONFIG_DEBUG
			chunk->pool = pool;
#endif
		}
		chunk->next = pool->state.last[0];
		ASAN_POISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
		pool->state.last[0] = chunk;
		pool->state.free[0] = pool->chunk_size - size;
		return (uint8_t *)chunk - pool->chunk_size;
	} else if (likely(size <= MP_SIZE_MAX)) {
		pool->idx = 1;
		size_t aligned = ALIGN_TO(size, CPU_STRUCT_ALIGN);
		chunk = mp_new_big_chunk(aligned);
		if (!chunk) {
			return NULL;
		}
		chunk->next = pool->state.last[1];
#ifdef CONFIG_DEBUG
		chunk->pool = pool;
#endif

		ASAN_POISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
		pool->state.last[1] = chunk;
		pool->state.free[1] = aligned - size;
		return pool->last_big = (uint8_t *)chunk - aligned;
	} else {
		fprintf(stderr, "Cannot allocate %zu bytes from a mempool", size);
		assert(0);
		return NULL;
	}
}

void *
mp_alloc(struct mempool *pool, size_t size)
{
	size_t avail = pool->state.free[0] & ~(size_t)(CPU_STRUCT_ALIGN - 1);
	void *ptr = NULL;
	if (size <= avail) {
		pool->state.free[0] = avail - size;
		ptr = (uint8_t *)pool->state.last[0] - avail;
	} else {
		ptr = mp_alloc_internal(pool, size);
	}
	if (ptr) ASAN_UNPOISON_MEMORY_REGION(ptr, size);
	return ptr;
}

void *
mp_alloc_noalign(struct mempool *pool, size_t size)
{
	void *ptr = NULL;
	if (size <= pool->state.free[0]) {
		ptr = (uint8_t *)pool->state.last[0] - pool->state.free[0];
		pool->state.free[0] -= size;
	} else {
		ptr = mp_alloc_internal(pool, size);
	}
	ASAN_UNPOISON_MEMORY_REGION(ptr, size);
	return ptr;
}

static void *
mp_start_internal(struct mempool *pool, size_t size)
{
	void *ptr = mp_alloc_internal(pool, size);
	if (!ptr)
		return NULL;
	pool->state.free[pool->idx] += size;
	return ptr;
}

void *
mp_start(struct mempool *pool, size_t size)
{
	size_t avail = pool->state.free[0] & ~(size_t)(CPU_STRUCT_ALIGN - 1);
	void *ptr = NULL;
	if (size <= avail) {
		pool->idx = 0;
		pool->state.free[0] = avail;
		ptr = (uint8_t *)pool->state.last[0] - avail;
	} else {
		ptr = mp_start_internal(pool, size);
	}
	ASAN_UNPOISON_MEMORY_REGION(ptr, pool->state.free[pool->idx]);
	return ptr;
}

void *
mp_start_noalign(struct mempool *pool, size_t size)
{
	void *ptr = NULL;
	if (size <= pool->state.free[0]) {
		pool->idx = 0;
		ptr = (uint8_t *)pool->state.last[0] - pool->state.free[0];
	} else {
		ptr = mp_start_internal(pool, size);
	}
	ASAN_UNPOISON_MEMORY_REGION(ptr, pool->state.free[pool->idx]);
	return ptr;
}

void *
mp_grow_internal(struct mempool *pool, size_t size)
{
	if (unlikely(size > MP_SIZE_MAX))
		return NULL;
	size_t avail = mp_avail(pool);
	void *ptr = mp_ptr(pool);
	if (pool->idx) {
		size_t amortized = likely(avail <= MP_SIZE_MAX / 2) ? avail * 2 : MP_SIZE_MAX;
		amortized = MAX(amortized, size);
		amortized = ALIGN_TO(amortized, CPU_STRUCT_ALIGN);
		struct mempool_chunk *chunk = pool->state.last[1];
		ASAN_UNPOISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
		struct mempool_chunk *next = chunk->next;
		void *nptr = realloc(ptr, amortized + MP_CHUNK_TAIL);
		if (!nptr) {
			ASAN_POISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
			return NULL;
		}
		ptr = nptr;
		chunk = ptr + amortized;
		chunk->next = next;
		chunk->size = amortized;
		ASAN_POISON_MEMORY_REGION(chunk, sizeof(struct mempool_chunk));
		pool->state.last[1] = chunk;
		pool->state.free[1] = amortized;
		pool->last_big = ptr;
		return ptr;
	} else {
		void *p = mp_start_internal(pool, size);
		ASAN_UNPOISON_MEMORY_REGION(p, pool->state.free[pool->idx]);
		memcpy(p, ptr, avail);
		ASAN_POISON_MEMORY_REGION(ptr, avail);
		return p;
	}
}

size_t
mp_open(struct mempool *pool, void *ptr)
{
	pool->idx = mp_idx(pool, ptr);
	size_t size = ((uint8_t *)pool->state.last[pool->idx] - (uint8_t *)ptr) - pool->state.free[pool->idx];
	pool->state.free[pool->idx] += size;
	ASAN_UNPOISON_MEMORY_REGION(ptr, pool->state.free[pool->idx]);
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
