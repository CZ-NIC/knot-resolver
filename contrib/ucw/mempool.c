/*
 *      UCW Library -- Memory Pools (One-Time Allocation)
 *
 *      (c) 1997--2014 Martin Mares <mj@ucw.cz>
 *      (c) 2007--2015 Pavel Charvat <pchar@ucw.cz>
 *
 *      SPDX-License-Identifier: LGPL-2.1-or-later
 *      Source: https://www.ucw.cz/libucw/
 */

#undef LOCAL_DEBUG

#include <ucw/config.h>
#include <ucw/lib.h>
#include <ucw/mempool.h>

#include <string.h>
#include <stdlib.h>

/* FIXME: migrate to Knot DNS version of mempools. */
#pragma GCC diagnostic ignored "-Wpointer-arith"

#define MP_CHUNK_TAIL ALIGN_TO(sizeof(struct mempool_chunk), CPU_STRUCT_ALIGN)
#define MP_SIZE_MAX (SIZE_MAX - MP_CHUNK_TAIL - CPU_PAGE_SIZE)

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
#ifdef CONFIG_UCW_POOL_IS_MMAP
	size = MAX(size, 64 + MP_CHUNK_TAIL);
	return ALIGN_TO(size, CPU_PAGE_SIZE) - MP_CHUNK_TAIL;
#else
	return ALIGN_TO(size, CPU_STRUCT_ALIGN);
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
mp_new_big_chunk(struct mempool *pool, size_t size)
{
	struct mempool_chunk *chunk;
	chunk = malloc(size + MP_CHUNK_TAIL);
	if (!chunk)
		return NULL;
	chunk = (struct mempool_chunk *)((char *)chunk + size);
	chunk->size = size;
	if (pool)
		pool->total_size += size + MP_CHUNK_TAIL;
	return chunk;
}

static void
mp_free_big_chunk(struct mempool *pool, struct mempool_chunk *chunk)
{
	pool->total_size -= chunk->size + MP_CHUNK_TAIL;
	free((void *)chunk - chunk->size);
}

static void *
mp_new_chunk(struct mempool *pool, size_t size)
{
#ifdef CONFIG_UCW_POOL_IS_MMAP
	struct mempool_chunk *chunk;
	chunk = page_alloc(size + MP_CHUNK_TAIL) + size;
	chunk->size = size;
	if (pool)
		pool->total_size += size + MP_CHUNK_TAIL;
	return chunk;
#else
	return mp_new_big_chunk(pool, size);
#endif
}

static void
mp_free_chunk(struct mempool *pool, struct mempool_chunk *chunk)
{
#ifdef CONFIG_UCW_POOL_IS_MMAP
	pool->total_size -= chunk->size + MP_CHUNK_TAIL;
	page_free((void *)chunk - chunk->size, chunk->size + MP_CHUNK_TAIL);
#else
	mp_free_big_chunk(pool, chunk);
#endif
}

struct mempool *
mp_new(size_t chunk_size)
{
	chunk_size = mp_align_size(MAX(sizeof(struct mempool), chunk_size));
	struct mempool_chunk *chunk = mp_new_chunk(NULL, chunk_size);
	struct mempool *pool = (void *)chunk - chunk_size;
	DBG("Creating mempool %p with %zu bytes long chunks", pool, chunk_size);
	chunk->next = NULL;
#ifdef CONFIG_DEBUG
	chunk->pool = pool;
#endif
	*pool = (struct mempool) {
		.state = { .free = { chunk_size - sizeof(*pool) }, .last = { chunk } },
		.chunk_size = chunk_size,
		.threshold = chunk_size >> 1,
		.last_big = &pool->last_big,
		.total_size = chunk->size + MP_CHUNK_TAIL,
	};
	return pool;
}

static void
mp_free_chain(struct mempool *pool, struct mempool_chunk *chunk)
{
	while (chunk) {
		struct mempool_chunk *next = chunk->next;
		mp_free_chunk(pool, chunk);
		chunk = next;
	}
}

static void
mp_free_big_chain(struct mempool *pool, struct mempool_chunk *chunk)
{
	while (chunk) {
		struct mempool_chunk *next = chunk->next;
		mp_free_big_chunk(pool, chunk);
		chunk = next;
	}
}

void
mp_delete(struct mempool *pool)
{
	DBG("Deleting mempool %p", pool);
	mp_free_big_chain(pool, pool->state.last[1]);
	mp_free_chain(pool, pool->unused);
	mp_free_chain(pool, pool->state.last[0]); // can contain the mempool structure
}

void
mp_flush(struct mempool *pool)
{
	mp_free_big_chain(pool, pool->state.last[1]);
	struct mempool_chunk *chunk, *next;
	for (chunk = pool->state.last[0]; chunk && (void *)chunk - chunk->size != pool; chunk = next) {
		next = chunk->next;
		chunk->next = pool->unused;
		pool->unused = chunk;
	}
	pool->state.last[0] = chunk;
	pool->state.free[0] = chunk ? chunk->size - sizeof(*pool) : 0;
	pool->state.last[1] = NULL;
	pool->state.free[1] = 0;
	pool->last_big = &pool->last_big;
}

static void
mp_stats_chain(struct mempool *pool, struct mempool_chunk *chunk, struct mempool_stats *stats, unsigned idx)
{
	while (chunk) {
		stats->chain_size[idx] += chunk->size + MP_CHUNK_TAIL;
		stats->chain_count[idx]++;
		if (idx < 2) {
			stats->used_size += chunk->size;
			if ((uint8_t *)pool == (uint8_t *)chunk - chunk->size)
				stats->used_size -= sizeof(*pool);
		}
		chunk = chunk->next;
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
	ASSERT(stats->total_size == pool->total_size);
	ASSERT(stats->used_size <= stats->total_size);
}

uint64_t
mp_total_size(struct mempool *pool)
{
	return pool->total_size;
}

void
mp_shrink(struct mempool *pool, uint64_t min_total_size)
{
	while (1) {
		struct mempool_chunk *chunk = pool->unused;
		if (!chunk || pool->total_size - (chunk->size + MP_CHUNK_TAIL) < min_total_size)
			break;
		pool->unused = chunk->next;
		mp_free_chunk(pool, chunk);
	}
}

void *
mp_alloc_internal(struct mempool *pool, size_t size)
{
	struct mempool_chunk *chunk;
	if (size <= pool->threshold) {
		pool->idx = 0;
		if (pool->unused) {
			chunk = pool->unused;
			pool->unused = chunk->next;
		} else {
			chunk = mp_new_chunk(pool, pool->chunk_size);
#ifdef CONFIG_DEBUG
			chunk->pool = pool;
#endif
		}
		chunk->next = pool->state.last[0];
		pool->state.last[0] = chunk;
		pool->state.free[0] = pool->chunk_size - size;
		return (void *)chunk - pool->chunk_size;
	} else if (likely(size <= MP_SIZE_MAX)) {
		pool->idx = 1;
		size_t aligned = ALIGN_TO(size, CPU_STRUCT_ALIGN);
		chunk = mp_new_big_chunk(pool, aligned);
		chunk->next = pool->state.last[1];
#ifdef CONFIG_DEBUG
		chunk->pool = pool;
#endif
		pool->state.last[1] = chunk;
		pool->state.free[1] = aligned - size;
		return pool->last_big = (void *)chunk - aligned;
	} else
		return NULL;
}

void *
mp_alloc(struct mempool *pool, size_t size)
{
	return mp_alloc_fast(pool, size);
}

void *
mp_alloc_noalign(struct mempool *pool, size_t size)
{
	return mp_alloc_fast_noalign(pool, size);
}

void *
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
	return mp_start_fast(pool, size);
}

void *
mp_start_noalign(struct mempool *pool, size_t size)
{
	return mp_start_fast_noalign(pool, size);
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
		struct mempool_chunk *chunk = pool->state.last[1], *next = chunk->next;
		pool->total_size = pool->total_size - chunk->size + amortized;
		void *nptr = realloc(ptr, amortized + MP_CHUNK_TAIL);
		if (!nptr)
			return NULL;
		ptr = nptr;
		chunk = ptr + amortized;
		chunk->next = next;
		chunk->size = amortized;
		pool->state.last[1] = chunk;
		pool->state.free[1] = amortized;
		pool->last_big = ptr;
		return ptr;
	} else {
		void *p = mp_start_internal(pool, size);
		memcpy(p, ptr, avail);
		return p;
	}
}

size_t
mp_open(struct mempool *pool, void *ptr)
{
	return mp_open_fast(pool, ptr);
}

void *
mp_realloc(struct mempool *pool, void *ptr, size_t size)
{
	return mp_realloc_fast(pool, ptr, size);
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
