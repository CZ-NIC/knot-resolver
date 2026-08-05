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

/** \note Imported MMAP backend from bigalloc.c */
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

static size_t
mp_align_size(size_t size)
{
	size = MAX(size, 64 + MP_CHUNK_TAIL);
	return ALIGN_TO(size, CPU_PAGE_SIZE) - MP_CHUNK_TAIL;
}

void
mp_init(struct mempool *pool, size_t chunk_size)
{

	chunk_size = MAX(sizeof(struct mempool), chunk_size);
	chunk_size = chunk_size < 2048 ? chunk_size : mp_align_size(chunk_size);
	*pool = (struct mempool) {
		.chunk_size = chunk_size,
	};
}

static void *
mp_new_chunk(size_t size)
{
	uint8_t *data = page_alloc(size + MP_CHUNK_TAIL);
	if (!data) {
		return NULL;
	}
	MEMCHECK_NOACCESS(data, size);
	struct mempool_chunk *chunk = (struct mempool_chunk *)(data + size);
	chunk->size = size;
	return chunk;
}

static void
mp_free_chunk(struct mempool_chunk *chunk)
{
	uint8_t *data = (uint8_t *)chunk - chunk->size;
	MEMCHECK_UNDEFINED(data, chunk->size);
	page_free(data, chunk->size + MP_CHUNK_TAIL);
}

// --- reusable chunks ---
#define MP_REUSABLE_CNT ARRAY_SIZE(mp_reusable_sizes)
#define MP_UNUSED_TAIL ALIGN_TO(sizeof(struct mp_unused), CPU_STRUCT_ALIGN)
struct mp_unused {
	uint32_t timestamp;
	uint32_t count;
	struct mempool_chunk *chunk;  // single normal chunk or list of small unused chunks within their page
	struct mp_unused *next;
	struct mp_unused *prev;
};

static inline struct mp_unused *chunk_to_unused(struct mempool_chunk *chunk)
{
	struct mp_unused *unused;
	if (chunk->size < CPU_PAGE_SIZE >> 1) {
		unused = (void *)((uintptr_t)(chunk) & (UINTPTR_MAX - CPU_PAGE_SIZE + 1)) + CPU_PAGE_SIZE - MP_UNUSED_TAIL;
	} else {
		unused = (void *)(chunk) - MP_UNUSED_TAIL;
		memset(unused, 0, sizeof(*unused));
	}

	unused->count++;
	chunk->prev = unused->chunk;
	unused->chunk = chunk;

	return unused;
}
static struct mp_unused *mp_new_small_chunks(size_t size) {
	uint8_t *data = page_alloc(CPU_PAGE_SIZE);
	if (!data) {
		return NULL;
	}
	struct mp_unused *unused = (struct mp_unused *)(data + CPU_PAGE_SIZE - MP_UNUSED_TAIL);
	memset(unused, 0, sizeof(*unused));
	while ((data + size + MP_CHUNK_TAIL) <= (uint8_t *) unused) {
		struct mempool_chunk *chunk = (struct mempool_chunk *)(data + size);
		chunk->size = size;
		chunk->prev = unused->chunk;
		unused->chunk = chunk;
		unused->count++;
		data += size + MP_CHUNK_TAIL;
	}
	return unused;
}
static void mp_free_small_chunks(struct mp_unused *unused) {
	uint8_t *data = (uint8_t *)unused + MP_UNUSED_TAIL - CPU_PAGE_SIZE;
	page_free(data, CPU_PAGE_SIZE);
}
static inline void mp_insert_unused(struct mp_unused *item, struct mp_unused *after) {
	item->prev = after;
	item->next = after->next;
	after->next = item;
	item->next->prev = item;
}
static inline void mp_remove_unused(struct mp_unused *item) {
	item->prev->next = item->next;
	item->next->prev = item->prev;
	item->next = NULL;
	item->prev = NULL;
}

const uint32_t mp_reusable_sizes[] = { (CPU_PAGE_SIZE - MP_UNUSED_TAIL) / 4, 4 * 1024, 16 * 1024, 68 * 1024};
struct mp_reusable {
	size_t unused_cnt, total_cnt;
	struct mp_unused head, sep;
	uint32_t chunk_size, chunks_per_block;
} mp_reusable[MP_REUSABLE_CNT] = {0};


__attribute__((constructor))
void mp_reusable_init(void) {
	for (int i = 0; i < MP_REUSABLE_CNT; i++) {
		struct mp_reusable *r = &mp_reusable[i];
		r->head.next = r->head.prev = &r->head;
		r->chunk_size = mp_reusable_sizes[i] - MP_CHUNK_TAIL;
		if (r->chunk_size < CPU_PAGE_SIZE >> 1) {
			mp_insert_unused(&r->sep, &r->head);
			r->chunks_per_block = (CPU_PAGE_SIZE - MP_CHUNK_TAIL) / mp_reusable_sizes[i];
		} else {
			r->chunks_per_block = 1;
		}
	}
}

struct mp_reusable *mp_get_reusable(uint32_t *size) {
	for (int i = 0; i < MP_REUSABLE_CNT; i++) {
		if (*size <= mp_reusable[i].chunk_size) {
			*size = mp_reusable[i].chunk_size;
			return mp_reusable + i;
		}
	}
	return NULL;
}

static void *
mp_new_reusable_chunk(uint32_t requested_size, size_t pool_size) {
	struct mempool_chunk *chunk = NULL;
	uint32_t size = MAX(requested_size, MIN(pool_size >> 3, mp_reusable_sizes[MP_REUSABLE_CNT - 1] - MP_CHUNK_TAIL));
	struct mp_reusable *reusable = mp_get_reusable(&size);
	if (reusable) {
		struct mp_unused *unused = reusable->head.prev;
		if (unused == &reusable->sep) {
			unused = unused->prev;
		}
		if (unused->count > 0) {
			reusable->unused_cnt--;
			mp_remove_unused(unused);
			chunk = unused->chunk;
			unused->chunk = chunk->prev;
			if (--unused->count) {
				mp_insert_unused(unused, reusable->head.prev);
			}
			return chunk;
		} else if (reusable->chunks_per_block > 1) {
			unused = mp_new_small_chunks(size);
			chunk = unused->chunk;
			unused->chunk = chunk->prev;
			reusable->total_cnt += unused->count;
			unused->count--;
			reusable->unused_cnt += unused->count;
			mp_insert_unused(unused, reusable->head.prev);
			return chunk;
		} else {
			reusable->total_cnt++;
			// fall through
		}
	} else {
		size = mp_align_size(size);
	}
	return mp_new_chunk(size);
}

static void
mp_free_reusable_chunk(struct mempool_chunk *chunk) {
	uint32_t size = chunk->size;
	struct mp_reusable *reusable = mp_get_reusable(&chunk->size);
	if (reusable) {
		reusable->unused_cnt++;
		struct mp_unused *unused = chunk_to_unused(chunk);
		if (unused->count == 1) {
			mp_insert_unused(unused, reusable->head.prev);
		} else if (unused->count == reusable->chunks_per_block) {
			mp_remove_unused(unused);
			mp_insert_unused(unused, reusable->sep.prev);
		}
	} else {
		mp_free_chunk(chunk);
	}
}

static void
mp_balance_reusable(void) {
	// just free all unused chunks/blocks for now
	for (int i = 0; i < MP_REUSABLE_CNT; i++) {
		struct mp_unused *unused;
		while ((unused = mp_reusable[i].head.next)->count > 0) {
			mp_remove_unused(unused);
			mp_reusable[i].total_cnt  -= mp_reusable[i].chunks_per_block;
			mp_reusable[i].unused_cnt -= mp_reusable[i].chunks_per_block;
			if (mp_reusable[i].chunks_per_block > 1) {
				mp_free_small_chunks(unused);
			} else {
				mp_free_chunk(unused->chunk);
			}
		}
	}
}

#define CONFIG_UCW_POOL_ACTIVE_CHUNKS (ARRAY_SIZE(mp_reusable) + 1)
// ------


struct mempool *
mp_new(size_t chunk_size)
{
	chunk_size = MAX(sizeof(struct mempool), chunk_size);
	chunk_size = chunk_size < 2048 ? chunk_size : mp_align_size(chunk_size);
	struct mempool_chunk *chunk = mp_new_reusable_chunk(chunk_size, 0);
	struct mempool *pool = (void *)chunk - chunk->size;
	MEMCHECK_UNDEFINED(pool, sizeof(*pool));
	DBG("Creating mempool %p with %zu bytes long chunks", pool, chunk_size);
	chunk->prev = NULL;
#ifdef CONFIG_DEBUG
	chunk->pool = pool;
#endif
	chunk->free = chunk_size - sizeof(*pool);
	*pool = (struct mempool) {
		.last = chunk,
		.total_size = chunk->size + MP_CHUNK_TAIL,
		.chunk_size = chunk_size,
	};
	MEMCHECK_NOACCESS(chunk, MP_CHUNK_TAIL);
	return pool;
}

static void
mp_free_chain(struct mempool_chunk *chunk)
{
	while (chunk) {
		MEMCHECK_DEFINED(chunk, MP_CHUNK_TAIL);
		struct mempool_chunk *prev = chunk->prev;
		mp_free_reusable_chunk(chunk);
		chunk = prev;
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
	struct mempool_chunk *chunk = pool->last, *prev, *poolchunk = NULL;
	while (chunk) {
		MEMCHECK_DEFINED(chunk, MP_CHUNK_TAIL);
		prev = chunk->prev;
		if ((uint8_t *)chunk - chunk->size == (uint8_t *)pool) {
			poolchunk = chunk;
			chunk->prev = NULL;
		} else {
			mp_free_reusable_chunk(chunk);
		}
		chunk = prev;
	}
	if (poolchunk) {
		chunk = poolchunk;
		chunk->free = chunk->size - sizeof(*pool);
		MEMCHECK_NOACCESS((uint8_t *)chunk - chunk->size + sizeof(struct mempool),
				chunk->size - sizeof(struct mempool) + MP_CHUNK_TAIL);
	}
	pool->last = chunk;
	pool->total_size = chunk ? chunk->size + MP_CHUNK_TAIL : 0; // memcheck violation
}

static void
mp_stats_chain(struct mempool *pool, struct mempool_chunk *chunk, struct mempool_stats *stats)
{
	struct mempool_chunk *prev;
	while (chunk) {
		MEMCHECK_DEFINED(chunk, MP_CHUNK_TAIL);
		stats->total_size += chunk->size + MP_CHUNK_TAIL;
		stats->chunks_count++;
		stats->used_size += chunk->size - chunk->free;
		if ((uint8_t *)pool == (uint8_t *)chunk - chunk->size)
			stats->used_size -= sizeof(*pool);
		prev = chunk->prev;
		MEMCHECK_NOACCESS(chunk, MP_CHUNK_TAIL);
		chunk = prev;
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
	return pool->total_size;
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
			for (int i = 1; *(pchunk = &(*pchunk)->prev) && (i < CONFIG_UCW_POOL_ACTIVE_CHUNKS) ; i++) {
				MEMCHECK_DEFINED(*pchunk, MP_CHUNK_TAIL);
				size_t avail = (*pchunk)->free & ~(size_t)(CPU_STRUCT_ALIGN - 1);
				if (size <= avail) {
					struct mempool_chunk *chunk = *pchunk;
					chunk->free = avail - size;
					uint8_t *ptr = (uint8_t *)chunk - avail;

					// make pchunk the last one
					*pchunk = chunk->prev;
					chunk->prev = pool->last;
					pool->last = chunk;

					for (struct mempool_chunk *c = pool->last; MEMCHECK_ACTIVE && c != *pchunk; c = c->prev) {
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
			*pfullest = fullest->prev;
			fullest->prev = chunk;

			for (struct mempool_chunk *c = pool->last; MEMCHECK_ACTIVE && c != chunk; c = c->prev) {
				MEMCHECK_NOACCESS(c, MP_CHUNK_TAIL);
			}
		}

		// allocate a new chunk
		struct mempool_chunk *chunk = mp_new_reusable_chunk(size <= pool->chunk_size ? pool->chunk_size : mp_align_size(size), pool->total_size);
		if (!chunk) {
			return NULL;
		}
#ifdef CONFIG_DEBUG
		chunk->pool = pool;
#endif
		chunk->prev = pool->last;
		chunk->free = chunk->size - size;
		void *ptr = (uint8_t *)chunk - chunk->size;
		pool->last = chunk;
		pool->total_size += chunk->size + MP_CHUNK_TAIL;
		MEMCHECK_NOACCESS(chunk, MP_CHUNK_TAIL);
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
