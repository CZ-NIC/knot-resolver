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

/* Design overview:
 *
 * A _mempool_ consists of mmapped chunks of different sizes.
 * We use _chunk_ to refer the mempool_chunk struct located after the data area of size chunk->size,
 * which contains data already allocated to the application followed by chunk->free bytes of available space.
 * Normal chunks of sizes 4K, 16K, 68K and greater are mmaped on their own,
 * small chunks of size 1K are allocated by whole pages consecutively containing four of them.
 *
 * When allocating memory to the application,
 * we seek sufficient space in several last chunks of the mempool and move the chosen one to the end of list,
 * or we add a new chunk while getting the lowest-free-space one out of our view.
 * The last allocation may be resized if needed.
 * The size of a new chunk is lower-bounded by wanted allocation size and mempool chunk_size
 * and becomes larger with increasing total size of the mempool.
 *
 * Unused chunks of sizes up to 68K from deleted pools are recycled globally.
 * They are pointed by the _unused_ structure mp_unused connected to lists containing same-sized chunks;
 * the structure is located either in the data area of normal chunks
 * or after the 4-tuple of small chunks representing all unused of them.
 *
 * During idle, unused chunks that were not used for at least 1 minute are munmapped.
 *
 *
 * MEMCHECK summary (ASan + Valgrind annotations):
 *
 * Memory regions are explicitely marked as
 *   * NOACCESS (locked, poisoned, inaccessible),
 *   * UNDEFINED (unlocked but uninitialized), or
 *   * DEFINED (unlocked and initialized).
 * ASan then disallows access to poisoned (NOACCESS) memory,
 * Valgrind also detects decisions based on uninitialized memory.
 *
 * Desired state outside of our code:
 *   * mempool structure is accessible,
 *   * within used chunks
 *      * user-allocated data are accessible,
 *      * free part of the data area is locked,
 *      * chunk (metadata) is locked,
 *   * within unused chunks
 *      * data area is locked except for the possibly contained unused structure,
 *      * chunk (metadata) is accessible,
 *      * unused structure is accessible,
 *   * other internal metadata are accessible.
 * During internal code execution the memory classification is being changed as needed
 * to access the internal structures but allow detection of user data overflow to our metadata;
 * also reused memory can be repeteadly handled as uninitialized this way.
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
#include <time.h>

#pragma GCC diagnostic ignored "-Wpointer-arith"

#define MP_SIZE_MAX (UINT32_MAX - MP_CHUNK_TAIL - CPU_PAGE_SIZE)

#define MP_REUSABLE_HOLD_TIME 60000
#define MP_REUSABLE_MIN_FREE_PERIOD 1000
#define MP_REUSABLE_MAX_CONSECUTIVE_FREES 250

static uint32_t get_stamp_default(void) {
	struct timespec ts = { 0 };
#ifdef CLOCK_MONOTONIC_COARSE
	clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);  // Linux-specific
#else
	clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static uint32_t (*get_stamp)(void) = get_stamp_default;

void mp_set_time(uint32_t (*get_stamp_cb)(void)) {
	get_stamp = get_stamp_cb;
}

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
	// MEMCHECK: pool defined
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
	// MEMCHECK: data locked, chunk unlocked
	return chunk;
}

static void
mp_free_chunk(struct mempool_chunk *chunk)
{
	// MEMCHECK: data unknown, chunk unlocked
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
	// MEMCHECK: chunk defined, unused defined iff small
	struct mp_unused *unused;
	if (chunk->size < CPU_PAGE_SIZE >> 1) {
		unused = (void *)((uintptr_t)(chunk) & (UINTPTR_MAX - CPU_PAGE_SIZE + 1)) + CPU_PAGE_SIZE - MP_UNUSED_TAIL;
	} else {
		unused = (void *)(chunk) - MP_UNUSED_TAIL;
		MEMCHECK_UNDEFINED(unused, MP_UNUSED_TAIL);
		memset(unused, 0, sizeof(*unused));
	}

	unused->count++;
	chunk->prev = unused->chunk;
	unused->chunk = chunk;
	unused->timestamp = get_stamp ? get_stamp() : 0;

	// MEMCHECK: chunk defined, unused defined
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
		MEMCHECK_NOACCESS(data, size);
		struct mempool_chunk *chunk = (struct mempool_chunk *)(data + size);
		chunk->size = size;
		chunk->prev = unused->chunk;
		unused->chunk = chunk;
		unused->count++;
		data += size + MP_CHUNK_TAIL;
	}
	// MEMCHECK: data locked, chunks defined, unused defined
	return unused;
}
static void mp_free_small_chunks(struct mp_unused *unused) {
	// MEMCHECK: data unknown, chunks defined, unused defined
	uint8_t *data = (uint8_t *)unused + MP_UNUSED_TAIL - CPU_PAGE_SIZE;
	MEMCHECK_UNDEFINED(data, CPU_PAGE_SIZE);
	page_free(data, CPU_PAGE_SIZE);
}
static inline void mp_insert_unused(struct mp_unused *item, struct mp_unused *after) {
	// MEMCHECK: all unused defined
	item->prev = after;
	item->next = after->next;
	after->next = item;
	item->next->prev = item;
}
static inline void mp_remove_unused(struct mp_unused *item) {
	// MEMCHECK: all unused defined
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
		// MEMCHECK: data locked excl. unused, chunks defined, unused defined
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
			MEMCHECK_NOACCESS((uint8_t *)chunk - chunk->size, chunk->size);
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
	// MEMCHECK: data locked, chunk defined
}

static void
mp_free_reusable_chunk(struct mempool_chunk *chunk) {
	// MEMCHECK: data unknown, chunk defined, unused defined if small
	uint32_t size = chunk->size;
	struct mp_reusable *reusable = mp_get_reusable(&chunk->size);
	if (reusable) {
		MEMCHECK_NOACCESS((uint8_t *)chunk - chunk->size, chunk->size);
		reusable->unused_cnt++;
		struct mp_unused *unused = chunk_to_unused(chunk);
		if (unused->count == 1) {
			mp_insert_unused(unused, reusable->head.prev);
		} else if (unused->count == reusable->chunks_per_block) {
			mp_remove_unused(unused);
			mp_insert_unused(unused, reusable->sep.prev);
		}
		// MEMCHECK: data locked, chunk defined, unused defined
	} else {
		char trace[150]; kr_log_get_shorttrace(trace);
		printf("FREE_REUSABLE: size orig %8u, new %8u   %s\n",
				size, chunk->size, trace);
		mp_free_chunk(chunk);
	}
}

uint64_t mp_balance_reusable(void)
{
	// MEMCHECK: all data locked, chunks defined, unused defined
	uint32_t now = get_stamp ? get_stamp() : 0;
	uint32_t longest_unused = 0;
	int max_frees = MP_REUSABLE_MAX_CONSECUTIVE_FREES;
	for (int i = 0; i < MP_REUSABLE_CNT; i++) {
		struct mp_unused *unused;
		while ((unused = mp_reusable[i].head.next)->count > 0) {
			if (get_stamp && (now - unused->timestamp < MP_REUSABLE_HOLD_TIME)) {
				longest_unused = MAX(longest_unused, now - unused->timestamp);
				break;
			}
			if (max_frees-- <= 0) return 0;
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

	// temporary logging
	static uint32_t log_ts = 0;
	if (now - log_ts >= 60000) {
		log_ts = now;
		mp_log_global_stats();
	}

	return MAX(MP_REUSABLE_HOLD_TIME - longest_unused, MP_REUSABLE_MIN_FREE_PERIOD);
}

#define CONFIG_UCW_POOL_ACTIVE_CHUNKS (ARRAY_SIZE(mp_reusable) + 1)
// ------

void log_pool_stats(struct mempool *pool)
{
	// MEMCHECK: pool defined, pool chunks locked, data unknown
	int counts[MP_REUSABLE_CNT + 1] = { 0 };
	int count = 0;
	size_t free = 0, total = 0;
	for (struct mempool_chunk *chunk = pool->last; chunk; ) {
		MEMCHECK_DEFINED(chunk, MP_CHUNK_TAIL);
		free += chunk->free;
		total += chunk->size;  // excl. chunk metadata
		count++;
		int size_index = MP_REUSABLE_CNT;
		for (int i = 0; i < MP_REUSABLE_CNT; i++) {
			if (chunk->size == mp_reusable[i].chunk_size) {
				size_index = i;
				break;
			}
		}
		counts[size_index]++;

		struct mempool_chunk *prev = chunk->prev;
		MEMCHECK_NOACCESS(chunk, MP_CHUNK_TAIL);
		chunk = prev;
	}

	char *log_reason = NULL;
	if ((float)free / total > 0.5) log_reason = "UNDERFULL_POOL";
	if (count > 18) log_reason = "OVERCOUNT_POOL";
	if (counts[MP_REUSABLE_CNT] > 0) log_reason = "NOT-FULLY-REUSED_POOL";

	if (log_reason) {
		char trace[150]; kr_log_get_shorttrace(trace);
		printf("%21s: counts", log_reason);
		for (int i = 0; i < MP_REUSABLE_CNT + 1; i++) {
			printf(" %2d", counts[i]);
		}
		printf(", util %5.1f %%, %s\n", (float)(total - free) / total * 100, trace);
	}
}

void mp_log_global_stats(void)
{
	printf("MEMPOOL_STATS: ");
	for (int i = 0; i < MP_REUSABLE_CNT; i++) {
		printf("%5zu/%-5zu ", mp_reusable[i].total_cnt - mp_reusable[i].unused_cnt, mp_reusable[i].total_cnt);
	}
	printf("\n");
}

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
	// MEMCHECK: pool defined, other data locked, chunk locked
}

static void
mp_free_chain(struct mempool_chunk *chunk)
{
	// MEMCHECK: pool chunks locked, data unknown
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
	// MEMCHECK: pool defined, pool chunks locked, data unknown
	if (pool == NULL) {
		return;
	}
	// log_pool_stats(pool);
	DBG("Deleting mempool %p", pool);
	mp_free_chain(pool->last); // can contain the mempool structure
}

void
mp_flush(struct mempool *pool)
{
	// MEMCHECK: pool defined, pool chunks locked, data unknown
	// log_pool_stats(pool);
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
	pool->total_size = 0;
	if (poolchunk) {
		chunk = poolchunk;
		chunk->free = chunk->size - sizeof(*pool);
		pool->total_size = chunk->size + MP_CHUNK_TAIL;
		MEMCHECK_NOACCESS((uint8_t *)chunk - chunk->size + sizeof(struct mempool),
				chunk->size - sizeof(struct mempool) + MP_CHUNK_TAIL);
	}
	pool->last = chunk;
	// MEMCHECK: pool defined, pool chunks locked, data except pool locked
}

static void
mp_stats_chain(struct mempool *pool, struct mempool_chunk *chunk, struct mempool_stats *stats)
{
	// MEMCHECK: pool defined, pool chunks locked
	while (chunk) {
		MEMCHECK_DEFINED(chunk, MP_CHUNK_TAIL);
		stats->total_size += chunk->size + MP_CHUNK_TAIL;
		stats->chunks_count++;
		stats->used_size += chunk->size - chunk->free;
		if ((uint8_t *)pool == (uint8_t *)chunk - chunk->size)
			stats->used_size -= sizeof(*pool);

		struct mempool_chunk *prev = chunk->prev;
		MEMCHECK_NOACCESS(chunk, MP_CHUNK_TAIL);
		chunk = prev;
	}
}

void
mp_stats(struct mempool *pool, struct mempool_stats *stats)
{
	// MEMCHECK: pool defined, pool chunks locked
	bzero(stats, sizeof(*stats));
	mp_stats_chain(pool, pool->last, stats);
	assert(stats->used_size <= stats->total_size);
}

size_t
mp_total_size(struct mempool *pool)
{
	// MEMCHECK: pool defined
	return pool->total_size;
}

static void *
mp_alloc_internal(struct mempool *pool, size_t size)
{
	// MEMCHECK: pool defined, pool chunks locked
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

					chunk = *pchunk;
					for (struct mempool_chunk *c = pool->last; MEMCHECK_ACTIVE && c != chunk; ) {
						struct mempool_chunk *prev = c->prev;
						MEMCHECK_NOACCESS(c, MP_CHUNK_TAIL);
						c = prev;
					}
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

			for (struct mempool_chunk *c = pool->last; MEMCHECK_ACTIVE && c != chunk; ) {
				struct mempool_chunk *prev = c->prev;
				MEMCHECK_NOACCESS(c, MP_CHUNK_TAIL);
				c = prev;
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
	// MEMCHECK: pool defined, pool chunks locked, alloc'd data still locked, further data locked
}

void *
mp_alloc(struct mempool *pool, size_t size)
{
	// MEMCHECK: pool defined, pool chunks locked, free data region locked
	void *ptr = NULL;
	if (pool->last) {
		MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
		size_t avail = pool->last->free & ~(size_t)(CPU_STRUCT_ALIGN - 1);
		if (size <= avail) {
			pool->last->free = avail - size;
			ptr = (uint8_t *)pool->last - avail;
		}
		MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
	}
	if (!ptr) {
		ptr = mp_alloc_internal(pool, size);
	}
	if (ptr) MEMCHECK_UNDEFINED(ptr, size);
	return ptr;
	// MEMCHECK: pool defined, pool chunks locked, alloc'd data undefined
}

static void *
mp_start_internal(struct mempool *pool, size_t size)
{
	// MEMCHECK: pool defined, pool chunks locked
	void *ptr = mp_alloc_internal(pool, size);
	if (!ptr)
		return NULL;
	MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
	pool->last->free += size;
	MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
	return ptr;
	// MEMCHECK: pool defined, pool chunks locked, alloc'd data still locked
}

void *
mp_start(struct mempool *pool, size_t size)
{
	// MEMCHECK: pool defined, pool chunks locked, free data region locked
	void *ptr = NULL;
	if (pool->last) {
		MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
		size_t avail = pool->last->free & ~(size_t)(CPU_STRUCT_ALIGN - 1);
		if (size <= avail) {
			pool->last->free = avail;
			ptr = (uint8_t *)pool->last - avail;
		}
		MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
	}
	if (!ptr) {
		ptr = mp_start_internal(pool, size);
	}
	if (ptr) {
		MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
		MEMCHECK_UNDEFINED(ptr, pool->last->free);
		MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
	}
	return ptr;
	// MEMCHECK: pool defined, pool chunks locked, free data undefined
}

void *
mp_grow_internal(struct mempool *pool, size_t size)
{
	// MEMCHECK: pool defined, pool chunks locked, free data unlocked
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
	// MEMCHECK: pool defined, pool chunks locked, free data unlocked, previous free data locked
}

size_t
mp_open(struct mempool *pool, void *ptr)
{
	// MEMCHECK: pool defined, pool chunks locked, free data locked
	MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
	size_t size = ((uint8_t *)pool->last - (uint8_t *)ptr) - pool->last->free;
	MEMCHECK_UNDEFINED(ptr + size, pool->last->free);
	pool->last->free += size;
	MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
	return size;
	// MEMCHECK: pool defined, pool chunks locked, free data unlocked
}

void *
mp_realloc(struct mempool *pool, void *ptr, size_t size)
{
	// MEMCHECK: pool defined, pool chunks locked, free data locked
	mp_open(pool, ptr);
	ptr = mp_grow(pool, size);
	mp_end(pool, (uint8_t *)ptr + size);
	return ptr;
	// MEMCHECK: pool defined, pool chunks locked, free data locked
}

void *
mp_spread_internal(struct mempool *pool, void *p, size_t size)
{
	// MEMCHECK: pool defined, pool chunks locked, free data unlocked
	void *old = mp_ptr(pool);
	void *new = mp_grow_internal(pool, p-old+size);
	if (!new) {
		return NULL;
	}
	return p-old+new;
	// MEMCHECK: pool defined, pool chunks locked, free data unlocked, previous free data locked
}
