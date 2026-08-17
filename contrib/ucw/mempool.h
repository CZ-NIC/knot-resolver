/*
 *  UCW Library -- Memory Pools (One-Time Allocation)
 *
 *  (c) 1997--2015 Martin Mares <mj@ucw.cz>
 *  (c) 2007 Pavel Charvat <pchar@ucw.cz>
 *  (c) 2015, 2017, 2026 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  Source: https://www.ucw.cz/libucw/
 */

#pragma once

#include <memcheck.h>
#include "lib/defines.h"
#include <ucw/config.h>
#include <ucw/lib.h>
#include <string.h>
#include <stdint.h>

#include <lib/log.h>


/***
 * [[defs]]
 * Definitions
 * -----------
 ***/

struct mempool_chunk {
	struct mempool_chunk *prev;
	uint32_t size;
	uint32_t free;
#ifdef CONFIG_DEBUG
	struct mempool *pool;         // Can be useful when analysing coredump for memory leaks
#endif
};
#define MP_CHUNK_TAIL ALIGN_TO(sizeof(struct mempool_chunk), CPU_STRUCT_ALIGN)

/**
 * Memory pool.
 * You should use this one as an opaque handle only, the insides are internal.
 **/
struct mempool {
	struct mempool_chunk *last;
	size_t chunk_size;
	size_t total_size;
};

struct mempool_stats {          /** Mempool statistics. See mp_stats(). **/
	size_t total_size;          /** Real allocated size in bytes. */
	size_t used_size;           /** Size allocated from mempool to application. */
	unsigned chunks_count;      /** Number of allocated chunks. */
};

// #define MP_DEBUG_CONSISTENCY_CHECKS  // slow
#ifdef MP_DEBUG_CONSISTENCY_CHECKS
#define MP_CHUNK_CHECK(c) MP_CHUNK_CHECKi(c, 0)
#define MP_CHUNK_CHECKi(c, i) \
	if ((c->free > c->size) || (c->size > (1 << 23))) { \
		char trace[150]; kr_log_get_shorttrace(trace); \
		printf("BUG: chunk %p (%d-th), size %d, free %d   %s\n", (void *)c, i, c->size, c->free, trace); \
	}
#define MP_POOL_CHECK(pool) \
{ \
	struct mempool_chunk *c = pool->last; \
	for (int ci = 0; c && (ci < 6); ci++) { \
		MEMCHECK_DEFINED(c, MP_CHUNK_TAIL); \
		MP_CHUNK_CHECKi(c, ci); \
		c = c->prev; \
		MEMCHECK_NOACCESS(c, MP_CHUNK_TAIL); \
	} \
}
#else
#define MP_CHUNK_CHECK(c)
#define MP_POOL_CHECK(c)
#endif

/***
 * [[basic]]
 * Basic manipulation
 * ------------------
 ***/

/**
 * Initialize a given mempool structure.
 * \p chunk_size must be in the interval `[1, SIZE_MAX / 2]`.
 * It will allocate memory by this large chunks and take
 * memory to satisfy requests from them.
 *
 * Memory pools can be treated as <<trans:respools,resources>>, see <<trans:res_mempool()>>.
 **/
KR_EXPORT
void mp_init(struct mempool *pool, size_t chunk_size);

/**
 * Allocate and initialize a new memory pool.
 * See \ref mp_init() for \p chunk_size limitations.
 *
 * The new mempool structure is allocated on the new mempool.
 *
 * Memory pools can be treated as <<trans:respools,resources>>, see <<trans:res_mempool()>>.
 **/
KR_EXPORT
struct mempool *mp_new(size_t chunk_size);

/**
 * Cleanup mempool initialized by mp_init or mp_new.
 * Frees all the memory allocated by this mempool and,
 * if created by \ref mp_new(), the \p pool itself.
 **/
KR_EXPORT
void mp_delete(struct mempool *pool);

/**
 * Frees all data on a memory pool, but leaves it working.
 * It can keep some of the chunks allocated to serve
 * further allocation requests. Leaves the \p pool alive,
 * even if it was created with \ref mp_new().
 **/
KR_EXPORT
void mp_flush(struct mempool *pool);

/**
 * Compute some statistics for debug purposes.
 * See the definition of the <<struct_mempool_stats,mempool_stats structure>>.
 * This function scans the chunk list, so it can be slow.
 **/
void mp_stats(struct mempool *pool, struct mempool_stats *stats);

/**
 * Return how many bytes were allocated by the pool, including unused parts
 * of chunks. This function is constant-time.
 **/
size_t mp_total_size(struct mempool *pool);

KR_EXPORT
void mp_log_global_stats(void);

/**
 * Free memory which was unused for a certain time period.
 * After it is called for the first time, it has to be called periodically for freeing memory.
 * Returns time delay in msec in which it may be called again;
 * ideally, call it sometime after that time during idle.
 * It may yield (and return 0) before freeing is fully completed,
 * not to block for too long.
 *
 * Before calling this function for the first time,
 * balancing is performed during some other mempool operations.
 * If you however don't use mempools for a long time after a memory intensive operation,
 * the unused memory stays allocated; calling this function is thus recommended.
 *
 * If MEMPOOL_IS_THREAD_SAFE is defined in C file,
 * reusing chunks is thread_local as well as the effects of this function.
 * The balancing during other operations is then disabled only in threads
 * where this function was called.
 */
KR_EXPORT
uint64_t mp_balance_reusable(void);

/**
 * Set function returning current time in msec (but precision of secs is also OK)
 * instead of the default clock_gettime, which might be slow.
 * Call it before using mempools to keep internal timestamps consistent.
 * The function is set globally for all threads.
 */
void mp_set_time(uint32_t (*get_stamp_cb)(void));

/***
 * [[alloc]]
 * Allocation routines
 * -------------------
 ***/

/**
 * The function allocates new \p size bytes on a given memory pool.
 * If the \p size is zero, the resulting pointer is undefined,
 * but it may be safely reallocated or used as the parameter
 * to other functions below.
 *
 * The resulting pointer is always aligned to a multiple of
 * `CPU_STRUCT_ALIGN` bytes and this condition remains true also
 * after future reallocations.
 **/
KR_EXPORT
void *mp_alloc(struct mempool *pool, size_t size);

/***
 * [[gbuf]]
 * Growing buffers
 * ---------------
 *
 * You do not need to know, how a buffer will need to be large,
 * you can grow it incrementally to needed size. You can grow only
 * one buffer at a time on a given mempool.
 *
 * Similar functionality is provided by <<growbuf:,growing buffers>> module.
 ***/

/* For internal use only, do not call directly */
void *mp_grow_internal(struct mempool *pool, size_t size);
void *mp_spread_internal(struct mempool *pool, void *p, size_t size);

/**
 * Open a new growing buffer (at least \p size bytes long).
 * If the \p size is zero, the resulting pointer is undefined,
 * but it may be safely reallocated or used as the parameter
 * to other functions below.
 *
 * The resulting pointer is always aligned to a multiple of
 * `CPU_STRUCT_ALIGN` bytes and this condition remains true also
 * after future reallocations. There is an unaligned version as well.
 *
 * Keep in mind that you can't make any other pool allocations
 * before you "close" the growing buffer with \ref mp_end().
 */
void *mp_start(struct mempool *pool, size_t size);

/**
 * Return start pointer of the growing buffer allocated by latest \ref mp_start() or a similar function.
 **/
static inline void *mp_ptr(struct mempool *pool)
{
	// MEMCHECK: pool defined, pool chunks locked, free data unlocked
	MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
	void *ptr = (uint8_t *)pool->last - pool->last->free;
	MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
	return ptr;
}

/**
 * Return the number of bytes available for extending the growing buffer.
 * (Before a reallocation will be needed).
 **/
static inline size_t mp_avail(struct mempool *pool)
{
	// MEMCHECK: pool defined, pool chunks locked, free data unlocked
	MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
	const size_t avail = pool->last->free;
	MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
	return avail;
}

/**
 * Grow the buffer allocated by \ref mp_start() to be at least \p size bytes long
 * (\p size may be less than \ref mp_avail(), even zero). Reallocated buffer may
 * change its starting position. The content will be unchanged to the minimum
 * of the old and new sizes; newly allocated memory will be uninitialized.
 * Multiple calls to mp_grow() have amortized linear cost wrt. the maximum value of \p size. */
static inline void *mp_grow(struct mempool *pool, size_t size)
{
	// MEMCHECK: pool defined, pool chunks locked, free data unlocked
	return (size <= mp_avail(pool)) ? mp_ptr(pool) : mp_grow_internal(pool, size);
}

/**
 * Grow the buffer by at least one byte -- equivalent to <<mp_grow(),`mp_grow`>>`(pool, mp_avail(pool) + 1)`.
 **/
static inline void *mp_expand(struct mempool *pool)
{
	return mp_grow_internal(pool, mp_avail(pool) + 1);
}

/**
 * Ensure that there is at least \p size bytes free after \p p,
 * if not, reallocate and adjust \p p.
 **/
static inline void *mp_spread(struct mempool *pool, void *p, size_t size)
{
	// MEMCHECK: pool defined, pool chunks locked, free data unlocked
	return (((size_t)((uint8_t *)pool->last - (uint8_t *)p) >= size) ? p : mp_spread_internal(pool, p, size));
}

/**
 * Append a character to the growing buffer. Called with \p p pointing after
 * the last byte in the buffer, returns a pointer after the last byte
 * of the new (possibly reallocated) buffer.
 **/
static inline char *mp_append_char(struct mempool *pool, char *p, unsigned c)
{
	p = (char *)mp_spread(pool, p, 1);
	*p++ = c;
	return p;
}

/**
 * Append a memory block to the growing buffer. Called with \p p pointing after
 * the last byte in the buffer, returns a pointer after the last byte
 * of the new (possibly reallocated) buffer.
 **/
static inline void *mp_append_block(struct mempool *pool, void *p, const void *block, size_t size)
{
	char *q = (char *)mp_spread(pool, p, size);
	memcpy(q, block, size);
	return q + size;
}

/**
 * Append a string to the growing buffer. Called with \p p pointing after
 * the last byte in the buffer, returns a pointer after the last byte
 * of the new (possibly reallocated) buffer.
 **/
static inline void *mp_append_string(struct mempool *pool, void *p, const char *str)
{
	return mp_append_block(pool, p, str, strlen(str));
}

/**
 * Close the growing buffer. The \p end must point just behind the data, you want to keep
 * allocated (so it can be in the interval `[mp_ptr(pool), mp_ptr(pool) + mp_avail(pool)]`).
 * Returns a pointer to the beginning of the just closed block.
 **/
static inline void *mp_end(struct mempool *pool, void *end)
{
	// MEMCHECK: pool defined, pool chunks locked, free data unlocked
	MP_POOL_CHECK(pool);
	void *p = mp_ptr(pool);
	MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
	const size_t avail = (uint8_t *)pool->last - (uint8_t *)end;
	if (avail > pool->last->free) {
		char trace[150]; kr_log_get_shorttrace(trace);
		printf("BUG_MP_END: chunk %p, free %d, end %p, new free %ld   %s\n",
				(void *)pool->last, pool->last->free, end, avail, trace);
	}
	pool->last->free = avail;
	MEMCHECK_NOACCESS(end, pool->last->free + MP_CHUNK_TAIL);
	MP_POOL_CHECK(pool);
	return p;
	// MEMCHECK: pool defined, pool chunks locked, free data locked
}

/**
 * Close the growing buffer as a string. That is, append a zero byte and call mp_end().
 **/
static inline char *mp_end_string(struct mempool *pool, void *end)
{
	end = mp_append_char(pool, (char *)end, 0);
	return (char *)mp_end(pool, end);
}

/**
 * Return size in bytes of the last allocated memory block (with \ref mp_alloc() or \ref mp_end()).
 **/
static inline size_t mp_size(struct mempool *pool, void *ptr)
{
	// MEMCHECK: pool defined, pool chunks locked
	MEMCHECK_DEFINED(pool->last, MP_CHUNK_TAIL);
	const size_t size = ((uint8_t *)pool->last - (uint8_t *)ptr) - pool->last->free;
	MEMCHECK_NOACCESS(pool->last, MP_CHUNK_TAIL);
	return size;
}

/**
 * Open the last memory block (allocated with \ref mp_alloc() or \ref mp_end())
 * for growing and return its size in bytes. The contents and the start pointer
 * remain unchanged. Do not forget to call \ref mp_end() to close it.
 **/
size_t mp_open(struct mempool *pool, void *ptr);

/**
 * Reallocate the last memory block (allocated with \ref mp_alloc() or \ref mp_end())
 * to the new \p size. Behavior is similar to \ref mp_grow(), but the resulting
 * block is closed.
 **/
void *mp_realloc(struct mempool *pool, void *ptr, size_t size);

/***
 * [[format]]
 * Formatted output
 * ---------------
 ***/

/**
 * printf() into a in-memory string, allocated on the memory pool.
 **/
KR_EXPORT
char *mp_printf(struct mempool *mp, const char *fmt, ...) FORMAT_CHECK(printf,2,3) LIKE_MALLOC;
/**
 * Like \ref mp_printf(), but uses `va_list` for parameters.
 **/
char *mp_vprintf(struct mempool *mp, const char *fmt, va_list args) LIKE_MALLOC;
/**
 * Like \ref mp_printf(), but it appends the data at the end of string
 * pointed to by \p ptr. The string is \ref mp_open()ed, so you have to
 * provide something that can be.
 *
 * Returns pointer to the beginning of the string (the pointer may have
 * changed due to reallocation).
 *
 * In some versions of LibUCW, this function was called mp_append_printf(). However,
 * this name turned out to be confusing -- unlike other appending functions, this one is
 * not called on an opened growing buffer. The old name will be preserved for backward
 * compatibility for the time being.
 **/
KR_EXPORT
char *mp_printf_append(struct mempool *mp, char *ptr, const char *fmt, ...) FORMAT_CHECK(printf,3,4);
#define mp_append_printf mp_printf_append
/**
 * Like \ref mp_printf_append(), but uses `va_list` for parameters.
 *
 * In some versions of LibUCW, this function was called mp_append_vprintf(). However,
 * this name turned out to be confusing -- unlike other appending functions, this one is
 * not called on an opened growing buffer. The old name will be preserved for backward
 * compatibility for the time being.
 **/
char *mp_vprintf_append(struct mempool *mp, char *ptr, const char *fmt, va_list args);
#define mp_append_vprintf mp_vprintf_append

/*
 * Some parts of mempools were removed in Knot projects,
 * see upstream if you need:
     * variants of methods returning zeroed memory and/or unaligned memory,
     * restoring previous state of allocations (no more compatible with our version of mempools),
     * concatenating and duplicating memory/strings on mempools,
     * generic allocator interface spanning both malloc and mempools.
*/
