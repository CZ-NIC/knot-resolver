/*
 *  UCW Library -- Memory Pools
 *
 *  (c) 1997--2015 Martin Mares <mj@ucw.cz>
 *  (c) 2007 Pavel Charvat <pchar@ucw.cz>
 *  (c) 2015, 2017, 2026 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  Source: https://www.ucw.cz/libucw/
 */

#ifndef _UCW_POOLS_H
#define _UCW_POOLS_H

#include <asan.h>
#include "lib/defines.h"
#include <ucw/config.h>
#include <ucw/lib.h>
#include <string.h>


/***
 * [[defs]]
 * Definitions
 * -----------
 ***/

/**
 * Memory pool state (see mp_push(), ...).
 * You should use this one as an opaque handle only, the insides are internal.
 **/
struct mempool_state {
	size_t free[2];
	void *last[2];
};

/**
 * Memory pool.
 * You should use this one as an opaque handle only, the insides are internal.
 **/
struct mempool {
	struct mempool_state state;
	void *unused, *last_big;
	size_t chunk_size, threshold;
	unsigned idx;
};

struct mempool_stats {          /** Mempool statistics. See mp_stats(). **/
	uint64_t total_size;            /** Real allocated size in bytes. */
	uint64_t used_size;             /** Estimated size allocated from mempool to application. */
	unsigned chain_count[3];        /** Number of allocated chunks in small/big/unused chains. */
	uint64_t chain_size[3];         /** Size of allocated chunks in small/big/unused chains. */
};

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
 * of chunks. This function scans the chunk list, so it can be slow.
 **/
uint64_t mp_total_size(struct mempool *pool);

/**
 * Release unused chunks of memory reserved for further allocation
 * requests, but stop if mp_total_size() would drop below \p min_total_size.
 **/
void mp_shrink(struct mempool *pool, uint64_t min_total_size);

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

/**
 * The same as \ref mp_alloc(), but the result may be unaligned.
 **/
void *mp_alloc_noalign(struct mempool *pool, size_t size);


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

static inline unsigned mp_idx(struct mempool *pool, void *ptr)
{
	return ptr == pool->last_big;
}

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
void *mp_start_noalign(struct mempool *pool, size_t size);

/**
 * Return start pointer of the growing buffer allocated by latest \ref mp_start() or a similar function.
 **/
static inline void *mp_ptr(struct mempool *pool)
{
	return (uint8_t *)pool->state.last[pool->idx] - pool->state.free[pool->idx];
}

/**
 * Return the number of bytes available for extending the growing buffer.
 * (Before a reallocation will be needed).
 **/
static inline size_t mp_avail(struct mempool *pool)
{
	return pool->state.free[pool->idx];
}

/**
 * Grow the buffer allocated by \ref mp_start() to be at least \p size bytes long
 * (\p size may be less than \ref mp_avail(), even zero). Reallocated buffer may
 * change its starting position. The content will be unchanged to the minimum
 * of the old and new sizes; newly allocated memory will be uninitialized.
 * Multiple calls to mp_grow() have amortized linear cost wrt. the maximum value of \p size. */
static inline void *mp_grow(struct mempool *pool, size_t size)
{
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
	return (((size_t)((uint8_t *)pool->state.last[pool->idx] - (uint8_t *)p) >= size) ? p : mp_spread_internal(pool, p, size));
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
	void *p = mp_ptr(pool);
	pool->state.free[pool->idx] = (uint8_t *)pool->state.last[pool->idx] - (uint8_t *)end;
	ASAN_POISON_MEMORY_REGION(end, pool->state.free[pool->idx]);
	return p;
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
	unsigned idx = mp_idx(pool, ptr);
	return ((uint8_t *)pool->state.last[idx] - (uint8_t *)ptr) - pool->state.free[idx];
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
     * variants of methods returning zeroed memory,
     * restoring previous state of allocations,
     * concatenating and duplicating memory/strings on mempools,
     * generic allocator interface spanning both malloc and mempools.
*/

#endif
