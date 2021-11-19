/*
 *	UCW Library -- Memory Pools
 *
 *	(c) 1997--2015 Martin Mares <mj@ucw.cz>
 *	(c) 2007 Pavel Charvat <pchar@ucw.cz>
 *	SPDX-License-Identifier: LGPL-2.1-or-later
 *	Source: https://www.ucw.cz/libucw/
 */

#ifndef _UCW_POOLS_H
#define _UCW_POOLS_H

#include "lib/defines.h"
#include <ucw/alloc.h>
#include <ucw/config.h>
#include <ucw/lib.h>
#include <string.h>

#ifdef CONFIG_UCW_CLEAN_ABI
#define mp_alloc ucw_mp_alloc
#define mp_alloc_internal ucw_mp_alloc_internal
#define mp_alloc_noalign ucw_mp_alloc_noalign
#define mp_alloc_zero ucw_mp_alloc_zero
#define mp_delete ucw_mp_delete
#define mp_flush ucw_mp_flush
#define mp_grow_internal ucw_mp_grow_internal
#define mp_init ucw_mp_init
#define mp_memdup ucw_mp_memdup
#define mp_multicat ucw_mp_multicat
#define mp_new ucw_mp_new
#define mp_open ucw_mp_open
#define mp_pop ucw_mp_pop
#define mp_printf ucw_mp_printf
#define mp_printf_append ucw_mp_printf_append
#define mp_push ucw_mp_push
#define mp_realloc ucw_mp_realloc
#define mp_realloc_zero ucw_mp_realloc_zero
#define mp_restore ucw_mp_restore
#define mp_shrink ucw_mp_shrink
#define mp_spread_internal ucw_mp_spread_internal
#define mp_start ucw_mp_start
#define mp_start_internal ucw_mp_start_internal
#define mp_start_noalign ucw_mp_start_noalign
#define mp_stats ucw_mp_stats
#define mp_str_from_mem ucw_mp_str_from_mem
#define mp_strdup ucw_mp_strdup
#define mp_strjoin ucw_mp_strjoin
#define mp_total_size ucw_mp_total_size
#define mp_vprintf ucw_mp_vprintf
#define mp_vprintf_append ucw_mp_vprintf_append
#endif

/***
 * [[defs]]
 * Definitions
 * -----------
 ***/

/**
 * Memory pool state (see @mp_push(), ...).
 * You should use this one as an opaque handle only, the insides are internal.
 **/
struct mempool_state {
  size_t free[2];
  void *last[2];
  struct mempool_state *next;
};

/**
 * Memory pool.
 * You should use this one as an opaque handle only, the insides are internal.
 **/
struct mempool {
  struct ucw_allocator allocator;	// This must be the first element
  struct mempool_state state;
  void *unused, *last_big;
  size_t chunk_size, threshold;
  uint idx;
  u64 total_size;
};

struct mempool_stats {			/** Mempool statistics. See @mp_stats(). **/
  u64 total_size;			/* Real allocated size in bytes */
  u64 used_size;			/* Estimated size allocated from mempool to application */
  uint chain_count[3];			/* Number of allocated chunks in small/big/unused chains */
  u64 chain_size[3];			/* Size of allocated chunks in small/big/unused chains */
};

/***
 * [[basic]]
 * Basic manipulation
 * ------------------
 ***/

/**
 * Initialize a given mempool structure.
 * @chunk_size must be in the interval `[1, SIZE_MAX / 2]`.
 * It will allocate memory by this large chunks and take
 * memory to satisfy requests from them.
 *
 * Memory pools can be treated as <<trans:respools,resources>>, see <<trans:res_mempool()>>.
 **/
KR_EXPORT
void mp_init(struct mempool *pool, size_t chunk_size);

/**
 * Allocate and initialize a new memory pool.
 * See @mp_init() for @chunk_size limitations.
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
 * if created by @mp_new(), the @pool itself.
 **/
KR_EXPORT
void mp_delete(struct mempool *pool);

/**
 * Frees all data on a memory pool, but leaves it working.
 * It can keep some of the chunks allocated to serve
 * further allocation requests. Leaves the @pool alive,
 * even if it was created with @mp_new().
 **/
KR_EXPORT
void mp_flush(struct mempool *pool);

/**
 * Compute some statistics for debug purposes.
 * See the definition of the <<struct_mempool_stats,mempool_stats structure>>.
 * This function scans the chunk list, so it can be slow. If you are interested
 * in total memory consumption only, mp_total_size() is faster.
 **/
void mp_stats(struct mempool *pool, struct mempool_stats *stats);

/**
 * Return how many bytes were allocated by the pool, including unused parts
 * of chunks. This function runs in constant time.
 **/
u64 mp_total_size(struct mempool *pool);

/**
 * Release unused chunks of memory reserved for further allocation
 * requests, but stop if mp_total_size() would drop below @min_total_size.
 **/
void mp_shrink(struct mempool *pool, u64 min_total_size);

/***
 * [[alloc]]
 * Allocation routines
 * -------------------
 ***/

/* For internal use only, do not call directly */
void *mp_alloc_internal(struct mempool *pool, size_t size) LIKE_MALLOC;

/**
 * The function allocates new @size bytes on a given memory pool.
 * If the @size is zero, the resulting pointer is undefined,
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
 * The same as @mp_alloc(), but the result may be unaligned.
 **/
void *mp_alloc_noalign(struct mempool *pool, size_t size);

/**
 * The same as @mp_alloc(), but fills the newly allocated memory with zeroes.
 **/
void *mp_alloc_zero(struct mempool *pool, size_t size);

/**
 * Inlined version of @mp_alloc().
 **/
static inline void *mp_alloc_fast(struct mempool *pool, size_t size)
{
  size_t avail = pool->state.free[0] & ~(size_t)(CPU_STRUCT_ALIGN - 1);
  if (size <= avail)
    {
      pool->state.free[0] = avail - size;
      return (byte *)pool->state.last[0] - avail;
    }
  else
    return mp_alloc_internal(pool, size);
}

/**
 * Inlined version of @mp_alloc_noalign().
 **/
static inline void *mp_alloc_fast_noalign(struct mempool *pool, size_t size)
{
  if (size <= pool->state.free[0])
    {
      void *ptr = (byte *)pool->state.last[0] - pool->state.free[0];
      pool->state.free[0] -= size;
      return ptr;
    }
  else
    return mp_alloc_internal(pool, size);
}

/**
 * Return a generic allocator representing the given mempool.
 **/
static inline struct ucw_allocator *mp_get_allocator(struct mempool *mp)
{
  return &mp->allocator;
}

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
void *mp_start_internal(struct mempool *pool, size_t size) LIKE_MALLOC;
void *mp_grow_internal(struct mempool *pool, size_t size);
void *mp_spread_internal(struct mempool *pool, void *p, size_t size);

static inline uint mp_idx(struct mempool *pool, void *ptr)
{
  return ptr == pool->last_big;
}

/**
 * Open a new growing buffer (at least @size bytes long).
 * If the @size is zero, the resulting pointer is undefined,
 * but it may be safely reallocated or used as the parameter
 * to other functions below.
 *
 * The resulting pointer is always aligned to a multiple of
 * `CPU_STRUCT_ALIGN` bytes and this condition remains true also
 * after future reallocations. There is an unaligned version as well.
 *
 * Keep in mind that you can't make any other pool allocations
 * before you "close" the growing buffer with @mp_end().
 */
void *mp_start(struct mempool *pool, size_t size);
void *mp_start_noalign(struct mempool *pool, size_t size);

/**
 * Inlined version of @mp_start().
 **/
static inline void *mp_start_fast(struct mempool *pool, size_t size)
{
  size_t avail = pool->state.free[0] & ~(size_t)(CPU_STRUCT_ALIGN - 1);
  if (size <= avail)
    {
      pool->idx = 0;
      pool->state.free[0] = avail;
      return (byte *)pool->state.last[0] - avail;
    }
  else
    return mp_start_internal(pool, size);
}

/**
 * Inlined version of @mp_start_noalign().
 **/
static inline void *mp_start_fast_noalign(struct mempool *pool, size_t size)
{
  if (size <= pool->state.free[0])
    {
      pool->idx = 0;
      return (byte *)pool->state.last[0] - pool->state.free[0];
    }
  else
    return mp_start_internal(pool, size);
}

/**
 * Return start pointer of the growing buffer allocated by latest @mp_start() or a similar function.
 **/
static inline void *mp_ptr(struct mempool *pool)
{
  return (byte *)pool->state.last[pool->idx] - pool->state.free[pool->idx];
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
 * Grow the buffer allocated by @mp_start() to be at least @size bytes long
 * (@size may be less than @mp_avail(), even zero). Reallocated buffer may
 * change its starting position. The content will be unchanged to the minimum
 * of the old and new sizes; newly allocated memory will be uninitialized.
 * Multiple calls to mp_grow() have amortized linear cost wrt. the maximum value of @size. */
static inline void *mp_grow(struct mempool *pool, size_t size)
{
  return (size <= mp_avail(pool)) ? mp_ptr(pool) : mp_grow_internal(pool, size);
}

/**
 * Grow the buffer by at least one byte -- equivalent to <<mp_grow(),`mp_grow`>>`(@pool, @mp_avail(pool) + 1)`.
 **/
static inline void *mp_expand(struct mempool *pool)
{
  return mp_grow_internal(pool, mp_avail(pool) + 1);
}

/**
 * Ensure that there is at least @size bytes free after @p,
 * if not, reallocate and adjust @p.
 **/
static inline void *mp_spread(struct mempool *pool, void *p, size_t size)
{
  return (((size_t)((byte *)pool->state.last[pool->idx] - (byte *)p) >= size) ? p : mp_spread_internal(pool, p, size));
}

/**
 * Append a character to the growing buffer. Called with @p pointing after
 * the last byte in the buffer, returns a pointer after the last byte
 * of the new (possibly reallocated) buffer.
 **/
static inline char *mp_append_char(struct mempool *pool, char *p, uint c)
{
  p = mp_spread(pool, p, 1);
  *p++ = c;
  return p;
}

/**
 * Append a memory block to the growing buffer. Called with @p pointing after
 * the last byte in the buffer, returns a pointer after the last byte
 * of the new (possibly reallocated) buffer.
 **/
static inline void *mp_append_block(struct mempool *pool, void *p, const void *block, size_t size)
{
  char *q = mp_spread(pool, p, size);
  memcpy(q, block, size);
  return q + size;
}

/**
 * Append a string to the growing buffer. Called with @p pointing after
 * the last byte in the buffer, returns a pointer after the last byte
 * of the new (possibly reallocated) buffer.
 **/
static inline void *mp_append_string(struct mempool *pool, void *p, const char *str)
{
  return mp_append_block(pool, p, str, strlen(str));
}

/**
 * Close the growing buffer. The @end must point just behind the data, you want to keep
 * allocated (so it can be in the interval `[@mp_ptr(@pool), @mp_ptr(@pool) + @mp_avail(@pool)]`).
 * Returns a pointer to the beginning of the just closed block.
 **/
static inline void *mp_end(struct mempool *pool, void *end)
{
  void *p = mp_ptr(pool);
  pool->state.free[pool->idx] = (byte *)pool->state.last[pool->idx] - (byte *)end;
  return p;
}

/**
 * Close the growing buffer as a string. That is, append a zero byte and call mp_end().
 **/
static inline char *mp_end_string(struct mempool *pool, void *end)
{
  end = mp_append_char(pool, end, 0);
  return mp_end(pool, end);
}

/**
 * Return size in bytes of the last allocated memory block (with @mp_alloc() or @mp_end()).
 **/
static inline size_t mp_size(struct mempool *pool, void *ptr)
{
  uint idx = mp_idx(pool, ptr);
  return ((byte *)pool->state.last[idx] - (byte *)ptr) - pool->state.free[idx];
}

/**
 * Open the last memory block (allocated with @mp_alloc() or @mp_end())
 * for growing and return its size in bytes. The contents and the start pointer
 * remain unchanged. Do not forget to call @mp_end() to close it.
 **/
size_t mp_open(struct mempool *pool, void *ptr);

/**
 * Inlined version of @mp_open().
 **/
static inline size_t mp_open_fast(struct mempool *pool, void *ptr)
{
  pool->idx = mp_idx(pool, ptr);
  size_t size = ((byte *)pool->state.last[pool->idx] - (byte *)ptr) - pool->state.free[pool->idx];
  pool->state.free[pool->idx] += size;
  return size;
}

/**
 * Reallocate the last memory block (allocated with @mp_alloc() or @mp_end())
 * to the new @size. Behavior is similar to @mp_grow(), but the resulting
 * block is closed.
 **/
void *mp_realloc(struct mempool *pool, void *ptr, size_t size);

/**
 * The same as @mp_realloc(), but fills the additional bytes (if any) with zeroes.
 **/
void *mp_realloc_zero(struct mempool *pool, void *ptr, size_t size);

/**
 * Inlined version of @mp_realloc().
 **/
static inline void *mp_realloc_fast(struct mempool *pool, void *ptr, size_t size)
{
  mp_open_fast(pool, ptr);
  ptr = mp_grow(pool, size);
  mp_end(pool, (byte *)ptr + size);
  return ptr;
}

/***
 * [[store]]
 * Storing and restoring state
 * ---------------------------
 *
 * Mempools can remember history of what was allocated and return back
 * in time.
 ***/

/**
 * Save the current state of a memory pool.
 * Do not call this function with an opened growing buffer.
 **/
static inline void mp_save(struct mempool *pool, struct mempool_state *state)
{
  *state = pool->state;
  pool->state.next = state;
}

/**
 * Save the current state to a newly allocated mempool_state structure.
 * Do not call this function with an opened growing buffer.
 **/
struct mempool_state *mp_push(struct mempool *pool);

/**
 * Restore the state saved by @mp_save() or @mp_push() and free all
 * data allocated after that point (including the state structure itself).
 * You can't reallocate the last memory block from the saved state.
 **/
void mp_restore(struct mempool *pool, struct mempool_state *state);

/**
 * Inlined version of @mp_restore().
 **/
static inline void mp_restore_fast(struct mempool *pool, struct mempool_state *state)
{
  if (pool->state.last[0] != state->last[0] || pool->state.last[1] != state->last[1])
    mp_restore(pool, state);
  else
    {
      pool->state = *state;
      pool->last_big = &pool->last_big;
    }
}

/**
 * Restore the state saved by the last call to @mp_push().
 * @mp_pop() and @mp_push() works as a stack so you can push more states safely.
 **/
void mp_pop(struct mempool *pool);


/***
 * [[string]]
 * String operations
 * -----------------
 ***/

char *mp_strdup(struct mempool *, const char *) LIKE_MALLOC;		/** Makes a copy of a string on a mempool. Returns NULL for NULL string. **/
void *mp_memdup(struct mempool *, const void *, size_t) LIKE_MALLOC;	/** Makes a copy of a memory block on a mempool. **/
/**
 * Concatenates all passed strings. The last parameter must be NULL.
 * This will concatenate two strings:
 *
 *   char *message = mp_multicat(pool, "hello ", "world", NULL);
 **/
char *mp_multicat(struct mempool *, ...) LIKE_MALLOC SENTINEL_CHECK;
/**
 * Concatenates two strings and stores result on @mp.
 */
static inline char *LIKE_MALLOC mp_strcat(struct mempool *mp, const char *x, const char *y)
{
  return mp_multicat(mp, x, y, NULL);
}
/**
 * Join strings and place @sep between each two neighboring.
 * @p is the mempool to provide memory, @a is array of strings and @n
 * tells how many there is of them.
 **/
char *mp_strjoin(struct mempool *p, char **a, uint n, uint sep) LIKE_MALLOC;
/**
 * Convert memory block to a string. Makes a copy of the given memory block
 * in the mempool @p, adding an extra terminating zero byte at the end.
 **/
char *mp_str_from_mem(struct mempool *p, const void *mem, size_t len) LIKE_MALLOC;


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
 * Like @mp_printf(), but uses `va_list` for parameters.
 **/
char *mp_vprintf(struct mempool *mp, const char *fmt, va_list args) LIKE_MALLOC;
/**
 * Like @mp_printf(), but it appends the data at the end of string
 * pointed to by @ptr. The string is @mp_open()ed, so you have to
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
 * Like @mp_printf_append(), but uses `va_list` for parameters.
 *
 * In some versions of LibUCW, this function was called mp_append_vprintf(). However,
 * this name turned out to be confusing -- unlike other appending functions, this one is
 * not called on an opened growing buffer. The old name will be preserved for backward
 * compatibility for the time being.
 **/
char *mp_vprintf_append(struct mempool *mp, char *ptr, const char *fmt, va_list args);
#define mp_append_vprintf mp_vprintf_append

#endif
