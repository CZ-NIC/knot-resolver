/*
 *	UCW Library -- Memory Pools
 *
 *	(c) 1997--2005 Martin Mares <mj@ucw.cz>
 *	(c) 2007 Pavel Charvat <pchar@ucw.cz>
 *	(c) 2015, 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

#pragma once

#include <string.h>
#include <stdint.h>

#define CPU_STRUCT_ALIGN (sizeof(void*))

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
	unsigned free[2];
	void *last[2];
};

/**
 * Memory pool.
 * You should use this one as an opaque handle only, the insides are internal.
 **/
struct mempool {
	struct mempool_state state;
	void *unused, *last_big;
	unsigned chunk_size, threshold, idx;
};

struct mempool_stats {			/** Mempool statistics. See mp_stats(). **/
	uint64_t total_size;		/** Real allocated size in bytes. */
	unsigned chain_count[3];	/** Number of allocated chunks in small/big/unused chains. */
	unsigned chain_size[3];		/** Size of allocated chunks in small/big/unused chains. */
};

/***
 * [[basic]]
 * Basic manipulation
 * ------------------
 ***/

/**
 * Initialize a given mempool structure.
 * \p chunk_size must be in the interval `[1, UINT_MAX / 2]`.
 * It will allocate memory by this large chunks and take
 * memory to satisfy requests from them.
 *
 * Memory pools can be treated as <<trans:respools,resources>>, see <<trans:res_mempool()>>.
 **/
void mp_init(struct mempool *pool, unsigned chunk_size);

/**
 * Allocate and initialize a new memory pool.
 * See \ref mp_init() for \p chunk_size limitations.
 *
 * The new mempool structure is allocated on the new mempool.
 *
 * Memory pools can be treated as <<trans:respools,resources>>, see <<trans:res_mempool()>>.
 **/
struct mempool *mp_new(unsigned chunk_size);

/**
 * Cleanup mempool initialized by mp_init or mp_new.
 * Frees all the memory allocated by this mempool and,
 * if created by \ref mp_new(), the \p pool itself.
 **/
void mp_delete(struct mempool *pool);

/**
 * Frees all data on a memory pool, but leaves it working.
 * It can keep some of the chunks allocated to serve
 * further allocation requests. Leaves the \p pool alive,
 * even if it was created with \ref mp_new().
 **/
void mp_flush(struct mempool *pool);

/**
 * Compute some statistics for debug purposes.
 * See the definition of the <<struct_mempool_stats,mempool_stats structure>>.
 **/
void mp_stats(struct mempool *pool, struct mempool_stats *stats);
uint64_t mp_total_size(struct mempool *pool);	/** How many bytes were allocated by the pool. **/

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
void *mp_alloc(struct mempool *pool, unsigned size);

/**
 * The same as \ref mp_alloc(), but the result may be unaligned.
 **/
void *mp_alloc_noalign(struct mempool *pool, unsigned size);

/**
 * The same as \ref mp_alloc(), but fills the newly allocated memory with zeroes.
 **/
void *mp_alloc_zero(struct mempool *pool, unsigned size);
