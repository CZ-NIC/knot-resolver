/*
 *	UCW Library -- Memory Pools (One-Time Allocation)
 *
 *	(c) 1997--2014 Martin Mares <mj@ucw.cz>
 *	(c) 2007--2015 Pavel Charvat <pchar@ucw.cz>
 *
 * 	SPDX-License-Identifier: LGPL-2.1-or-later
 * 	Source: https://www.ucw.cz/libucw/
 */

#undef LOCAL_DEBUG

#include <ucw/config.h>
#include <ucw/lib.h>
#include <ucw/alloc.h>
#include <ucw/mempool.h>

#include <string.h>
#include <stdlib.h>

/* FIXME: migrate to Knot DNS version of mempools. */
#pragma GCC diagnostic ignored "-Wpointer-arith"

#define MP_CHUNK_TAIL ALIGN_TO(sizeof(struct mempool_chunk), CPU_STRUCT_ALIGN)
#define MP_SIZE_MAX (SIZE_MAX - MP_CHUNK_TAIL - CPU_PAGE_SIZE)

struct mempool_chunk {
#ifdef CONFIG_DEBUG
  struct mempool *pool;		// Can be useful when analysing coredump for memory leaks
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

static void *mp_allocator_alloc(struct ucw_allocator *a, size_t size)
{
  struct mempool *mp = (struct mempool *) a;
  return mp_alloc_fast(mp, size);
}

static void *mp_allocator_realloc(struct ucw_allocator *a, void *ptr, size_t old_size, size_t new_size)
{
  if (new_size <= old_size)
    return ptr;

  /*
   *  In the future, we might want to do something like mp_realloc(),
   *  but we have to check that it is indeed the last block in the pool.
   */
  struct mempool *mp = (struct mempool *) a;
  void *new = mp_alloc_fast(mp, new_size);
  memcpy(new, ptr, old_size);
  return new;
}

static void mp_allocator_free(struct ucw_allocator *a UNUSED, void *ptr UNUSED)
{
  // Does nothing
}

void
mp_init(struct mempool *pool, size_t chunk_size)
{
  chunk_size = mp_align_size(MAX(sizeof(struct mempool), chunk_size));
  *pool = (struct mempool) {
    .allocator = {
      .alloc = mp_allocator_alloc,
      .realloc = mp_allocator_realloc,
      .free = mp_allocator_free,
    },
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
  DBG("Creating mempool %p with %u bytes long chunks", pool, chunk_size);
  chunk->next = NULL;
#ifdef CONFIG_DEBUG
  chunk->pool = pool;
#endif
  *pool = (struct mempool) {
    .allocator = {
      .alloc = mp_allocator_alloc,
      .realloc = mp_allocator_realloc,
      .free = mp_allocator_free,
    },
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
  while (chunk)
    {
      struct mempool_chunk *next = chunk->next;
      mp_free_chunk(pool, chunk);
      chunk = next;
    }
}

static void
mp_free_big_chain(struct mempool *pool, struct mempool_chunk *chunk)
{
  while (chunk)
    {
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
  for (chunk = pool->state.last[0]; chunk && (void *)chunk - chunk->size != pool; chunk = next)
    {
      next = chunk->next;
      chunk->next = pool->unused;
      pool->unused = chunk;
    }
  pool->state.last[0] = chunk;
  pool->state.free[0] = chunk ? chunk->size - sizeof(*pool) : 0;
  pool->state.last[1] = NULL;
  pool->state.free[1] = 0;
  pool->state.next = NULL;
  pool->last_big = &pool->last_big;
}

static void
mp_stats_chain(struct mempool *pool, struct mempool_chunk *chunk, struct mempool_stats *stats, uint idx)
{
  while (chunk)
    {
      stats->chain_size[idx] += chunk->size + MP_CHUNK_TAIL;
      stats->chain_count[idx]++;
      if (idx < 2)
	{
	  stats->used_size += chunk->size;
	  if ((byte *)pool == (byte *)chunk - chunk->size)
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

u64
mp_total_size(struct mempool *pool)
{
  return pool->total_size;
}

void
mp_shrink(struct mempool *pool, u64 min_total_size)
{
  while (1)
    {
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
  if (size <= pool->threshold)
    {
      pool->idx = 0;
      if (pool->unused)
        {
	  chunk = pool->unused;
	  pool->unused = chunk->next;
	}
      else
	{
	  chunk = mp_new_chunk(pool, pool->chunk_size);
#ifdef CONFIG_DEBUG
	  chunk->pool = pool;
#endif
	}
      chunk->next = pool->state.last[0];
      pool->state.last[0] = chunk;
      pool->state.free[0] = pool->chunk_size - size;
      return (void *)chunk - pool->chunk_size;
    }
  else if (likely(size <= MP_SIZE_MAX))
    {
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
    }
  else
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
mp_alloc_zero(struct mempool *pool, size_t size)
{
  void *ptr = mp_alloc_fast(pool, size);
  bzero(ptr, size);
  return ptr;
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
  if (pool->idx)
    {
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
    }
  else
    {
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
mp_realloc_zero(struct mempool *pool, void *ptr, size_t size)
{
  size_t old_size = mp_open_fast(pool, ptr);
  ptr = mp_grow(pool, size);
  if (size > old_size)
    bzero(ptr + old_size, size - old_size);
  mp_end(pool, ptr + size);
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

void
mp_restore(struct mempool *pool, struct mempool_state *state)
{
  struct mempool_chunk *chunk, *next;
  struct mempool_state s = *state;
  for (chunk = pool->state.last[0]; chunk != s.last[0]; chunk = next)
    {
      next = chunk->next;
      chunk->next = pool->unused;
      pool->unused = chunk;
    }
  for (chunk = pool->state.last[1]; chunk != s.last[1]; chunk = next)
    {
      next = chunk->next;
      mp_free_big_chunk(pool, chunk);
    }
  pool->state = s;
  pool->last_big = &pool->last_big;
}

struct mempool_state *
mp_push(struct mempool *pool)
{
  struct mempool_state state = pool->state;
  struct mempool_state *p = mp_alloc_fast(pool, sizeof(*p));
  *p = state;
  pool->state.next = p;
  return p;
}

void
mp_pop(struct mempool *pool)
{
  ASSERT(pool->state.next);
  mp_restore(pool, pool->state.next);
}

#ifdef TEST

#include <ucw/getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static void
fill(byte *ptr, uint len, uint magic)
{
  while (len--)
    *ptr++ = (magic++ & 255);
}

static void
check(byte *ptr, uint len, uint magic, uint align)
{
  ASSERT(!((uintptr_t)ptr & (align - 1)));
  while (len--)
    if (*ptr++ != (magic++ & 255))
      ASSERT(0);
}

int main(int argc, char **argv)
{
  srand(time(NULL));
  log_init(argv[0]);
  cf_def_file = NULL;
  if (cf_getopt(argc, argv, CF_SHORT_OPTS, CF_NO_LONG_OPTS, NULL) >= 0 || argc != optind)
    die("Invalid usage");

  uint max = 1000, n = 0, m = 0, can_realloc = 0;
  void *ptr[max];
  struct mempool_state *state[max];
  uint len[max], num[max], align[max];
  struct mempool *mp = mp_new(128), mp_static;

  for (uint i = 0; i < 5000; i++)
    {
      for (uint j = 0; j < n; j++)
	check(ptr[j], len[j], j, align[j]);
#if 0
      DBG("free_small=%u free_big=%u idx=%u chunk_size=%u last_big=%p", mp->state.free[0], mp->state.free[1], mp->idx, mp->chunk_size, mp->last_big);
      for (struct mempool_chunk *ch = mp->state.last[0]; ch; ch = ch->next)
	DBG("small %p %p %p %d", (byte *)ch - ch->size, ch, ch + 1, ch->size);
      for (struct mempool_chunk *ch = mp->state.last[1]; ch; ch = ch->next)
	DBG("big %p %p %p %d", (byte *)ch - ch->size, ch, ch + 1, ch->size);
#endif
      int r = random_max(100);
      if ((r -= 1) < 0)
        {
	  DBG("flush");
	  mp_flush(mp);
	  n = m = 0;
	}
      else if ((r -= 1) < 0)
        {
	  DBG("delete & new");
	  mp_delete(mp);
	  if (random_max(2))
	    mp = mp_new(random_max(0x1000) + 1);
	  else
	    mp = &mp_static, mp_init(mp, random_max(512) + 1);
	  n = m = 0;
	}
      else if (n < max && (r -= 30) < 0)
        {
	  len[n] = random_max(0x2000);
	  DBG("alloc(%u)", len[n]);
	  align[n] = random_max(2) ? CPU_STRUCT_ALIGN : 1;
	  ptr[n] = (align[n] == 1) ? mp_alloc_fast_noalign(mp, len[n]) : mp_alloc_fast(mp, len[n]);
	  DBG(" -> (%p)", ptr[n]);
	  fill(ptr[n], len[n], n);
	  n++;
	  can_realloc = 1;
	}
      else if (n < max && (r -= 20) < 0)
        {
	  len[n] = random_max(0x2000);
	  DBG("start(%u)", len[n]);
	  align[n] = random_max(2) ? CPU_STRUCT_ALIGN : 1;
	  ptr[n] = (align[n] == 1) ? mp_start_fast_noalign(mp, len[n]) : mp_start_fast(mp, len[n]);
	  DBG(" -> (%p)", ptr[n]);
	  fill(ptr[n], len[n], n);
	  n++;
	  can_realloc = 1;
	  goto grow;
	}
      else if (can_realloc && n && (r -= 10) < 0)
        {
	  if (mp_open(mp, ptr[n - 1]) != len[n - 1])
	    ASSERT(0);
grow:
	  {
	    uint k = n - 1;
	    for (uint i = random_max(4); i--; )
	      {
	        uint l = len[k];
	        len[k] = random_max(0x2000);
	        DBG("grow(%u)", len[k]);
	        ptr[k] = mp_grow(mp, len[k]);
	        DBG(" -> (%p)", ptr[k]);
	        check(ptr[k], MIN(l, len[k]), k, align[k]);
	        fill(ptr[k], len[k], k);
	      }
	    mp_end(mp, ptr[k] + len[k]);
	  }
	}
      else if (can_realloc && n && (r -= 20) < 0)
        {
	  uint i = n - 1, l = len[i];
	  DBG("realloc(%p, %u)", ptr[i], len[i]);
	  ptr[i] = mp_realloc(mp, ptr[i], len[i] = random_max(0x2000));
	  DBG(" -> (%p, %u)", ptr[i], len[i]);
	  check(ptr[i],  MIN(len[i], l), i, align[i]);
	  fill(ptr[i], len[i], i);
	}
      else if (m < max && (r -= 5) < 0)
        {
	  DBG("push(%u)", m);
	  num[m] = n;
	  state[m++] = mp_push(mp);
	  can_realloc = 0;
	}
      else if (m && (r -= 2) < 0)
        {
	  m--;
	  DBG("pop(%u)", m);
	  mp_pop(mp);
	  n = num[m];
	  can_realloc = 0;
	}
      else if (m && (r -= 1) < 0)
        {
	  uint i = random_max(m);
	  DBG("restore(%u)", i);
	  mp_restore(mp, state[i]);
	  n = num[m = i];
	  can_realloc = 0;
	}
      else if (can_realloc && n && (r -= 5) < 0)
        ASSERT(mp_size(mp, ptr[n - 1]) == len[n - 1]);
      else
	{
	  struct mempool_stats stats;
	  mp_stats(mp, &stats);
	}
    }

  mp_delete(mp);
  return 0;
}

#endif
