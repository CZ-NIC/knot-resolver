/*
 *	UCW Library -- Generic allocators
 *
 *	(c) 2014 Martin Mares <mj@ucw.cz>
 *	SPDX-License-Identifier: LGPL-2.1-or-later
 *	Source: https://www.ucw.cz/libucw/
 */

#ifndef _UCW_ALLOC_H
#define _UCW_ALLOC_H

/**
 * This structure describes a generic allocator. It provides pointers
 * to three functions, which handle the actual (re)allocations.
 **/
struct ucw_allocator {
  void * (*alloc)(struct ucw_allocator *alloc, size_t size);
  void * (*realloc)(struct ucw_allocator *alloc, void *ptr, size_t old_size, size_t new_size);
  void (*free)(struct ucw_allocator *alloc, void *ptr);
};

/* alloc-std.c */

/**
 * [[std]]
 * This allocator uses <<basics:xmalloc()>>, <<basics:xrealloc()>> and <<basics:xfree()>>. The memory
 * it allocates is left unitialized.
 **/
extern struct ucw_allocator ucw_allocator_std;

/**
 * [[zeroing]]
 * This allocator uses <<basics:xmalloc()>>, <<basics:xrealloc()>> and <<basics:xfree()>>. All memory
 * is zeroed upon allocation.
 **/
extern struct ucw_allocator ucw_allocator_zeroed;

#endif
