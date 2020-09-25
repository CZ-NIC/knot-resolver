/*
 *	The UCW Library -- Miscellaneous Functions
 *
 *	(c) 1997--2014 Martin Mares <mj@ucw.cz>
 *	(c) 2005--2014 Tomas Valla <tom@ucw.cz>
 *	(c) 2006 Robert Spalek <robert@ucw.cz>
 *	(c) 2007 Pavel Charvat <pchar@ucw.cz>
 *
 *	SPDX-License-Identifier: LGPL-2.1-or-later
 *	Source: https://www.ucw.cz/libucw/
 */

#ifndef _UCW_LIB_H
#define _UCW_LIB_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef CONFIG_UCW_CLEAN_ABI
#define assert_failed ucw_assert_failed
#define assert_failed_msg ucw_assert_failed_msg
#define assert_failed_noinfo ucw_assert_failed_noinfo
#define big_alloc ucw_big_alloc
#define big_alloc_zero ucw_big_alloc_zero
#define big_free ucw_big_free
#define die ucw_die
#define log_die_hook ucw_log_die_hook
#define log_file ucw_log_file
#define log_fork ucw_log_fork
#define log_init ucw_log_init
#define log_pid ucw_log_pid
#define log_title ucw_log_title
#define msg ucw_msg
#define page_alloc ucw_page_alloc
#define page_alloc_zero ucw_page_alloc_zero
#define page_free ucw_page_free
#define page_realloc ucw_page_realloc
#define random_max ucw_random_max
#define random_max_u64 ucw_random_max_u64
#define random_u32 ucw_random_u32
#define random_u64 ucw_random_u64
#define vdie ucw_vdie
#define vmsg ucw_vmsg
#define xfree ucw_xfree
#define xmalloc ucw_xmalloc
#define xmalloc_zero ucw_xmalloc_zero
#define xrealloc ucw_xrealloc
#define xstrdup ucw_xstrdup
#endif

/*** === Macros for handling structures, offsets and alignment ***/

#define CHECK_PTR_TYPE(x, type) ((x)-(type)(x) + (type)(x))		/** Check that a pointer @x is of type @type. Fail compilation if not. **/
#define PTR_TO(s, i) &((s*)0)->i					/** Return OFFSETOF() in form of a pointer. **/
#define OFFSETOF(s, i) ((uint)offsetof(s, i))				/** Offset of item @i from the start of structure @s **/
#define SKIP_BACK(s, i, p) ((s *)((char *)p - OFFSETOF(s, i)))		/** Given a pointer @p to item @i of structure @s, return a pointer to the start of the struct. **/

/** Align an integer @s to the nearest higher multiple of @a (which should be a power of two) **/
#define ALIGN_TO(s, a) (((s)+a-1)&~(a-1))

/** Align a pointer @p to the nearest higher multiple of @s. **/
#define ALIGN_PTR(p, s) ((uintptr_t)(p) % (s) ? (typeof(p))((uintptr_t)(p) + (s) - (uintptr_t)(p) % (s)) : (p))

#define UNALIGNED_PART(ptr, type) (((uintptr_t) (ptr)) % sizeof(type))

/*** === Other utility macros ***/

#define MIN(a,b) (((a)<(b))?(a):(b))			/** Minimum of two numbers **/
#define MAX(a,b) (((a)>(b))?(a):(b))			/** Maximum of two numbers **/
#define CLAMP(x,min,max) ({ typeof(x) _t=x; (_t < min) ? min : (_t > max) ? max : _t; })	/** Clip a number @x to interval [@min,@max] **/
#define ABS(x) ((x) < 0 ? -(x) : (x))			/** Absolute value **/
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*(a)))		/** The number of elements of an array **/
#define STRINGIFY(x) #x					/** Convert macro parameter to a string **/
#define STRINGIFY_EXPANDED(x) STRINGIFY(x)		/** Convert an expanded macro parameter to a string **/
#define GLUE(x,y) x##y					/** Glue two tokens together **/
#define GLUE_(x,y) x##_##y				/** Glue two tokens together, separating them by an underscore **/

#define COMPARE(x,y) do { if ((x)<(y)) return -1; if ((x)>(y)) return 1; } while(0)		/** Numeric comparison function for qsort() **/
#define REV_COMPARE(x,y) COMPARE(y,x)								/** Reverse numeric comparison **/
#define COMPARE_LT(x,y) do { if ((x)<(y)) return 1; if ((x)>(y)) return 0; } while(0)
#define COMPARE_GT(x,y) COMPARE_LT(y,x)

#define	ROL(x, bits) (((x) << (bits)) | ((uint)(x) >> (sizeof(uint)*8 - (bits))))		/** Bitwise rotation of an unsigned int to the left **/
#define	ROR(x, bits) (((uint)(x) >> (bits)) | ((x) << (sizeof(uint)*8 - (bits))))		/** Bitwise rotation of an unsigned int to the right **/

/*** === Shortcuts for GCC Extensions ***/

#ifdef __GNUC__

#include "ccan/compiler/compiler.h"
#define FORMAT_CHECK(x,y,z) __attribute__((format(x,y,z)))		/** Checking of printf-like format strings **/
#define likely(x) __builtin_expect((x),1)				/** Use `if (likely(@x))` if @x is almost always true **/
#define unlikely(x) __builtin_expect((x),0)				/** Use `if (unlikely(@x))` to hint that @x is almost always false **/

#if __GNUC__ >= 4 || __GNUC__ == 3 && __GNUC_MINOR__ >= 3
#define ALWAYS_INLINE inline __attribute__((always_inline))		/** Forcibly inline **/
#define NO_INLINE __attribute__((noinline))				/** Forcibly uninline **/
#else
#define ALWAYS_INLINE inline
#endif

#if __GNUC__ >= 4
#define LIKE_MALLOC __attribute__((malloc))				/** Function returns a "new" pointer **/
#define SENTINEL_CHECK __attribute__((sentinel))			/** The last argument must be NULL **/
#else
#define LIKE_MALLOC
#define SENTINEL_CHECK
#endif

#else
#error This program requires the GNU C compiler.
#endif

/***
 * [[logging]]
 *
 * === Basic logging functions (see <<log:,Logging>> and <ucw/log.h> for more)
 ***/

#define DBG(x, ...) do { } while(0)
#define DBG_SPOT do { } while(0)
#define ASSERT(x)

#endif
