/*
 *	UCW Library -- Configuration-Dependent Definitions
 *
 *	(c) 1997--2012 Martin Mares <mj@ucw.cz>
 *	(c) 2006 Robert Spalek <robert@ucw.cz>
 *
 *	SPDX-License-Identifier: LGPL-2.1-or-later
 *	Source: https://www.ucw.cz/libucw/
 */

#ifndef _UCW_CONFIG_H
#define _UCW_CONFIG_H

/* Default page size and pointer alignment */
#ifndef CPU_PAGE_SIZE
#define CPU_PAGE_SIZE 4096
#endif
#define CPU_STRUCT_ALIGN sizeof(void *)

/* Tell libc we're going to use all extensions available */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Types (based on standard C99 integers) */

#include <stddef.h>
#include <stdint.h>

typedef uint8_t byte;			/** Exactly 8 bits, unsigned **/
typedef uint8_t u8;			/** Exactly 8 bits, unsigned **/
typedef int8_t s8;			/** Exactly 8 bits, signed **/
typedef uint16_t u16;			/** Exactly 16 bits, unsigned **/
typedef int16_t s16;			/** Exactly 16 bits, signed **/
typedef uint32_t u32;			/** Exactly 32 bits, unsigned **/
typedef int32_t s32;			/** Exactly 32 bits, signed **/
typedef uint64_t u64;			/** Exactly 64 bits, unsigned **/
typedef int64_t s64;			/** Exactly 64 bits, signed **/


#ifndef uint /* Redefining typedef is a C11 feature. */
typedef unsigned int uint;		/** A better pronounceable alias for `unsigned int` **/
#define uint uint
#endif

typedef s64 timestamp_t;		/** Milliseconds since an unknown epoch **/

// FIXME: This should be removed soon
typedef uint uns;			/** Backwards compatible alias for `uint' ***/

#ifdef CONFIG_UCW_LARGE_FILES
typedef s64 ucw_off_t;			/** File position (either 32- or 64-bit, depending on `CONFIG_UCW_LARGE_FILES`). **/
#else
typedef s32 ucw_off_t;
#endif

#endif
