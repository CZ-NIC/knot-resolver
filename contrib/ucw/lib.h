/*
 *	The UCW Library -- Miscellaneous Functions
 *
 *	(c) 1997--2014 Martin Mares <mj@ucw.cz>
 *	(c) 2005--2014 Tomas Valla <tom@ucw.cz>
 *	(c) 2006 Robert Spalek <robert@ucw.cz>
 *	(c) 2007 Pavel Charvat <pchar@ucw.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

#ifndef _UCW_LIB_H
#define _UCW_LIB_H

#include <stdarg.h>
#include <stdbool.h>

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

#undef inline
#define NONRET __attribute__((noreturn))				/** Function does not return **/
#define UNUSED __attribute__((unused))					/** Variable/parameter is knowingly unused **/
#define CONSTRUCTOR __attribute__((constructor))			/** Call function upon start of program **/
#define CONSTRUCTOR_WITH_PRIORITY(p) __attribute__((constructor(p)))	/** Define constructor with a given priority **/
#define PACKED __attribute__((packed))					/** Structure should be packed **/
#define CONST __attribute__((const))					/** Function depends only on arguments **/
#define PURE __attribute__((pure))					/** Function depends only on arguments and global vars **/
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

enum log_levels {			/** The available log levels to pass to msg() and friends. **/
  L_DEBUG=0,				// 'D' - Debugging
  L_INFO,				// 'I' - Informational
  L_WARN,				// 'W' - Warning
  L_ERROR,				// 'E' - Error, but non-critical
  L_INFO_R,				// 'i' - An alternative set of levels for messages caused by remote events
  L_WARN_R,				// 'w'   (e.g., a packet received via network)
  L_ERROR_R,				// 'e'
  L_FATAL,				// '!' - Fatal error
  L_MAX
};

#define LOG_LEVEL_NAMES P(DEBUG) P(INFO) P(WARN) P(ERROR) P(INFO_R) P(WARN_R) P(ERROR_R) P(FATAL)

// Return the letter associated with a given severity level
#define LS_LEVEL_LETTER(level) ("DIWEiwe!###"[( level )])

#define L_SIGHANDLER	0x80000000	/** Avoid operations that are unsafe in signal handlers **/
#define L_LOGGER_ERR	0x40000000	/** Used internally to avoid infinite reporting of logging errors **/

/**
 * This is the basic printf-like function for logging a message.
 * The @flags contain the log level and possibly other flag bits (like `L_SIGHANDLER`).
 **/
void msg(uint flags, const char *fmt, ...) FORMAT_CHECK(printf,2,3);
void vmsg(uint flags, const char *fmt, va_list args);		/** A vararg version of msg(). **/
void die(const char *, ...) NONRET FORMAT_CHECK(printf,1,2);	/** Log a fatal error message and exit the program. **/
void vdie(const char *fmt, va_list args) NONRET;		/** va_list version of die() **/

extern char *log_title;			/** An optional log message title. Set to program name by log_init(). **/
extern int log_pid;			/** An optional PID printed in each log message. Set to 0 if it shouldn't be logged. **/
extern void (*log_die_hook)(void);	/** An optional function called just before die() exists. **/	// API: log_die_hook

void log_init(const char *argv0);	/** Set @log_title to the program name extracted from @argv[0]. **/
void log_fork(void);			/** Call after fork() to update @log_pid. **/
void log_file(const char *name);	/** Establish logging to the named file. Also redirect stderr there. **/

void assert_failed(const char *assertion, const char *file, int line) NONRET;
void assert_failed_msg(const char *assertion, const char *file, int line, const char *fmt, ...) NONRET FORMAT_CHECK(printf,4,5);
void assert_failed_noinfo(void) NONRET;

#ifdef DEBUG_ASSERTS
/**
 * Check an assertion. If the condition @x is false, stop the program with a fatal error.
 * Assertion checks are compiled only when `DEBUG_ASSERTS` is defined.
 **/
#define ASSERT(x) ({ if (unlikely(!(x))) assert_failed(#x, __FILE__, __LINE__); 1; })

/**
 * Check an assertion with a debug message. If the condition @cond is false,
 * print the message and stop the program with fatal error.
 * Assertion checks are compiled only when `DEBUG_ASSERTS` is defined.
 **/
#define ASSERT_MSG(cond,str,x...) ({ if (unlikely(!(cond))) assert_failed_msg(#cond, __FILE__, __LINE__, str,##x); 1; })

#else
#define ASSERT(x) ({ if (__builtin_constant_p(x) && !(x)) assert_failed_noinfo(); 1; })
#define ASSERT_MSG(cond,str,x...) ASSERT(cond)
#endif

#define COMPILE_ASSERT(name,x) typedef char _COMPILE_ASSERT_##name[!!(x)-1]

#ifdef LOCAL_DEBUG
#define DBG(x,y...) msg(L_DEBUG, x,##y)	/** If `LOCAL_DEBUG` is defined before including <ucw/lib.h>, log a debug message. Otherwise do nothing. **/
/**
 * If `LOCAL_DEBUG` is defined before including <ucw/lib.h>, log current
 * file name and line number. Otherwise do nothing.
 **/
#define DBG_SPOT msg(L_DEBUG, "%s:%d (%s)", __FILE__, __LINE__, __func__)
#else
#define DBG(x,y...) do { } while(0)
#define DBG_SPOT do { } while(0)
#endif

#ifdef DEBUG_ASSERTS
/**
 * Sometimes, we may want to check that a pointer points to a valid memory
 * location before we start using it for anything more complicated. This
 * macro checks pointer validity by reading the byte it points to.
 **/
#define ASSERT_READABLE(ptr) ({ volatile char *__p = (ptr); *__p; })
/** Like the previous macro, but it checks writeability, too. **/
#define ASSERT_WRITEABLE(ptr) ({ volatile char *__p = (ptr); *__p = *__p; })
#else
#define ASSERT_READABLE(ptr) do { } while(0)
#define ASSERT_WRITEABLE(ptr) do { } while(0)
#endif

/*** === Memory allocation ***/

/*
 * Unfortunately, several libraries we might want to link to define
 * their own xmalloc and we don't want to interfere with them, hence
 * the renaming.
 */
#define xmalloc ucw_xmalloc
#define xrealloc ucw_xrealloc
#define xfree ucw_xfree

void *xmalloc(size_t) LIKE_MALLOC;		/** Allocate memory and die() if there is none. **/
void *xrealloc(void *, size_t);			/** Reallocate memory and die() if there is none. **/
void xfree(void *);				/** Free memory allocated by xmalloc() or xrealloc(). **/

void *xmalloc_zero(size_t) LIKE_MALLOC;		/** Allocate memory and fill it by zeroes. **/
char *xstrdup(const char *) LIKE_MALLOC;	/** Make a xmalloc()'ed copy of a string. Returns NULL for NULL string. **/

/* bigalloc.c */

void *page_alloc(u64 len) LIKE_MALLOC;		// Internal: allocates a multiple of CPU_PAGE_SIZE bytes with mmap
void *page_alloc_zero(u64 len) LIKE_MALLOC;
void page_free(void *start, u64 len);
void *page_realloc(void *start, u64 old_len, u64 new_len);

void *big_alloc(u64 len) LIKE_MALLOC;		/** Allocate a large memory block in the most efficient way available. **/
void *big_alloc_zero(u64 len) LIKE_MALLOC;	/** Allocate and clear a large memory block. **/
void big_free(void *start, u64 len);		/** Free block allocated by @big_alloc() or @big_alloc_zero(). **/

/*** === Random numbers (random.c) ***/

uint random_u32(void);				/** Return a pseudorandom 32-bit number. **/
uint random_max(uint max);			/** Return a pseudorandom 32-bit number in range [0,@max). **/
u64 random_u64(void);				/** Return a pseudorandom 64-bit number. **/
u64 random_max_u64(u64 max);			/** Return a pseudorandom 64-bit number in range [0,@max). **/

#endif
