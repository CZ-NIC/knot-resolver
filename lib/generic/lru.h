/*  Copyright (C) 2016-2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
/**
 * @file lru.h
 * @brief A lossy cache.
 *
 * @note The implementation tries to keep frequent keys and avoid others,
 *  even if "used recently", so it may refuse to store it on lru_get_new().
 *  It uses hashing to split the problem pseudo-randomly into smaller groups,
 *  and within each it tries to approximate relative usage counts of several
 *  most frequent keys/hashes.  This tracking is done for *more* keys than
 *  those that are actually stored.
 *
 * Example usage:
 * @code{.c}
 * 	// Define new LRU type
 * 	typedef lru_t(int) lru_int_t;
 *
 * 	// Create LRU
 * 	lru_int_t *lru;
 * 	lru_create(&lru, 5, NULL, NULL);
 *
 * 	// Insert some values
 * 	int *pi = lru_get_new(lru, "luke", strlen("luke"), NULL);
 * 	if (pi)
 * 		*pi = 42;
 * 	pi = lru_get_new(lru, "leia", strlen("leia"), NULL);
 * 	if (pi)
 * 		*pi = 24;
 *
 * 	// Retrieve values
 * 	int *ret = lru_get_try(lru, "luke", strlen("luke"), NULL);
 * 	if (!ret) printf("luke dropped out!\n");
 * 	    else  printf("luke's number is %d\n", *ret);
 *
 * 	char *enemies[] = {"goro", "raiden", "subzero", "scorpion"};
 * 	for (int i = 0; i < 4; ++i) {
 * 		int *val = lru_get_new(lru, enemies[i], strlen(enemies[i]), NULL);
 * 		if (val)
 * 			*val = i;
 * 	}
 *
 * 	// We're done
 * 	lru_free(lru);
 * @endcode
 *
 * \addtogroup generics
 * @{
 */

#pragma once

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#include "contrib/ucw/lib.h"
#include "lib/utils.h"
#include "libknot/mm_ctx.h"

/* ================================ Interface ================================ */

/** @brief The type for LRU, parametrized by value type. */
#define lru_t(type) \
	union { \
		type *pdata_t; /* only the *type* information is used */ \
		struct lru lru; \
	}

/**
 * @brief Allocate and initialize an LRU with default associativity.
 *
 * The real limit on the number of slots can be a bit larger but less than double.
 *
 * @param ptable pointer to a pointer to the LRU
 * @param max_slots number of slots
 * @param mm_ctx_array memory context to use for the huge array, NULL for default
 * 	If you pass your own, it needs to produce CACHE_ALIGNED allocations (ubsan).
 * @param mm_ctx memory context to use for individual key-value pairs, NULL for default
 *
 * @note The pointers to memory contexts need to remain valid
 * 	during the whole life of the structure (or be NULL).
 */
/* Pragmas: C11 only standardizes alignof on type names, not on expressions.
 * That's a GNU extension; in clang it's supported but may generate warnings.
 * It seems hard to disable warnings that are only supported by some compilers. */
#define lru_create(ptable, max_slots, mm_ctx_array, mm_ctx) do { \
	(void)(((__typeof__((*(ptable))->pdata_t))0) == (void *)0); /* typecheck lru_t */ \
	_Pragma("GCC diagnostic push") \
	_Pragma("GCC diagnostic ignored \"-Wpragmas\"") \
	_Pragma("GCC diagnostic ignored \"-Wunknown-pragmas\"") \
	_Pragma("GCC diagnostic ignored \"-Wgnu-alignof-expression\"") \
	*(ptable) = (__typeof__(*(ptable))) \
		lru_create_impl((max_slots), alignof(*( (*(ptable))->pdata_t )), \
				(mm_ctx_array), (mm_ctx)); \
	_Pragma("GCC diagnostic pop") \
	} while (false)

/** @brief Free an LRU created by lru_create (it can be NULL). */
#define lru_free(table) \
	lru_free_impl(&(table)->lru)

/** @brief Reset an LRU to the empty state (but preserve any settings). */
#define lru_reset(table) \
	lru_reset_impl(&(table)->lru)

/**
 * @brief Find key in the LRU and return pointer to the corresponding value.
 *
 * @param table pointer to LRU
 * @param key_ lookup key
 * @param len_ key length
 * @return pointer to data or NULL if not found
 */
#define lru_get_try(table, key_, len_) \
	(__typeof__((table)->pdata_t)) \
		lru_get_impl(&(table)->lru, (key_), (len_), -1, false, NULL)

/**
 * @brief Return pointer to value, inserting if needed (zeroed).
 *
 * @param table pointer to LRU
 * @param key_ lookup key
 * @param len_ key lengthkeys
 * @param is_new pointer to bool to store result of operation
 *             (true if entry is newly added, false otherwise; can be NULL).
 * @return pointer to data or NULL (can be even if memory could be allocated!)
 */
#define lru_get_new(table, key_, len_, is_new) \
	(__typeof__((table)->pdata_t)) \
		lru_get_impl(&(table)->lru, (key_), (len_), \
		sizeof(*(table)->pdata_t), true, is_new)

/**
 * @brief Apply a function to every item in LRU.
 *
 * @param table pointer to LRU
 * @param function enum lru_apply_do (*function)(const char *key, uint len, val_type *val, void *baton)
 *        See enum lru_apply_do for the return type meanings.
 * @param baton extra pointer passed to each function invocation
 */
#define lru_apply(table, function, baton) do { \
	lru_apply_fun_g(fun_dummy, __typeof__(*(table)->pdata_t)) = 0; \
	(void)(fun_dummy == (function)); /* produce a warning with incompatible function type */ \
	lru_apply_impl(&(table)->lru, (lru_apply_fun)(function), (baton)); \
	} while (false)

/** @brief Possible actions to do with an element. */
enum lru_apply_do {
	LRU_APPLY_DO_NOTHING,
	LRU_APPLY_DO_EVICT,
	/* maybe more in future*/
};

/**
 * @brief Return the real capacity - maximum number of keys holdable within.
 *
 * @param table pointer to LRU
 */
#define lru_capacity(table) lru_capacity_impl(&(table)->lru)



/* ======================== Inlined part of implementation ======================== */
/** @cond internal */

#define lru_apply_fun_g(name, val_type) \
	enum lru_apply_do (*(name))(const char *key, uint len, val_type *val, void *baton)
typedef lru_apply_fun_g(lru_apply_fun, void);

#if __GNUC__ >= 4
	#define CACHE_ALIGNED __attribute__((aligned(64)))
#else
	#define CACHE_ALIGNED
#endif

struct lru;
void lru_free_items_impl(struct lru *lru);
struct lru * lru_create_impl(uint max_slots, uint val_alignment,
			     knot_mm_t *mm_array, knot_mm_t *mm);
void * lru_get_impl(struct lru *lru, const char *key, uint key_len,
		    uint val_len, bool do_insert, bool *is_new);
void lru_apply_impl(struct lru *lru, lru_apply_fun f, void *baton);

struct lru_item;

#if SIZE_MAX > (1 << 32)
	/** @internal The number of keys stored within each group. */
	#define LRU_ASSOC 3
#else
	#define LRU_ASSOC 4
#endif
/** @internal The number of hashes tracked within each group: 10-1 or 12-1. */
#define LRU_TRACKED ((64 - sizeof(size_t) * LRU_ASSOC) / 4 - 1)

struct lru_group {
	uint16_t counts[LRU_TRACKED+1]; /*!< Occurrence counters; the last one is special. */
	uint16_t hashes[LRU_TRACKED+1]; /*!< Top halves of hashes; the last one is unused. */
	struct lru_item *items[LRU_ASSOC]; /*!< The full items. */
} CACHE_ALIGNED;

/* The sizes are chosen so lru_group just fits into a single x86 cache line. */
static_assert(64 == sizeof(struct lru_group)
		&& 64 == LRU_ASSOC * sizeof(void*) + (LRU_TRACKED+1) * 4,
		"bad sizing for your sizeof(void*)");

struct lru {
	struct knot_mm *mm, /**< Memory context to use for keys. */
		*mm_array; /**< Memory context to use for this structure itself. */
	uint log_groups; /**< Logarithm of the number of LRU groups. */
	uint val_alignment; /**< Alignment for the values. */
	struct lru_group groups[] CACHE_ALIGNED; /**< The groups of items. */
};

/** @internal See lru_free. */
static inline void lru_free_impl(struct lru *lru)
{
	if (!lru)
		return;
	lru_free_items_impl(lru);
	mm_free(lru->mm_array, lru);
}

/** @internal See lru_reset. */
static inline void lru_reset_impl(struct lru *lru)
{
	lru_free_items_impl(lru);
	memset(lru->groups, 0, sizeof(lru->groups[0]) * (1 << lru->log_groups));
}

/** @internal See lru_capacity. */
static inline uint lru_capacity_impl(struct lru *lru)
{
	kr_require(lru);
	return (1 << lru->log_groups) * LRU_ASSOC;
}

/** @endcond */
/** @} (addtogroup generics) */
