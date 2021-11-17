/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file set.h
 * @brief A set abstraction implemented on top of map.
 *
 * @note The API is based on map.h, see it for more examples.
 *
 * # Example usage:
 *
 * @code{.c}
 *      set_t set = set_make(NULL);
 *
 *      // Insert keys
 *      if (set_add(&set, "princess") != 0 ||
 *          set_add(&set, "prince")   != 0 ||
 *          set_add(&set, "leia")     != 0) {
 *          fail();
 *      }
 *
 *      // Test membership
 *      if (set_contains(&set, "leia")) {
 *          success();
 *      }
 *
 *      // Prefix search
 *      int i = 0;
 *      int count(const char *s, void *n) { (*(int *)n)++; return 0; }
 *      if (set_walk_prefixed(set, "princ", count, &i) == 0) {
 *          printf("%d matches\n", i);
 *      }
 *
 *      // Delete
 *      if (set_del(&set, "badkey") != 0) {
 *          fail(); // No such key
 *      }
 *
 *      // Clear the set
 *      set_clear(&set);
 * @endcode
 *
 * \addtogroup generics
 * @{
 */

#pragma once

#include <stddef.h>
#include "map.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef map_t set_t;
typedef int (set_walk_cb)(const char *, void *);

/*! Creates an new, empty critbit set */
#define set_make \
	map_make

/*! Returns non-zero if set contains str */
#define set_contains(set, str) \
	map_contains((set), (str))

/*! Inserts str into set.  Returns 0 if new, 1 if already present, or ENOMEM. */
#define set_add(set, str) \
	map_set((set), (str), (void *)1)

/*! Deletes str from the set, returns 0 on success */
#define set_del(set, str) \
	map_del((set), (str))

/*! Clears the given set */
#define set_clear(set) \
	map_clear(set)

/*! Calls callback for all strings in map  */
#define set_walk(set, callback, baton) \
	map_walk_prefixed((set), "", (callback), (baton))

/*! Calls callback for all strings in set with the given prefix  */
#define set_walk_prefixed(set, prefix, callback, baton) \
	map_walk_prefixed((set), (prefix), (callback), (baton))


#ifdef __cplusplus
}
#endif

/** @} */
