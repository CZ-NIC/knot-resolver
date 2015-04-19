/*
 * critbit89 - A crit-bit map implementation for strings in C89
 * Written by Jonas Gehring <jonas@jgehring.net>
 */

/**
 * @file map.h
 * @brief A Crit-bit tree key-value map implementation.
 *
 * @warning If the user provides a custom allocator, it must return addresses aligned to 2B boundary.
 *
 * Example usage:
 *
 *      map_t map = map_make();
 *
 *      // Custom allocator (optional)
 *      map.malloc = &mymalloc;
 *      map.baton  = &mymalloc_context;
 *
 *      // Insert keys
 *      if (map_set(&map, "princess") != 0 ||
 *          map_set(&map, "prince")   != 0 ||
 *          map_set(&map, "leia")     != 0) {
 *          fail();
 *      }
 *
 *      // Test membership
 *      if (map_contains(&map, "leia")) {
 *          success();
 *      }
 *
 *      // Prefix search
 *      int i = 0;
 *      int count(const char *k, void *v, void *ext) { (*(int *)ext)++; return 0; }
 *      if (map_walk_prefixed(map, "princ", count, &i) == 0) {
 *          printf("%d matches\n", i);
 *      }
 *
 *      // Delete
 *      if (map_del(&map, "badkey") != 0) {
 *          fail(); // No such key
 *      }
 *
 *      // Clear the map
 *      map_clear(&map);
 *
 * \addtogroup generics
 * @{
 */

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *(*map_alloc_f)(void *, size_t);
typedef void (*map_free_f)(void *baton, void *ptr);

/** Main data structure */
typedef struct {
	void *root;
	map_alloc_f malloc;
	map_free_f free;
	void *baton; /** Passed to malloc() and free() */
} map_t;

/** Creates an new, empty critbit map */
map_t map_make(void);

/** Returns non-zero if map contains str */
int map_contains(map_t *map, const char *str);

/** Returns value if map contains str */
void *map_get(map_t *map, const char *str);

/** Inserts str into map, returns 0 on suceess */
int map_set(map_t *map, const char *str, void *val);

/** Deletes str from the map, returns 0 on suceess */
int map_del(map_t *map, const char *str);

/** Clears the given map */
void map_clear(map_t *map);

/**
 * Calls callback for all strings in map
 * See @fn map_walk_prefixed() for documentation on parameters.
 */
#define map_walk(map, callback, baton) \
	map_walk_prefixed((map), "", (callback), (baton))

/**
 * Calls callback for all strings in map with the given prefix
 * @param map
 * @param prefix   required string prefix (empty => all strings)
 * @param callback callback parameters are (key, value, baton)
 * @param baton    passed uservalue
 */
int map_walk_prefixed(map_t *map, const char *prefix,
	int (*callback)(const char *, void *, void *), void *baton);


#ifdef __cplusplus
}
#endif

/** @} */
