/*
 * critbit89 - A crit-bit tree implementation for strings in C89
 * Written by Jonas Gehring <jonas@jgehring.net>
 * Implemented key-value storing by Marek Vavrusa <marek.vavrusa@nic.cz>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The code makes the assumption that malloc returns pointers aligned at at
 * least a two-byte boundary. Since the C standard requires that malloc return
 * pointers that can store any type, there are no commonly-used toolchains for
 * which this assumption is false.
 *
 * See https://github.com/agl/critbit/blob/master/critbit.pdf for reference.
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "map.h"
#include "lib/utils.h"

 /* Exports */
#if defined _WIN32 || defined __CYGWIN__
  #define EXPORT __attribute__ ((dllexport))
#else
  #define EXPORT __attribute__ ((visibility ("default")))
#endif

#ifdef _MSC_VER /* MSVC */
 typedef unsigned __int8 uint8_t;
 typedef unsigned __int32 uint32_t;
 #ifdef _WIN64
  typedef signed __int64 intptr_t;
 #else
  typedef _W64 signed int intptr_t;
 #endif
#else /* Not MSVC */
 #include <stdint.h>
#endif

typedef struct {
	void* value;
	uint8_t key[];
} cb_data_t;

typedef struct {
	void *child[2];
	uint32_t byte;
	uint8_t otherbits;
} cb_node_t;

/* Return true if ptr is internal node. */
static inline int ref_is_internal(const uint8_t *p)
{
	return 1 & (intptr_t)p;
}

/* Get internal node. */
static inline cb_node_t *ref_get_internal(uint8_t *p)
{
	return (cb_node_t *)(p - 1);
}

/* Static helper functions */
static void cbt_traverse_delete(map_t *map, void *top)
{
	uint8_t *p = top;
	if (ref_is_internal(p)) {
		cb_node_t *q = ref_get_internal(p);
		cbt_traverse_delete(map, q->child[0]);
		cbt_traverse_delete(map, q->child[1]);
		mm_free(map->pool, q);
	} else {
		mm_free(map->pool, p);
	}
}

static int cbt_traverse_prefixed(void *top,
	int (*callback)(const char *, void *, void *), void *baton)
{
	uint8_t *p = top;
	cb_data_t *x = (cb_data_t *)top;

	if (ref_is_internal(p)) {
		cb_node_t *q = ref_get_internal(p);
		int ret = 0;

		ret = cbt_traverse_prefixed(q->child[0], callback, baton);
		if (ret != 0) {
			return ret;
		}
		ret = cbt_traverse_prefixed(q->child[1], callback, baton);
		if (ret != 0) {
			return ret;
		}
		return 0;
	}

	return (callback)((const char *)x->key, x->value, baton);
}

static cb_data_t *cbt_make_data(map_t *map, const uint8_t *str, size_t len, void *value)
{
	cb_data_t *x = mm_alloc(map->pool, sizeof(cb_data_t) + len);
	if (x != NULL) {
		x->value = value;
		memcpy(x->key, str, len);
	}
	return x;
}

/*! Like map_contains, but also set the value, if passed and found. */
static int cbt_get(map_t *map, const char *str, void **value)
{
	const uint8_t *ubytes = (void *)str;
	const size_t ulen = strlen(str);
	uint8_t *p = map->root;
	cb_data_t *x = NULL;

	if (p == NULL) {
		return 0;
	}

	while (ref_is_internal(p)) {
		cb_node_t *q = ref_get_internal(p);
		uint8_t c = 0;
		int direction;

		if (q->byte < ulen) {
			c = ubytes[q->byte];
		}
		direction = (1 + (q->otherbits | c)) >> 8;

		p = q->child[direction];
	}

	x = (cb_data_t *)p;
	if (strcmp(str, (const char *)x->key) == 0) {
		if (value != NULL) {
			*value = x->value;
		}
		return 1;
	}

	return 0;
}

/*! Returns non-zero if map contains str */
EXPORT int map_contains(map_t *map, const char *str)
{
	return cbt_get(map, str, NULL);
}

EXPORT void *map_get(map_t *map, const char *str)
{
	void *v = NULL;
	cbt_get(map, str, &v);
	return v;
}

EXPORT int map_set(map_t *map, const char *str, void *val)
{
	const uint8_t *const ubytes = (void *)str;
	const size_t ulen = strlen(str);
	uint8_t *p = map->root;
	uint8_t c = 0, *x = NULL;
	uint32_t newbyte = 0;
	uint32_t newotherbits = 0;
	int direction = 0, newdirection = 0;
	cb_node_t *newnode = NULL;
	cb_data_t *data = NULL;
	void **wherep = NULL;

	if (p == NULL) {
		map->root = cbt_make_data(map, (const uint8_t *)str, ulen + 1, val);
		if (map->root == NULL) {
			return ENOMEM;
		}
		return 0;
	}

	while (ref_is_internal(p)) {
		cb_node_t *q = ref_get_internal(p);
		c = 0;
		if (q->byte < ulen) {
			c = ubytes[q->byte];
		}
		direction = (1 + (q->otherbits | c)) >> 8;

		p = q->child[direction];
	}

	data = (cb_data_t *)p;
	for (newbyte = 0; newbyte < ulen; ++newbyte) {
		if (data->key[newbyte] != ubytes[newbyte]) {
			newotherbits = data->key[newbyte] ^ ubytes[newbyte];
			goto different_byte_found;
		}
	}

	if (data->key[newbyte] != 0) {
		newotherbits = data->key[newbyte];
		goto different_byte_found;
	}
	data->value = val;
	return 1;

different_byte_found:
	newotherbits |= newotherbits >> 1;
	newotherbits |= newotherbits >> 2;
	newotherbits |= newotherbits >> 4;
	newotherbits = (newotherbits & ~(newotherbits >> 1)) ^ 255;
	c = data->key[newbyte];
	newdirection = (1 + (newotherbits | c)) >> 8;

	newnode = mm_alloc(map->pool, sizeof(cb_node_t));
	if (newnode == NULL) {
		return ENOMEM;
	}

	x = (uint8_t *)cbt_make_data(map, ubytes, ulen + 1, val);
	if (x == NULL) {
		mm_free(map->pool, newnode);
		return ENOMEM;
	}

	newnode->byte = newbyte;
	newnode->otherbits = newotherbits;
	newnode->child[1 - newdirection] = x;

	/* Insert into map */
	wherep = &map->root;
	for (;;) {
		cb_node_t *q;
		p = *wherep;
		if (!ref_is_internal(p)) {
			break;
		}

		q = ref_get_internal(p);
		if (q->byte > newbyte) {
			break;
		}
		if (q->byte == newbyte && q->otherbits > newotherbits) {
			break;
		}

		c = 0;
		if (q->byte < ulen) {
			c = ubytes[q->byte];
		}
		direction = (1 + (q->otherbits | c)) >> 8;
		wherep = q->child + direction;
	}

	newnode->child[newdirection] = *wherep;
	*wherep = (void *)(1 + (char *)newnode);
	return 0;
}

/*! Deletes str from the map, returns 0 on success */
EXPORT int map_del(map_t *map, const char *str)
{
	const uint8_t *ubytes = (void *)str;
	const size_t ulen = strlen(str);
	uint8_t *p = map->root;
	void **wherep = NULL, **whereq = NULL;
	cb_node_t *q = NULL;
	cb_data_t *data = NULL;
	int direction = 0;

	if (map->root == NULL) {
		return 1;
	}
	wherep = &map->root;

	while (ref_is_internal(p)) {
		uint8_t c = 0;
		whereq = wherep;
		q = ref_get_internal(p);

		if (q->byte < ulen) {
			c = ubytes[q->byte];
		}
		direction = (1 + (q->otherbits | c)) >> 8;
		wherep = q->child + direction;
		p = *wherep;
	}

	data = (cb_data_t *)p;
	if (strcmp(str, (const char *)data->key) != 0) {
		return 1;
	}
	mm_free(map->pool, p);

	if (!whereq) {
		map->root = NULL;
		return 0;
	}

	*whereq = q->child[1 - direction];
	mm_free(map->pool, q);
	return 0;
}

/*! Clears the given map */
EXPORT void map_clear(map_t *map)
{
	if (map->root) {
		cbt_traverse_delete(map, map->root);
	}
	map->root = NULL;
}

/*! Calls callback for all strings in map with the given prefix */
EXPORT int map_walk_prefixed(map_t *map, const char *prefix,
	int (*callback)(const char *, void *, void *), void *baton)
{
	if (!map) {
		return 0;
	}

	const uint8_t *ubytes = (void *)prefix;
	const size_t ulen = strlen(prefix);
	uint8_t *p = map->root;
	uint8_t *top = p;
	cb_data_t *data = NULL;

	if (p == NULL) {
		return 0;
	}

	while (ref_is_internal(p)) {
		cb_node_t *q = ref_get_internal(p);
		uint8_t c = 0;
		int direction;

		if (q->byte < ulen) {
			c = ubytes[q->byte];
		}
		direction = (1 + (q->otherbits | c)) >> 8;

		p = q->child[direction];
		if (q->byte < ulen) {
			top = p;
		}
	}

	data = (cb_data_t *)p;
	if (strlen((const char *)data->key) < ulen || memcmp(data->key, prefix, ulen) != 0) {
		return 0; /* No strings match */
	}

	return cbt_traverse_prefixed(top, callback, baton);
}
