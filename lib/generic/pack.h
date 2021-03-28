/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file pack.h
 * @brief A length-prefixed list of objects, also an array list.
 *
 * Each object is prefixed by item length, unlike array this structure
 * permits variable-length data. It is also equivallent to forward-only list
 * backed by an array.
 *
 * @note Maximum object size is 2^16 bytes, see  ::pack_objlen_t
 * @todo If some mistake happens somewhere, the access may end up in an infinite loop.
 *       (equality comparison on pointers)
 *
 * # Example usage:
 *
 * @code{.c}
 *      pack_t pack;
 *      pack_init(pack);
 *
 *      // Reserve 2 objects, 6 bytes total
 *      pack_reserve(pack, 2, 4 + 2);
 *
 *      // Push 2 objects
 *      pack_obj_push(pack, U8("jedi"), 4)
 *      pack_obj_push(pack, U8("\xbe\xef"), 2);
 *
 *      // Iterate length-value pairs
 *      uint8_t *it = pack_head(pack);
 *      while (it != pack_tail(pack)) {
 *          uint8_t *val = pack_obj_val(it);
 *          it = pack_obj_next(it);
 *      }
 *
 *      // Remove object
 *      pack_obj_del(pack, U8("jedi"), 4);
 *
 *      pack_clear(pack);
 * @endcode
 *
 * \addtogroup generics
 * @{
 */

#pragma once

#include <stdint.h>
#include <string.h>
#include "array.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Packed object length type. */
typedef uint16_t pack_objlen_t;

/** Pack is defined as an array of bytes */
typedef array_t(uint8_t) pack_t;

/** Zero-initialize the pack. */
#define pack_init(pack) \
	array_init(pack)

/** Make the pack empty and free pointed-to memory (plain malloc/free). */
#define pack_clear(pack) \
	array_clear(pack)

/** Make the pack empty and free pointed-to memory.
 * Mempool usage: pass mm_free and a knot_mm_t* . */
#define pack_clear_mm(pack, free, baton) \
	array_clear_mm((pack), (free), (baton))

/** Reserve space for *additional* objects in the pack (plain malloc/free).
 * @return 0 if success, <0 on failure */
#define pack_reserve(pack, objs_count, objs_len) \
	pack_reserve_mm((pack), (objs_count), (objs_len), array_std_reserve, NULL)

/** Reserve space for *additional* objects in the pack.
 * Mempool usage: pass kr_memreserve and a knot_mm_t* .
 * @return 0 if success, <0 on failure */
#define pack_reserve_mm(pack, objs_count, objs_len, reserve, baton) \
	array_reserve_mm((pack), (pack).len + (sizeof(pack_objlen_t)*(objs_count) + (objs_len)), (reserve), (baton))

/** Return pointer to first packed object.
 *
 * Recommended way to iterate:
 *   for (uint8_t *it = pack_head(pack); it != pack_tail(pack); it = pack_obj_next(it))
 */
#define pack_head(pack) \
	((pack).len > 0 ? &((pack).at[0]) : NULL)

/** Return pack end pointer. */
#define pack_tail(pack) \
	((pack).len > 0 ? &((pack).at[(pack).len]) : NULL)

/** Return packed object length. */
static inline pack_objlen_t pack_obj_len(uint8_t *it)
{
	pack_objlen_t len = 0;
	if (it != NULL)
		memcpy(&len, it, sizeof(len));
	return len;
}

/** Return packed object value. */
static inline uint8_t *pack_obj_val(uint8_t *it)
{
	if (!kr_assume(it))
		return NULL;
	return it + sizeof(pack_objlen_t);
}

/** Return pointer to next packed object. */
static inline uint8_t *pack_obj_next(uint8_t *it)
{
	if (!kr_assume(it))
		return NULL;
	return pack_obj_val(it) + pack_obj_len(it);
}

/** Return pointer to the last packed object. */
static inline uint8_t *pack_last(pack_t pack)
{
	if (pack.len == 0)
		return NULL;
	uint8_t *it = pack_head(pack);
	uint8_t *tail = pack_tail(pack);
	while (true) {
		uint8_t *next = pack_obj_next(it);
		if (next == tail)
			return it;
		it = next;
	}
}

/** Push object to the end of the pack
  * @return 0 on success, negative number on failure
  */
static inline int pack_obj_push(pack_t *pack, const uint8_t *obj, pack_objlen_t len)
{
	if (!kr_assume(pack && obj))
		return kr_error(EINVAL);
	size_t packed_len = len + sizeof(len);
	if (pack->len + packed_len > pack->cap)
		return kr_error(ENOSPC);

	uint8_t *endp = pack->at + pack->len;
	memcpy(endp, (char *)&len, sizeof(len));
	memcpy(endp + sizeof(len), obj, len);
	pack->len += packed_len;
	return 0;
}

/** Returns a pointer to packed object.
  * @return pointer to packed object or NULL
  */
static inline uint8_t *pack_obj_find(pack_t *pack, const uint8_t *obj, pack_objlen_t len)
{
	if (!pack || !kr_assume(obj))
		return NULL;
	uint8_t *endp = pack_tail(*pack);
	uint8_t *it = pack_head(*pack);
	while (it != endp) {
		uint8_t *val = pack_obj_val(it);
		if (pack_obj_len(it) == len && memcmp(obj, val, len) == 0)
			return it;
		it = pack_obj_next(it);
	}
	return NULL;
}

/** Delete object from the pack
  * @return 0 on success, negative number on failure
  */
static inline int pack_obj_del(pack_t *pack, const uint8_t *obj, pack_objlen_t len)
{
	if (!pack || !kr_assume(obj))
		return kr_error(EINVAL);
	uint8_t *endp = pack_tail(*pack);
	uint8_t *it = pack_obj_find(pack, obj, len);
	if (it) {
		size_t packed_len = len + sizeof(len);
		memmove(it, it + packed_len, endp - it - packed_len);
		pack->len -= packed_len;
		return 0;
	}
	return -1;
}

/** Clone a pack, replacing destination pack; (*dst == NULL) is valid input.
 * @return kr_error(ENOMEM) on allocation failure. */
static inline int pack_clone(pack_t **dst, const pack_t *src, knot_mm_t *pool)
{
	if (!kr_assume(dst && src))
		return kr_error(EINVAL);
	/* Get a valid pack_t. */
	if (!*dst) {
		*dst = mm_alloc(pool, sizeof(pack_t));
		if (!*dst) return kr_error(ENOMEM);
		pack_init(**dst);
		/* Clone data only if needed */
		if (src->len == 0) return kr_ok();
	}
	/* Replace the contents of the pack_t. */
	int ret = array_reserve_mm(**dst, src->len, kr_memreserve, pool);
	if (ret < 0) {
		return kr_error(ENOMEM);
	}
	memcpy((*dst)->at, src->at, src->len);
	(*dst)->len = src->len;
	return kr_ok();
}

#ifdef __cplusplus
}
#endif

/** @} */
