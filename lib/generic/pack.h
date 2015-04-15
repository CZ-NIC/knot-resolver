/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
 *
 *  Example usage:
 *
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
 *      pack_clear(pack);
 *
 * \addtogroup generics
 * @{
 */

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
/** Free and the pack. */
#define pack_clear(pack) \
	array_clear(pack)
/** @internal Clear pack with a callback. */
#define pack_clear_mm(pack, free, baton) \
	array_clear_mm(pack, array_std_free, baton)
/** Incrementally reserve objects in the pack. */
#define pack_reserve(pack, objs_count, objs_len) \
	pack_reserve_mm((pack), (objs_count), (objs_len), array_std_reserve, NULL)
/** @internal Reservation with a callback. */
#define pack_reserve_mm(pack, objs_count, objs_len, reserve, baton) \
	array_reserve_mm((pack), (pack).len + (sizeof(pack_objlen_t)*(objs_count) + (objs_len)), (reserve), (baton))
/** Return pointer to first packed object. */
#define pack_head(pack) \
	&((pack).at[0])
/** Return pack end pointer. */
#define pack_tail(pack) \
	&((pack).at[(pack).len])

/** Return packed object length. */
static inline pack_objlen_t pack_obj_len(uint8_t *it)
{
	pack_objlen_t len = 0;
	memcpy(&len, it, sizeof(len));
	return len;
}

/** Return packed object value. */
static inline uint8_t *pack_obj_val(uint8_t *it)
{
	return it + sizeof(pack_objlen_t);
}

/** Return pointer to next packed object. */
static inline uint8_t *pack_obj_next(uint8_t *it)
{
	return pack_obj_val(it) + pack_obj_len(it);
}

/** Push object to the end of the pack
  * @return 0 on success, negative number on failure
  */
static inline int pack_obj_push(pack_t *pack, const uint8_t *obj, pack_objlen_t len)
{
	uint8_t *endp = pack_tail(*pack);
	size_t packed_len = len + sizeof(len);
	if (pack == NULL || (pack->len + packed_len) > pack->cap) {
		return -1;
	}

	memcpy(endp, (char *)&len, sizeof(len));
	memcpy(endp + sizeof(len), obj, len);
	pack->len += packed_len;
	return 0;
}

#ifdef __cplusplus
}
#endif

/** @} */
