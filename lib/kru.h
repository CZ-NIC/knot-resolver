/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ALIGNED_CPU_CACHE _Alignas(64)

// An unsigned integral type used for prices, blocking occurs when sum of prices overflows.
// Greater than 16-bit type enables randomized fractional incrementing as the internal counters are still 16-bit.
// Exponential decay always uses randomized rounding on 32 bits.
typedef uint32_t kru_price_t;

#define KRU_PRICE_BITS (8 * sizeof(kru_price_t))

// maximal allowed sum of prices without limiting
#define KRU_LIMIT     (((kru_price_t)-1ll) - (1ll << (KRU_PRICE_BITS - 16)) + 1)

struct kru;

/// Usage: KRU.limited(...)
struct kru_api {
	/// Initialize a new KRU structure that can track roughly 2^capacity_log limited keys.
	///
	/// The kru parameter should point to a zeroed preallocated memory
	/// of size returned by get_size aligned to 64-bytes;
	/// deallocate the memory to destroy KRU.
	/// RAM: the current parametrization will use roughly 8 bytes * 2^capacity_log.
	///
	/// The number of non-limited keys is basically arbitrary,
	/// but the total sum of prices per tick (for queries returning false)
	/// should not get over roughly 2^(capacity_log + 15).
	/// Note that the _multi variants increase these totals
	/// by tracking multiple keys in a single query.
	///
	/// Returns false if kru is NULL or other failure occurs.
	bool (*initialize)(struct kru *kru, int capacity_log, kru_price_t max_decay); // TODO describe max_decay and some other args below

	/// Calculate size of the KRU structure.
	size_t (*get_size)(int capacity_log);

	/// Determine if a key should get limited (and update the KRU).
	/// key needs to be aligned to a multiple of 16 bytes.
	bool (*limited)(struct kru *kru, uint32_t time_now, uint8_t key[static const 16], kru_price_t price);

	/// Multiple queries. Returns OR of answers. Updates KRU only if no query is blocked (and possibly on race).
	bool (*limited_multi_or)(struct kru *kru, uint32_t time_now, uint8_t **keys, kru_price_t *prices, size_t queries_cnt);

	/// Same as previous but without short-circuit evaluation; for time measurement purposes.
	bool (*limited_multi_or_nobreak)(struct kru *kru, uint32_t time_now, uint8_t ** keys, kru_price_t *prices, size_t queries_cnt);

	/// Multiple queries based on different prefixes of a single key.
	/// Returns a prefix (value in prefixes) on which the key is blocked, or zero if all queries passed.
	/// Updates KRU only if no query is blocked, unless a race condition occurs --
	/// in such a case all longer prefixes might have been updated.
	/// The key of i-th query consists of prefixes[i] bits of key, prefixes[i], and namespace.
	/// If zero is returned, *max_load_out is set to the maximum of final values of the involved counters normalized to the limit 2^16.
	uint8_t (*limited_multi_prefix_or)(struct kru *kru, uint32_t time_now,
			uint8_t namespace, uint8_t key[static 16], uint8_t *prefixes, kru_price_t *prices, size_t queries_cnt, uint16_t *max_load_out);

	/// Multiple queries based on different prefixes of a single key.
	/// Returns the maximum of final values of the involved counters normalized to the limit 2^16.
	/// Set prices to NULL to skip updating; otherwise, KRU is always updated, using maximal allowed value on overflow.
	/// The key of i-th query consists of prefixes[i] bits of key, prefixes[i], and namespace.
	uint16_t (*load_multi_prefix_max)(struct kru *kru, uint32_t time_now,
			uint8_t namespace, uint8_t key[static 16], uint8_t *prefixes, kru_price_t *prices, size_t queries_cnt);
};

// The functions are stored this way to make it easier to switch
// implementation based on detected CPU.
extern struct kru_api KRU;
extern const struct kru_api KRU_GENERIC, KRU_AVX2;
