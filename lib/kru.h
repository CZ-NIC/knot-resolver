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
#include <assert.h>

#define ALIGNED_CPU_CACHE _Alignas(64)

// An unsigned integral type used for prices, limiting occurs when sum of prices overflows.
// Greater than 16-bit type enables randomized fractional incrementing as the internal counters are still 16-bit.
// Exponential decay always uses randomized rounding on 32 bits.
typedef uint32_t kru_price_t;

typedef uint64_t kru_hash_t;

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
	/// The max_decay parameter sets maximal decrease of a counter per a time_now tick,
	/// which occurs when the original value was just under the limit.
	/// I.e. the value KRU_LIMIT will be lowered to (KRU_LIMIT - max_decay);
	/// in general, the value is multiplied by (KRU_LIMIT - max_decay)/KRU_LIMIT each time_now tick
	/// (typically time_now counts milliseconds).
	///
	/// Returns false if kru is NULL or other failure occurs.
	bool (*initialize)(struct kru *kru, int capacity_log, kru_price_t max_decay);

	/// Calculate size of the KRU structure.
	size_t (*get_size)(int capacity_log);

	/// Verify that given KRU structure expects just memory of the given size;
	/// it accesses just the first size bytes of kru.
	/// If false is returned, the memory is corrupted and calling other methods may cause SIGSEGV.
	bool (*check_size)(struct kru *kru, size_t size);

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
	/// The key of i-th query consists of prefixes[i] bits of key, prefixes[i], and namespace;
	/// the specific namespace values may be arbitrary,
	/// they just extend the keys to allow storing different noncolliding sets of them in the same table (such as IPv4 and IPv6).
	/// If zero is returned, *max_load_out (unless NULL) is set to
	/// the maximum of final values of the involved counters normalized to the limit 2^16.
	uint8_t (*limited_multi_prefix_or)(struct kru *kru, uint32_t time_now,
			uint8_t namespace, uint8_t key[static 16], uint8_t *prefixes, kru_price_t *prices, size_t queries_cnt, uint16_t *max_load_out);

	/// Multiple queries based on different prefixes of a single key.
	/// Returns the maximum of final values of the involved counters normalized to the limit 2^16
	/// and stores the corresponding prefix (value in prefixes) to *prefix_out (unless NULL).
	/// Set prices to NULL to skip updating; otherwise, KRU is always updated, using maximal allowed value on overflow.
	/// The key of i-th query consists of prefixes[i] bits of key, prefixes[i], and namespace; as above.
	uint16_t (*load_multi_prefix_max)(struct kru *kru, uint32_t time_now,
			uint8_t namespace, uint8_t key[static 16], uint8_t *prefixes, kru_price_t *prices, size_t queries_cnt, uint8_t *prefix_out);


	/// Multiple queries based on different prefixes of a single key.
	/// Stores the final values of the involved counters normalized to the limit 2^16 to *loads_out (unless NULL).
	/// Set prices to NULL to skip updating; otherwise, KRU is always updated, using maximal allowed value on overflow.
	/// The key of i-th query consists of prefixes[i] bits of key, prefixes[i], and namespace; as above.
	void (*load_multi_prefix)(struct kru *kru, uint32_t time_now,
			uint8_t namespace, uint8_t key[static 16], uint8_t *prefixes, kru_price_t *prices, size_t queries_cnt, uint16_t *loads_out);

	// TODO
	/// Compute 64-bit hash to be used in load_hash.
	/// The key need not to be aligned as we use always unoptimized variant here.
	kru_hash_t (*hash_bytes)(struct kru *kru, uint8_t *key, size_t key_size);
	uint16_t (*load_hash)(struct kru *kru, uint32_t time_now, kru_hash_t hash, kru_price_t price);
};

// The functions are stored this way to make it easier to switch
// implementation based on detected CPU.
extern struct kru_api KRU;
extern const struct kru_api KRU_GENERIC, KRU_AVX2;

/// Return whether we're using optimized variant right now.
static inline bool kru_using_avx2(void)
{
	bool result = (KRU.initialize == KRU_AVX2.initialize);
	assert(result || KRU.initialize == KRU_GENERIC.initialize);
	return result;
}
