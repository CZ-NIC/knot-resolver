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

/*
KRU estimates recently pricey inputs

Authors of the simple agorithm (without aging, multi-choice, etc.):
  Metwally, D. Agrawal, and A. E. Abbadi.
  Efficient computation of frequent and top-k elements in data streams.
  In International Conference on Database Theory, 2005.

With TABLE_COUNT > 1 we're improving reliability by utilizing the property that
longest buckets (cache-lines) get very much shortened, already by providing two choices:
  https://en.wikipedia.org/wiki/2-choice_hashing

The point is to answer point-queries that estimate if the item has been heavily used recently.
To give more weight to recent usage, we use aging via exponential decay (simple to compute).
That has applications for garbage collection of cache and various limiting scenario
(excessive rate, traffic, CPU, maybe RAM).

### Choosing parameters

Size (`loads_bits` = log2 length):
 - The KRU takes 64 bytes * length * TABLE_COUNT + some small constants.
   As TABLE_COUNT == 2 and loads_bits = capacity_log >> 4, we get capacity * 8 Bytes.
 - The length should probably be at least something like the square of the number of utilized CPUs.
   But this most likely won't be a limiting factor.
*/

#include <stdlib.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <math.h>

#include "./kru.h"
#include "contrib/ucw/lib.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"
#if USE_AES
	/// 4-8 rounds should be an OK choice, most likely.
	#define AES_ROUNDS 4
#endif //#else
// use SipHash also for variable-length keys with otherwise optimized variant
	#include "contrib/openbsd/siphash.h"

	/// 1,3 should be OK choice, probably.
	enum {
		SIPHASH_RC = 1,
		SIPHASH_RF = 3,
	};
//#endif

#if USE_AVX2 || USE_SSE41 || USE_AES
	#include <immintrin.h>
	#include <x86intrin.h>
#endif

/// Block of loads sharing the same time, so that we're more space-efficient.
/// It's exactly a single cache line.
struct load_cl {
	ALIGNED_CPU_CACHE
	_Atomic uint32_t time;
	#define LOADS_LEN 15
	uint16_t ids[LOADS_LEN];
	uint16_t loads[LOADS_LEN];
};
static_assert(64 == sizeof(struct load_cl), "bad size of struct load_cl");

/// Parametrization for speed of decay.
struct decay_config {
	/// Bit shift per tick, fractional
	double shift_bits;

	/// Ticks to get zero loads
	uint32_t max_ticks;

	uint32_t mult_cache[32];
};

struct kru {
#if USE_AES
	/// Hashing secret.  Random but shared by all users of the table.
	/// Let's not make it too large, so that header fits into 64 Bytes.
	_Alignas(32) char hash_key[48];
#else
	/// Hashing secret.  Random but shared by all users of the table.
	SIPHASH_KEY hash_key;
#endif
	struct decay_config decay;

	/// Length of `loads_cls`, stored as binary logarithm.
	uint32_t loads_bits;

	#define TABLE_COUNT 2
	/// These are read-write.  Each struct has exactly one cache line.
	struct load_cl load_cls[][TABLE_COUNT];
};

inline static uint64_t rand_bits(unsigned int bits)
{
	static _Thread_local uint64_t state = 3723796604792068981ull;
	const uint64_t prime1 = 11737314301796036329ull;
	const uint64_t prime2 = 3107264277052274849ull;
	state = prime1 * state + prime2;
	//return state & ((1 << bits) - 1);
	return state >> (64 - bits);
}

static inline void decay_initialize(struct decay_config *decay, kru_price_t max_decay)
{
	decay->shift_bits = log2(KRU_LIMIT - 1) - log2(KRU_LIMIT - 1 - max_decay);
	decay->max_ticks = 18 / decay->shift_bits;

	decay->mult_cache[0] = 0;  // not used
	for (size_t ticks = 1; ticks < sizeof(decay->mult_cache) / sizeof(*decay->mult_cache); ticks++) {
		decay->mult_cache[ticks] = exp2(32 - decay->shift_bits * ticks) + 0.5;
	}
}

/// Catch up the time drift with configurably slower decay.
static inline void update_time(struct load_cl *l, const uint32_t time_now,
			const struct decay_config *decay)
{
	uint32_t ticks;
	uint32_t time_last = atomic_load_explicit(&l->time, memory_order_relaxed);
	do {
		ticks = time_now - time_last;
		if (__builtin_expect(!ticks, true)) // we optimize for time not advancing
			return;
		// We accept some desynchronization of time_now (e.g. from different threads).
		if (ticks > (uint32_t)-1024)
			return;
	} while (!atomic_compare_exchange_weak_explicit(&l->time, &time_last, time_now, memory_order_relaxed, memory_order_relaxed));

	// If we passed here, we have acquired a time difference we are responsibe for.

	// Don't bother with complex computations if lots of ticks have passed. (little to no speed-up)
	if (ticks > decay->max_ticks) {
		memset(l->loads, 0, sizeof(l->loads));
		return;
	}

	uint32_t mult;
	if (__builtin_expect(ticks < sizeof(decay->mult_cache) / sizeof(*decay->mult_cache), 1)) {
		mult = decay->mult_cache[ticks];
	} else {
		mult = exp2(32 - decay->shift_bits * ticks) + 0.5;
	}

	for (int i = 0; i < LOADS_LEN; ++i) {
		// We perform decay for the acquired time difference; decays from different threads are commutative.
		_Atomic uint16_t *load_at = (_Atomic uint16_t *)&l->loads[i];
		uint16_t l1, load_orig = atomic_load_explicit(load_at, memory_order_relaxed);
		const uint16_t rnd = rand_bits(16);
		do {
			uint64_t m = (((uint64_t)load_orig << 16)) * mult;
			m = (m >> 32) + ((m >> 31) & 1);
			l1 = (m >> 16) + (rnd < (uint16_t)m);
		} while (!atomic_compare_exchange_weak_explicit(load_at, &load_orig, l1, memory_order_relaxed, memory_order_relaxed));
	}
}

static_assert(LOADS_LEN == 15 && TABLE_COUNT == 2, "");
// So, the pair of cache lines hold up to 2*15 elements.
// Let's say that we can reliably store 16 = 1 << (1+3).
// (probably more but certainly not 1 << 5)
enum { LOADS_CAPACITY_SHIFT = 1 + 3 };

/// Convert capacity_log to loads_bits
static inline int32_t capacity2loads(int capacity_log)
{
	int loads_bits = capacity_log - LOADS_CAPACITY_SHIFT;
	// Let's behave reasonably for weird capacity_log values.
	return loads_bits > 0 ? loads_bits : 1;
}

static size_t kru_get_size(int capacity_log)
{
	uint32_t loads_bits = capacity2loads(capacity_log);
	if (8 * sizeof(kru_hash_t) < TABLE_COUNT * loads_bits
				+ 8 * sizeof(((struct kru *)0)->load_cls[0]->ids[0])) {
		assert(false);
		return 0;
	}

	return offsetof(struct kru, load_cls)
		    + sizeof(struct load_cl) * TABLE_COUNT * (1 << loads_bits);
}

static bool kru_check_size(struct kru *kru, size_t size) {
	if (size < sizeof(struct kru)) return false;
	return size == kru_get_size(kru->loads_bits + LOADS_CAPACITY_SHIFT);
}

static bool kru_initialize(struct kru *kru, int capacity_log, kru_price_t max_decay)
{
	if (!kru) {
		return false;
	}

	uint32_t loads_bits = capacity2loads(capacity_log);
	if (8 * sizeof(kru_hash_t) < TABLE_COUNT * loads_bits
				+ 8 * sizeof(((struct kru *)0)->load_cls[0]->ids[0])) {
		assert(false);
		return false;
	}

	kru->loads_bits = loads_bits;

	if (dnssec_random_buffer((uint8_t *)&kru->hash_key, sizeof(kru->hash_key)) != DNSSEC_EOK) {
		return false;
	}

	decay_initialize(&kru->decay, max_decay);

	return true;
}

struct query_ctx {
	struct load_cl *l[TABLE_COUNT];
	uint32_t time_now;
	kru_price_t price;
	uint16_t price16;
	uint32_t limit16;  // 2^16 has to be representable
	uint16_t id;
	uint16_t final_load_value;  // set by kru_limited_update if not blocked
	uint16_t *load;
};

/// Phase 1/3 of a query -- hash, prefetch, ctx init. Based on one 16-byte key.
static inline void kru_limited_prefetch(struct kru *kru, uint32_t time_now, uint8_t key[static 16], kru_price_t price, struct query_ctx *ctx)
{
	// Obtain hash of *buf.
	kru_hash_t hash;
	static_assert(sizeof(kru_hash_t) * 8 <= 64);
#if !USE_AES
	hash = SipHash(&kru->hash_key, SIPHASH_RC, SIPHASH_RF, key, 16);
#else
	{
		__m128i h; /// hashing state
		h = _mm_load_si128((__m128i *)key);
		// Now do the the hashing itself.
		__m128i *aes_key = (void*)kru->hash_key;
		for (int i = 0; i < AES_ROUNDS; ++i) {
			int key_id = i % (sizeof(kru->hash_key) / sizeof(__m128i));
			h = _mm_aesenc_si128(h, _mm_load_si128(&aes_key[key_id]));
		}
		memcpy(&hash, &h, sizeof(hash));
	}
#endif

	// Choose the cache-lines to operate on
	const uint32_t loads_mask = (1 << kru->loads_bits) - 1;
	// Fetch the two cache-lines in parallel before we really touch them.
	for (int li = 0; li < TABLE_COUNT; ++li) {
		struct load_cl * const l = &kru->load_cls[hash & loads_mask][li];
		__builtin_prefetch(l, 0); // hope for read-only access
		hash >>= kru->loads_bits;
		ctx->l[li] = l;
	}

	ctx->time_now = time_now;
	ctx->price = price;
	ctx->id = hash;
}

/// Phase 1/3 of a query -- hash, prefetch, ctx init. Based on a bit prefix of one 16-byte key.
static inline void kru_limited_prefetch_prefix(struct kru *kru, uint32_t time_now, uint8_t namespace, uint8_t key[static 16], uint8_t prefix, kru_price_t price, struct query_ctx *ctx)
{
	// Obtain hash of *buf.
	kru_hash_t hash;
	static_assert(sizeof(kru_hash_t) * 8 <= 64);

#if !USE_AES
	{
		const int rc = SIPHASH_RC, rf = SIPHASH_RF;

		// Hash prefix of key, prefix size, and namespace together.
		SIPHASH_CTX hctx;
		SipHash_Init(&hctx, &kru->hash_key);
		SipHash_Update(&hctx, rc, rf, &namespace, sizeof(namespace));
		SipHash_Update(&hctx, rc, rf, &prefix, sizeof(prefix));
		SipHash_Update(&hctx, rc, rf, key, prefix / 8);
		if (prefix % 8) {
			const uint8_t masked_byte = key[prefix / 8] & (0xFF00 >> (prefix % 8));
			SipHash_Update(&hctx, rc, rf, &masked_byte, 1);
		}
		hash = SipHash_End(&hctx, rc, rf);
	}
#else
	{

		__m128i h; /// hashing state
		h = _mm_load_si128((__m128i *)key);

		{ // Keep only the prefix.
			const uint8_t p = prefix;

			// Prefix mask (1...0) -> little endian byte array (0x00 ... 0x00 0xFF ... 0xFF).
			__m128i mask = _mm_set_epi64x(
					(p < 64 ? (p == 0 ? 0 : (uint64_t)-1 << (64 - p)) : (uint64_t)-1),  // higher 64 bits (1...) -> second half of byte array (... 0xFF)
					(p <= 64 ? 0 : (uint64_t)-1 << (128 - p)));                 // lower  64 bits (...0) ->  first half of byte array (0x00 ...)

			// Swap mask endianness (0x11 ... 0x11 0x00 ... 0x00).
			mask = _mm_shuffle_epi8(mask,
					_mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));

			// Apply mask.
			h = _mm_and_si128(h, mask);
		}

		// Now do the the hashing itself.
		__m128i *aes_key = (void*)kru->hash_key;
		{
			// Mix namespace and prefix size into the first aes key.
			__m128i aes_key1 = _mm_insert_epi16(_mm_load_si128(aes_key), (namespace << 8) | prefix, 0);
			h = _mm_aesenc_si128(h, aes_key1);
		}
		for (int j = 1; j < AES_ROUNDS; ++j) {
			int key_id = j % (sizeof(kru->hash_key) / sizeof(__m128i));
			h = _mm_aesenc_si128(h, _mm_load_si128(&aes_key[key_id]));
		}
		memcpy(&hash, &h, sizeof(hash));
	}
#endif

	// Choose the cache-lines to operate on
	const uint32_t loads_mask = (1 << kru->loads_bits) - 1;
	// Fetch the two cache-lines in parallel before we really touch them.
	for (int li = 0; li < TABLE_COUNT; ++li) {
		struct load_cl * const l = &kru->load_cls[hash & loads_mask][li];
		__builtin_prefetch(l, 0); // hope for read-only access
		hash >>= kru->loads_bits;
		ctx->l[li] = l;
	}

	ctx->time_now = time_now;
	ctx->price = price;
	ctx->id = hash;
}

static kru_hash_t kru_hash_bytes(struct kru *kru, uint8_t *key, size_t key_size) {
	// Obtain hash of *buf.
	kru_hash_t hash;
	static_assert(sizeof(kru_hash_t) * 8 <= 64);

	// We use SipHash even for otherwise optimized KRU variant, which has diffent type of hash_key.
	static_assert(sizeof(kru->hash_key) >= sizeof(SIPHASH_KEY));
	SIPHASH_KEY *hash_key = (void *)&kru->hash_key;

	hash = SipHash(hash_key, SIPHASH_RC, SIPHASH_RF, key, key_size);

	return hash;
}

/// Phase 1/3 of a query -- hash, prefetch, ctx init. Based on arbitrary-length byte-stream.
static inline void kru_limited_prefetch_hash(struct kru *kru, uint32_t time_now, kru_hash_t hash, kru_price_t price, struct query_ctx *ctx)
{
	// Choose the cache-lines to operate on
	const uint32_t loads_mask = (1 << kru->loads_bits) - 1;
	// Fetch the two cache-lines in parallel before we really touch them.
	for (int li = 0; li < TABLE_COUNT; ++li) {
		struct load_cl * const l = &kru->load_cls[hash & loads_mask][li];
		__builtin_prefetch(l, 0); // hope for read-only access
		hash >>= kru->loads_bits;
		ctx->l[li] = l;
	}

	ctx->time_now = time_now;
	ctx->price = price;
	ctx->id = hash;
}

/// Phase 2/3 of a query -- returns answer with no state modification (except update_time).
static inline bool kru_limited_fetch(struct kru *kru, struct query_ctx *ctx)
{
	// Compute 16-bit limit and price.
	// For 32-bit prices we assume that a 16-bit load value corresponds
	// to the 32-bit value extended by low-significant ones and the limit is 2^32 (without ones).
	// The 16-bit price is thus rounded up for the comparison with limit,
	// but rounded probabilistically for rising the load.
	{
		const int fract_bits = 8 * sizeof(ctx->price) - 16;
		const kru_price_t price = ctx->price;
		const kru_price_t fract = price & ((((kru_price_t)1) << fract_bits) - 1);

		ctx->price16 = price >> fract_bits;
		ctx->limit16 = (1<<16) - ctx->price16;

		if ((fract_bits > 0) && (fract > 0)) {
			ctx->price16 += (rand_bits(fract_bits) < fract);
			ctx->limit16--;
		}
	}

	for (int li = 0; li < TABLE_COUNT; ++li) {
		update_time(ctx->l[li], ctx->time_now, &kru->decay);
	}

	const uint16_t id = ctx->id;

	// Find matching element.  Matching 16 bits in addition to loads_bits.
	ctx->load = NULL;
#if !USE_AVX2
	for (int li = 0; li < TABLE_COUNT; ++li)
		for (int i = 0; i < LOADS_LEN; ++i)
			if (ctx->l[li]->ids[i] == id) {
				ctx->load = &ctx->l[li]->loads[i];
				goto load_found;
			}
#else
	const __m256i id_v = _mm256_set1_epi16(id);
	for (int li = 0; li < TABLE_COUNT; ++li) {
		static_assert(LOADS_LEN == 15 && sizeof(ctx->l[li]->ids[0]) == 2, "");
		// unfortunately we can't use aligned load here
		__m256i ids_v = _mm256_loadu_si256((__m256i *)((uint16_t *)ctx->l[li]->ids - 1));
		__m256i match_mask = _mm256_cmpeq_epi16(ids_v, id_v);
		if (_mm256_testz_si256(match_mask, match_mask))
			continue; // no match of id
		int index = _bit_scan_reverse(_mm256_movemask_epi8(match_mask)) / 2 - 1;
		// there's a small possibility that we hit equality only on the -1 index
		if (index >= 0) {
			ctx->load = &ctx->l[li]->loads[index];
			goto load_found;
		}
	}
#endif

	ctx->final_load_value = 0;
	return false;

load_found:;
	ctx->final_load_value = *ctx->load;
	return (ctx->final_load_value >= ctx->limit16);
}

/// Phase 3/3 of a query -- state update, return value overrides previous answer in case of race.
/// Not needed if blocked by fetch phase. If overflow_update is activated, false is always returned.
static inline bool kru_limited_update(struct kru *kru, struct query_ctx *ctx, bool overflow_update)
{
	_Atomic uint16_t *load_at;
	if (!ctx->load) {
		// No match, so find position of the smallest load.
		int min_li = 0;
		int min_i = 0;
#if !USE_SSE41
		for (int li = 0; li < TABLE_COUNT; ++li)
			for (int i = 0; i < LOADS_LEN; ++i)
				if (ctx->l[li]->loads[i] < ctx->l[min_li]->loads[min_i]) {
					min_li = li;
					min_i = i;
				}
#else
		int min_val = 0;
		for (int li = 0; li < TABLE_COUNT; ++li) {
			// BEWARE: we're relying on the exact memory layout of struct load_cl,
			//  where the .loads array take 15 16-bit values at the very end.
			static_assert((offsetof(struct load_cl, loads) - 2) % 16 == 0,
					"bad alignment of struct load_cl::loads");
			static_assert(LOADS_LEN == 15 && sizeof(ctx->l[li]->loads[0]) == 2, "");
			__m128i *l_v = (__m128i *)((uint16_t *)ctx->l[li]->loads - 1);
			__m128i l0 = _mm_load_si128(l_v);
			__m128i l1 = _mm_load_si128(l_v + 1);
			// We want to avoid the first item in l0, so we maximize it.
			//  (but this function takes a signed integer, so -1 is the maximum)
			l0 = _mm_insert_epi16(l0, -1, 0);

			// Only one instruction can find minimum and its position,
			// and it works on 8x uint16_t.
			__m128i mp0 = _mm_minpos_epu16(l0);
			__m128i mp1 = _mm_minpos_epu16(l1);
			int min0 = _mm_extract_epi16(mp0, 0);
			int min1 = _mm_extract_epi16(mp1, 0);
			int min01, min_ix;
			if (min0 < min1) {
				min01 = min0;
				min_ix = _mm_extract_epi16(mp0, 1);
			} else {
				min01 = min1;
				min_ix = 8 + _mm_extract_epi16(mp1, 1);
			}

			if (li == 0 || min_val > min01) {
				min_li = li;
				min_i = min_ix;
				min_val = min01;
			}
		}
		// now, min_i (and min_ix) is offset by one due to alignment of .loads
		if (min_i != 0) // zero is very unlikely
			--min_i;
#endif

		ctx->l[min_li]->ids[min_i] = ctx->id;
		load_at = (_Atomic uint16_t *)&ctx->l[min_li]->loads[min_i];
	} else {
		load_at = (_Atomic uint16_t *)ctx->load;
	}

	static_assert(ATOMIC_CHAR16_T_LOCK_FREE == 2, "insufficient atomics");
	const uint16_t price = ctx->price16;
	const uint32_t limit = ctx->limit16;  // 2^16 has to be representable
	uint16_t load_orig = atomic_load_explicit(load_at, memory_order_relaxed);
	uint16_t load_new;
	do {
		if (load_orig >= limit) {
			if (overflow_update) {
				load_new = -1;
			} else {
				return true;
			}
		} else {
			load_new = load_orig + price;
		}
	} while (!atomic_compare_exchange_weak_explicit(load_at, &load_orig, load_new, memory_order_relaxed, memory_order_relaxed));

	ctx->final_load_value = load_new;
	return false;
}

static bool kru_limited_multi_or(struct kru *kru, uint32_t time_now, uint8_t **keys, kru_price_t *prices, size_t queries_cnt)
{
	struct query_ctx ctx[queries_cnt];

	for (size_t i = 0; i < queries_cnt; i++) {
		kru_limited_prefetch(kru, time_now, keys[i], prices[i], ctx + i);
	}
	for (size_t i = 0; i < queries_cnt; i++) {
		if (kru_limited_fetch(kru, ctx + i))
			return true;
	}
	bool ret = false;

	for (size_t i = 0; i < queries_cnt; i++) {
		ret |= kru_limited_update(kru, ctx + i, false);
	}

	return ret;
}

static bool kru_limited_multi_or_nobreak(struct kru *kru, uint32_t time_now, uint8_t **keys, kru_price_t *prices, size_t queries_cnt)
{
	struct query_ctx ctx[queries_cnt];
	bool ret = false;

	for (size_t i = 0; i < queries_cnt; i++) {
		kru_limited_prefetch(kru, time_now, keys[i], prices[i], ctx + i);
	}
	for (size_t i = 0; i < queries_cnt; i++) {
		if (kru_limited_fetch(kru, ctx + i))
			ret = true;
	}
	if (ret) return true;

	for (size_t i = 0; i < queries_cnt; i++) {
		if (kru_limited_update(kru, ctx + i, false))
			ret = true;
	}

	return ret;
}

static uint8_t kru_limited_multi_prefix_or(struct kru *kru, uint32_t time_now, uint8_t namespace,
                                           uint8_t key[static 16], uint8_t *prefixes, kru_price_t *prices, size_t queries_cnt, uint16_t *max_load_out)
{
	struct query_ctx ctx[queries_cnt];

	for (size_t i = 0; i < queries_cnt; i++) {
		kru_limited_prefetch_prefix(kru, time_now, namespace, key, prefixes[i], prices[i], ctx + i);
	}

	for (size_t i = 0; i < queries_cnt; i++) {
		if (kru_limited_fetch(kru, ctx + i))
			return prefixes[i];
	}

	for (int i = queries_cnt - 1; i >= 0; i--) {
		if (kru_limited_update(kru, ctx + i, false))
			return prefixes[i];
	}

	if (max_load_out) {
		*max_load_out = 0;
		for (size_t i = 0; i < queries_cnt; i++) {
			*max_load_out = MAX(*max_load_out, ctx[i].final_load_value);
		}
	}

	return 0;
}

static void kru_load_multi_prefix(struct kru *kru, uint32_t time_now, uint8_t namespace,
                                           uint8_t key[static 16], uint8_t *prefixes, kru_price_t *prices, size_t queries_cnt, uint16_t *loads_out)
{
	struct query_ctx ctx[queries_cnt];

	for (size_t i = 0; i < queries_cnt; i++) {
		kru_limited_prefetch_prefix(kru, time_now, namespace, key, prefixes[i], (prices ? prices[i] : 0), ctx + i);
	}

	for (size_t i = 0; i < queries_cnt; i++) {
		kru_limited_fetch(kru, ctx + i);
	}

	if (prices) {
		for (int i = queries_cnt - 1; i >= 0; i--) {
			kru_limited_update(kru, ctx + i, true);
		}
	}

	if (loads_out) {
		for (size_t i = 0; i < queries_cnt; i++) {
			loads_out[i] = ctx[i].final_load_value;
		}
	}
}


static uint16_t kru_load_multi_prefix_max(struct kru *kru, uint32_t time_now, uint8_t namespace,
                                           uint8_t key[static 16], uint8_t *prefixes, kru_price_t *prices, size_t queries_cnt, uint8_t *prefix_out)
{
	struct query_ctx ctx[queries_cnt];

	for (size_t i = 0; i < queries_cnt; i++) {
		kru_limited_prefetch_prefix(kru, time_now, namespace, key, prefixes[i], (prices ? prices[i] : 0), ctx + i);
	}

	for (size_t i = 0; i < queries_cnt; i++) {
		kru_limited_fetch(kru, ctx + i);
	}

	if (prices) {
		for (int i = queries_cnt - 1; i >= 0; i--) {
			kru_limited_update(kru, ctx + i, true);
		}
	}

	uint8_t prefix = 0;
	uint16_t max_load = 0;
	for (size_t i = 0; i < queries_cnt; i++) {
		if (max_load < ctx[i].final_load_value) {
			max_load = ctx[i].final_load_value;
			prefix = prefixes[i];
		}
	}
	if (prefix_out) {
		*prefix_out = prefix;
	}

	return max_load;
}

static uint16_t kru_load_hash(struct kru *kru, uint32_t time_now, kru_hash_t hash, kru_price_t price)
{
	struct query_ctx ctx;

	kru_limited_prefetch_hash(kru, time_now, hash, price, &ctx);
	kru_limited_fetch(kru, &ctx);

	if (price) {
		kru_limited_update(kru, &ctx, true);
	}

	return ctx.final_load_value;
}

/// Update limiting and return true iff it hit the limit instead.
static bool kru_limited(struct kru *kru, uint32_t time_now, uint8_t key[static 16], kru_price_t price)
{
	return kru_limited_multi_or(kru, time_now, &key, &price, 1);
}

#define KRU_API_INITIALIZER { \
	.get_size = kru_get_size, \
	.check_size = kru_check_size, \
	.initialize = kru_initialize, \
	.limited = kru_limited, \
	.limited_multi_or = kru_limited_multi_or, \
	.limited_multi_or_nobreak = kru_limited_multi_or_nobreak, \
	.limited_multi_prefix_or = kru_limited_multi_prefix_or, \
	.load_multi_prefix = kru_load_multi_prefix, \
	.load_multi_prefix_max = kru_load_multi_prefix_max, \
	.load_hash = kru_load_hash, \
	.hash_bytes = kru_hash_bytes, \
}
