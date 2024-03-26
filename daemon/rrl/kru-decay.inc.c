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

#include <math.h>

/// Parametrization for speed of decay.
struct decay_config {
	/// Bit shift per tick, fractional
	double shift_bits;

	/// Ticks to get zero loads
	uint32_t max_ticks;

	uint32_t mult_cache[32];
};

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
