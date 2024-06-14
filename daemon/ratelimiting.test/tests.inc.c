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

#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdatomic.h>

#include "tests/unit/test.h"
#include "libdnssec/crypto.h"
#include "libdnssec/random.h"
#include "libknot/libknot.h"
#include "contrib/openbsd/siphash.h"
#include "lib/resolve.h"

#include "lib/utils.h"
uint64_t fakeclock_now(void);
#define kr_now fakeclock_now
#include "daemon/ratelimiting.c"
#undef kr_now

#define RRL_TABLE_SIZE     (1 << 20)
#define RRL_INSTANT_LIMIT  (1 << 8)
#define RRL_RATE_LIMIT     (1 << 17)
#define RRL_BASE_PRICE     (KRU_LIMIT / RRL_INSTANT_LIMIT)

// Accessing RRL configuration of INSTANT/RATE limits for V4/V6 and specific prefix.
#define LIMIT(type, Vx, prefix) (RRL_MULT(Vx, prefix) * RRL_ ## type ## _LIMIT)

#define RRL_CONFIG(Vx, name) Vx ## _ ## name
#define RRL_MULT(Vx, prefix) get_mult(RRL_CONFIG(Vx, PREFIXES), RRL_CONFIG(Vx, RATE_MULT), RRL_CONFIG(Vx, PREFIXES_CNT), prefix)
static inline kru_price_t get_mult(uint8_t prefixes[], kru_price_t mults[], size_t cnt, uint8_t wanted_prefix) {
	for (size_t i = 0; i < cnt; i++)
		if (prefixes[i] == wanted_prefix)
			return mults[i];
	assert(0);
	return 0;
}

// Instant limits and rate limits per msec.
#define INST(Vx, prefix)  LIMIT(INSTANT, Vx, prefix)
#define RATEM(Vx, prefix) (LIMIT(RATE, Vx, prefix) / 1000)

/* Fix seed for randomness in RLL module. Change if improbable collisions arise. (one byte) */
#define RRL_SEED_GENERIC  1
#define RRL_SEED_AVX2     1

#define assert_int_between(VAL, MIN, MAX, ...) \
	if (((MIN) > (VAL)) || ((VAL) > (MAX))) { \
		fprintf(stderr, __VA_ARGS__); fprintf(stderr, ": %d <= %d <= %d, ", MIN, VAL, MAX); \
		assert_true(false); }

struct kru_generic {
	SIPHASH_KEY hash_key;
	// ...
};
struct kru_avx2 {
	_Alignas(32) char hash_key[48];
	// ...
};

/* Override time. */
uint64_t fakeclock_tick = 0;
uint64_t fakeclock_start = 0;

void fakeclock_init(void)
{
	fakeclock_start = kr_now();
	fakeclock_tick = 0;
}

uint64_t fakeclock_now(void)
{
	return fakeclock_start + fakeclock_tick;
}

static void test_rrl(void **state) {
	dnssec_crypto_init();
	fakeclock_init();

	/* create rrl table */
	const char *tmpdir = test_tmpdir_create();
	char mmap_file[64];
	stpcpy(stpcpy(mmap_file, tmpdir), "/rrl");
	ratelimiting_init(mmap_file, RRL_TABLE_SIZE, RRL_INSTANT_LIMIT, RRL_RATE_LIMIT, 100);

	if (KRU.initialize == KRU_GENERIC.initialize) {
		struct kru_generic *kru = (struct kru_generic *) ratelimiting->kru;
		memset(&kru->hash_key, RRL_SEED_GENERIC, sizeof(kru->hash_key));
	} else if (KRU.initialize == KRU_AVX2.initialize) {
		struct kru_avx2 *kru = (struct kru_avx2 *) ratelimiting->kru;
		memset(&kru->hash_key, RRL_SEED_AVX2, sizeof(kru->hash_key));
	} else {
		assert(0);
	}

	the_tests(state);

	ratelimiting_deinit();
	test_tmpdir_remove(tmpdir);
	dnssec_crypto_cleanup();
}

static void test_rrl_generic(void **state) {
	KRU = KRU_GENERIC;
	test_rrl(state);
}

static void test_rrl_avx2(void **state) {
	KRU = KRU_AVX2;
	test_rrl(state);
}

int main(int argc, char *argv[])
{
	assert(KRU_GENERIC.initialize != KRU_AVX2.initialize);
	if (KRU.initialize == KRU_AVX2.initialize) {
		const UnitTest tests[] = {
			unit_test(test_rrl_generic),
			unit_test(test_rrl_avx2)
		};
		return run_tests(tests);
	} else {
		const UnitTest tests[] = {
			unit_test(test_rrl_generic)
		};
		return run_tests(tests);
	}
}
