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
#include <string.h>
#include <time.h>

#include "tests/unit/test.h"
#include "libdnssec/crypto.h"
#include "libdnssec/random.h"
#include "libknot/libknot.h"
#include "contrib/openbsd/siphash.h"
#include "lib/resolve.h"

#include "lib/utils.h"
uint64_t fakeclock_now(void);
#define kr_now fakeclock_now
#include "daemon/dns_tunnel_filter.c"
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

#define DNS_QUERY_TYPE_A 0x0001
#define DNS_QUERY_CLASS_IN 0x0001

typedef struct {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed)) dns_header_t;

size_t get_packet_size(uint32_t dname_length) {
	uint8_t header_size = sizeof(dns_header_t);
	uint8_t encoded_dname_size = dname_length + 1;
	uint8_t query_flags_size = 4;
	return header_size + encoded_dname_size + query_flags_size;
}

void create_domain_name(uint8_t *dname, size_t domain_length, unsigned char *sname) {
	uint8_t encoded_size = 0;
	uint8_t sname_size = 0;
	int remaining_length = domain_length - 4;

	while (remaining_length > 0) {
		uint8_t max_label_length = (remaining_length > 64) ? 64 : remaining_length;
		uint8_t label_length = 2 + (rand() % (max_label_length - 1));
		while (remaining_length - label_length == 1)
			label_length = 2 + (rand() % (max_label_length - 1));

		dname[encoded_size++] = label_length;

		for (uint8_t i = 0; i < label_length - 1; i++) {
			char rl = 'a' + (rand() % 26);
			sname[sname_size++] = rl;
			dname[encoded_size++] = rl;
		}
		sname[sname_size++] = '.';
		remaining_length -= label_length;
	}

	dname[encoded_size++] = 2;
	dname[encoded_size++] = 'c';
	dname[encoded_size++] = 'z';
	dname[encoded_size++] = 0;

	sname[sname_size++] = 'c';
	sname[sname_size++] = 'z';
	sname[sname_size++] = '.';
	sname[sname_size++] = '\0';
}

void create_dns_query(uint32_t domain_length, uint8_t *dest, unsigned char* dname) {
	size_t domain_len = domain_length + 1;

	dns_header_t *header = (dns_header_t *)dest;
	header->id = htons(0x1234);
	header->flags = htons(0x0100);
	header->qdcount = htons(1);
	header->ancount = 0;
	header->nscount = 0;
	header->arcount = 0;

	uint8_t *qname = dest + sizeof(dns_header_t);
	create_domain_name(qname, domain_len, dname);

	uint16_t *qtype = (uint16_t *)(qname + domain_len);
	uint16_t *qclass = (uint16_t *)(qtype + 1);
	*qtype = htons(DNS_QUERY_TYPE_A);
	*qclass = htons(DNS_QUERY_CLASS_IN);
}

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
	stpcpy(stpcpy(mmap_file, tmpdir), "/dns_tunnel_filter");
	dns_tunnel_filter_init(mmap_file, RRL_TABLE_SIZE, RRL_INSTANT_LIMIT, RRL_RATE_LIMIT, 0, 0, false);

	if (KRU.initialize == KRU_GENERIC.initialize) {
		struct kru_generic *kru = (struct kru_generic *) dns_tunnel_filter->kru;
		memset(&kru->hash_key, RRL_SEED_GENERIC, sizeof(kru->hash_key));
	} else if (KRU.initialize == KRU_AVX2.initialize) {
		struct kru_avx2 *kru = (struct kru_avx2 *) dns_tunnel_filter->kru;
		memset(&kru->hash_key, RRL_SEED_AVX2, sizeof(kru->hash_key));
	} else {
		assert(0);
	}

	the_tests(state);

	dns_tunnel_filter_deinit();
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
	srand(time(NULL));
	
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
