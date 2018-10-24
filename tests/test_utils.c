/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <sys/socket.h>
#include <stdio.h>
#include <contrib/cleanup.h>

#include "tests/test.h"
#include "lib/utils.h"

static void test_strcatdup(void **state)
{
	auto_free char *empty_res = kr_strcatdup(0);
	assert_null(empty_res);

	auto_free char *null_res = kr_strcatdup(1, NULL);
	assert_null(null_res);

	auto_free char *nullcat_res = kr_strcatdup(2, NULL, "beef");
	assert_string_equal(nullcat_res, "beef");

	auto_free char *multi_res = kr_strcatdup(3, "need", "beef", "dead");
	assert_string_equal(multi_res, "needbeefdead");

	/* Test fails if this leaks. */
	auto_fclose FILE* null_file = fopen("/dev/null", "r");
	(void)(null_file);

	/* Test fails if this leaks. */
	auto_close int null_sock = socket(AF_INET, SOCK_DGRAM, 0);
	(void)(null_sock);
}

static inline int test_bitcmp(const char *subnet, const char *str_addr, size_t len)
{
	char addr_buf[16] = {'\0'};
	kr_straddr_subnet(addr_buf, str_addr);
	return kr_bitcmp(subnet, addr_buf, len);
}

static void test_straddr(void **state)
{
	const char *ip4_ok = "1.2.3.0/30";
	const char *ip4_bad = "1.2.3.0/33";
	const char *ip4_in = "1.2.3.1";
	const char *ip4_out = "1.2.3.5";
	const char *ip6_ok = "7caa::/4";
	const char *ip6_bad = "7caa::/129";
	const char *ip6_in = "7caa::aa7c";
	const char *ip6_out = "8caa::aa7c";
	/* Parsing family */
	assert_int_equal(kr_straddr_family(ip4_ok), AF_INET);
	assert_int_equal(kr_straddr_family(ip4_in), AF_INET);
	assert_int_equal(kr_straddr_family(ip6_ok), AF_INET6);
	assert_int_equal(kr_straddr_family(ip6_in), AF_INET6);
	/* Parsing subnet */
	char ip4_sub[4], ip6_sub[16];
	assert_true(kr_straddr_subnet(ip4_sub, ip4_bad) < 0);
	assert_int_equal(kr_straddr_subnet(ip4_sub, ip4_ok), 30);
	assert_true(kr_straddr_subnet(ip6_sub, ip6_bad) < 0);
	assert_int_equal(kr_straddr_subnet(ip6_sub, ip6_ok), 4);
	/* Matching subnet */
	assert_int_equal(test_bitcmp(ip4_sub, ip4_in, 30), 0);
	assert_int_not_equal(test_bitcmp(ip4_sub, ip4_out, 30), 0);
	assert_int_equal(test_bitcmp(ip6_sub, ip6_in, 4), 0);
	assert_int_not_equal(test_bitcmp(ip6_sub, ip6_out, 4), 0);
}

static void test_edns_append(void **state)
{
	uint8_t *source_option[KNOT_EDNS_MAX_OPTION_CODE];
	int source_option_len[KNOT_EDNS_MAX_OPTION_CODE];
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	knot_rrset_t *opt_rr = mm_alloc(NULL, sizeof(knot_rrset_t));
	knot_edns_init(opt_rr, KR_EDNS_PAYLOAD, 0, KR_EDNS_VERSION, NULL);
	pkt->opt_rr = opt_rr;

	for (uint16_t i = 0; i < KNOT_EDNS_MAX_OPTION_CODE; ++i) {
		if (i == KNOT_EDNS_OPTION_TCP_KEEPALIVE) {
			source_option[i] = NULL;
			source_option_len[i] = 0;
			continue;
		}
		int opt_len = kr_rand_uint(16);
		if (opt_len == 0) {
			opt_len = 16;
		}
		uint8_t *opt_buf = malloc(opt_len);
		assert_non_null(opt_buf);
		knot_rrset_t *opt_rr_new = mm_alloc(NULL, sizeof(knot_rrset_t));
		assert_non_null(opt_rr_new);

		for (int j = 0; j < opt_len; ++j) {
			opt_buf[j] = kr_rand_uint(255);
		}

		source_option[i] = opt_buf;
		source_option_len[i] = opt_len;

		knot_edns_init(opt_rr_new, KR_EDNS_PAYLOAD, 0, KR_EDNS_VERSION, NULL);
		knot_edns_add_option(opt_rr_new, i, opt_len, opt_buf, NULL);
		kr_edns_append(opt_rr, opt_rr_new->rrs.rdata, NULL);
		knot_rrset_free(opt_rr_new, NULL);
	}

	knot_edns_options_t *options;
	knot_edns_get_options(opt_rr, &options, NULL);

	for (uint16_t i = 0; i < KNOT_EDNS_MAX_OPTION_CODE; ++i) {
		uint8_t *opt = knot_edns_get_option(opt_rr,  i);
		if (source_option[i] == NULL) {
			assert_null(opt);
			continue;
		}
		int opt_len = knot_edns_opt_get_length(opt);
		assert_int_equal(opt_len, source_option_len[i]);
		assert_int_equal(memcmp(&opt[4], source_option[i], opt_len), 0);
		free(source_option[i]);
	}

	mm_free(NULL, options);
	knot_rrset_free(opt_rr, NULL);
	knot_pkt_free(pkt);
}

int main(void)
{
	const UnitTest tests[] = {
		unit_test(test_strcatdup),
		unit_test(test_straddr),
		unit_test(test_edns_append)
	};

	return run_tests(tests);
}
