/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <sys/socket.h>
#include <stdio.h>
#include <contrib/cleanup.h>

#include "tests/unit/test.h"
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

static inline int assert_bitmask(const char *addr, const char *exp_masked)
{
	unsigned char addr_buf[16];
	unsigned char exp_masked_buf[16];

	int bits = kr_straddr_subnet(addr_buf, addr);
	size_t addr_len = (kr_straddr_family(addr) == AF_INET6) ? 16 : 4;
	int exp_masked_bits = kr_straddr_subnet(exp_masked_buf, exp_masked);
	size_t exp_masked_len = (kr_straddr_family(exp_masked) == AF_INET6) ? 16 : 4;

	/* sanity checks */
	assert_true(bits >= 0);
	assert_int_equal(addr_len, exp_masked_len);
	assert_int_equal(exp_masked_bits, exp_masked_len * 8);

	kr_bitmask(addr_buf, addr_len, bits);
	return memcmp(addr_buf, exp_masked_buf, addr_len);
}

static void test_bitmask(void **state)
{
	assert_int_equal(assert_bitmask("10.0.1.5/32", "10.0.1.5"), 0);
	assert_int_equal(assert_bitmask("10.0.1.5", "10.0.1.5"), 0);
	assert_int_equal(assert_bitmask("10.0.1.5/24", "10.0.1.0"), 0);
	assert_int_equal(assert_bitmask("128.30.1.16/16", "128.30.0.0"), 0);
	assert_int_equal(assert_bitmask("255.255.255.255/20", "255.255.240.0"), 0);
	assert_int_equal(assert_bitmask("255.255.255.255/22", "255.255.252.0"), 0);
	assert_int_equal(assert_bitmask("192.168.0.1/0", "0.0.0.0"), 0);
	assert_int_equal(assert_bitmask("7caa::/4", "7000::"), 0);
	assert_int_equal(assert_bitmask("dead:beef::/16", "dead::"), 0);
	assert_int_equal(assert_bitmask("dead:beef::/20", "dead:b000::"), 0);
	assert_int_equal(assert_bitmask("dead:beef::/0", "::"), 0);
	assert_int_equal(assert_bitmask("64aa:22fa:1378:aaaa:bbbb::/36", "64aa:22fa:1000::"), 0);
}

static void test_strptime_diff(void **state)
{
	char *format = "%Y-%m-%dT%H:%M:%S";
	const char *errmsg = NULL;
	double output;

	errmsg = kr_strptime_diff(format,
		"2019-01-09T12:06:04",
		"2019-01-09T12:06:04", &output);
	assert_true(errmsg == NULL);
	/* double type -> equality is not reliable */
	assert_true(output > -0.01 && output < 0.01);

	errmsg = kr_strptime_diff(format,
		"2019-01-09T12:06:04",
		"2019-01-09T11:06:04", &output);
	assert_true(errmsg == NULL);
	/* double type -> equality is not reliable */
	assert_true(output > -3600.01 && output < 3600.01);

	/* invalid inputs */
	errmsg = kr_strptime_diff(format,
		"2019-01-09T25:06:04",
		"2019-01-09T11:06:04", &output);
	assert_true(errmsg != NULL);

	errmsg = kr_strptime_diff("fail",
		"2019-01-09T23:06:04",
		"2019-01-09T11:06:04", &output);
	assert_true(errmsg != NULL);
}

int main(void)
{
	const UnitTest tests[] = {
		unit_test(test_strcatdup),
		unit_test(test_straddr),
		unit_test(test_bitmask),
		unit_test(test_strptime_diff)
	};

	return run_tests(tests);
}
