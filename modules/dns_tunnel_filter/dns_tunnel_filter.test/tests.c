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

static void the_tests(void **state);

#include "./tests.inc.c"  // NOLINT(bugprone-suspicious-include)

// defining count_test as macro to let it print usable line number on failure
#define count_test(DESC, EXPECTED_PASSING, MARGIN_FRACT, WEIGHT, ...) { \
	int _max_diff = (EXPECTED_PASSING) * (MARGIN_FRACT); \
	int cnt = _count_test(EXPECTED_PASSING, WEIGHT, __VA_ARGS__); \
	assert_int_between(cnt, (EXPECTED_PASSING) - _max_diff, (EXPECTED_PASSING) + _max_diff, DESC); }

uint32_t _count_test(int expected_passing, uint32_t dname_length, int addr_family, char *addr_format, uint32_t ip_min_value, uint32_t ip_max_value)
{
	uint32_t max_queries = expected_passing > 0 ? 2 * expected_passing : -expected_passing;
	struct sockaddr_storage addr;

	uint8_t wire_answer[KNOT_WIRE_MIN_PKTSIZE] = { 0 };
	knot_pkt_t answer = { .wire = wire_answer };

	size_t query_packet_size = get_packet_size(dname_length);
	uint8_t wire_query[query_packet_size];
	unsigned char dname[256];
	create_dns_query(dname_length, wire_query, dname);
	
	knot_pkt_t query_packet = { .wire = wire_query};
	struct kr_query query = { .sname = dname}; 
	struct kr_request req = {
		.qsource.addr = (struct sockaddr *) &addr,
		.qsource.price_factor16 = (1 << 16),
		.qsource.packet = &query_packet,
		.qsource.size = query_packet_size,
		
		.answer = &answer,
		.current_query = &query
	};
	char addr_str[40];
	int cnt = -1;

	for (size_t i = 0; i < max_queries; i++) {
		(void)snprintf(addr_str, sizeof(addr_str), addr_format,
				i % (ip_max_value - ip_min_value + 1) + ip_min_value,
				i / (ip_max_value - ip_min_value + 1) % 256);
		kr_straddr_socket_set((struct sockaddr *) &addr, addr_str, 0);
		if (dns_tunnel_filter_request_begin(&req)) {
			cnt = i;
			break;
		}
	}
	return cnt;
}

static void the_tests(void **state)
{
	/* IPv4 multi-prefix tests */
	static_assert(V4_PREFIXES_CNT == 4,
		"There are no more IPv4 limited prefixes (/32, /24, /20, /18 will be tested).");

	count_test("IPv4 instant limit /32", INST(V4, 32) / 8, 0, 200,
			AF_INET, "128.0.0.0", 0, 0);

	count_test("IPv4 instant limit /32 not applied on /31", -1, 0, 100,
			AF_INET, "128.0.0.1", 0, 0);

	count_test("IPv4 instant limit /24", (INST(V4, 24) - INST(V4, 32) - 4) / 4, 0, 100,
			AF_INET, "128.0.0.%d", 2, 255);

	count_test("IPv4 instant limit /24 not applied on /23", -1, 0, 50,
			AF_INET, "128.0.1.0", 0, 0);

	count_test("IPv4 instant limit /20", (INST(V4, 20) - INST(V4, 24) - 2) / 2, 0.001, 50,
			AF_INET, "128.0.%d.%d", 2, 15);

	count_test("IPv4 instant limit /20 not applied on /19", -1, 0, 25,
			AF_INET, "128.0.16.0", 0, 0);

	count_test("IPv4 instant limit /18", INST(V4, 18) - INST(V4, 20) - 1, 0.01, 25,
			AF_INET, "128.0.%d.%d", 17, 63);

	count_test("IPv4 instant limit /18 not applied on /17", -1, 0, 113,
			AF_INET, "128.0.64.0", 0, 0);

	/* limit after 1 msec */
	fakeclock_tick++;

	count_test("IPv4 rate limit /32 after 1 msec", RATEM(V4, 32), 0, 25,
			AF_INET, "128.0.0.0", 0, 0);
}
