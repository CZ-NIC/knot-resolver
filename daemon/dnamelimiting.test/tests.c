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
#define count_test(DESC, EXPECTED_PASSING, MARGIN_FRACT, ...) { \
	int _max_diff = (EXPECTED_PASSING) * (MARGIN_FRACT); \
	int cnt = _count_test(EXPECTED_PASSING, __VA_ARGS__); \
	assert_int_between(cnt, (EXPECTED_PASSING) - _max_diff, (EXPECTED_PASSING) + _max_diff, DESC); }

uint32_t _count_test(int expected_passing, int addr_family, char *addr_format, uint32_t min_value, uint32_t max_value)
{
	uint32_t max_queries = expected_passing > 0 ? 2 * expected_passing : -expected_passing;
	struct sockaddr_storage addr;
	uint8_t wire[KNOT_WIRE_MIN_PKTSIZE] = { 0 };
	knot_pkt_t answer = { .wire = wire };
	struct kr_request req = {
		.qsource.addr = (struct sockaddr *) &addr,
		.qsource.price_factor16 = 1 << 16,
		.answer = &answer
	};
	char addr_str[40];
	int cnt = -1;

	for (size_t i = 0; i < max_queries; i++) {
		(void)snprintf(addr_str, sizeof(addr_str), addr_format,
				i % (max_value - min_value + 1) + min_value,
				i / (max_value - min_value + 1) % 256);
		kr_straddr_socket_set((struct sockaddr *) &addr, addr_str, 0);
		if (dnamelimiting_request_begin(&req, RRL_INSTANT_LIMIT)) {
			cnt = i;
			break;
		}
	}
	return cnt;
}

static void the_tests(void **state)
{
	
}
