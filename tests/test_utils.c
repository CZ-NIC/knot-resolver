/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "tests/test.h"
#include <cmocka.h>

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
}

int main(void)
{
	const UnitTest tests[] = {
		unit_test(test_strcatdup),
	};

	return run_tests(tests);
}
