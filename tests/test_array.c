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
#include "lib/generic/array.h"

mm_ctx_t global_mm;

static void test_array(void **state)
{
	int ret = 0;
	array_t(int) arr;
	array_init(arr);

	/* Basic access */
	assert_int_equal(arr.len, 0);
	assert_int_equal(array_push(arr, 5), 0);
	assert_int_equal(arr.at[0], 5);
	assert_int_equal(array_tail(arr), 5);
	array_clear(arr);

	/* Reserve capacity and fill. */
	assert_true(array_reserve(arr, 5) >= 0);
	for (unsigned i = 0; i < 100; ++i) {
		ret = array_push(arr, i);
		assert_true(ret >= 0);
	}

	/* Delete elements. */
	array_del(arr, 0);
	for (size_t i = arr.len; --i;) {
		ret = array_pop(arr);
		assert_true(ret == 0);
	}

	array_clear(arr);
}

int main(void)
{
	test_mm_ctx_init(&global_mm);

	const UnitTest tests[] = {
		unit_test(test_array),
	};

	return run_tests(tests);
}
