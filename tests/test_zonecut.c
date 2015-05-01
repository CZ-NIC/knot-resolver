/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "lib/zonecut.h"

static void test_zonecut_params(void **state)
{
	/* NULL args */
	struct kr_zonecut cut;
	assert_int_not_equal(kr_zonecut_init(NULL, NULL, NULL), 0);
	assert_int_not_equal(kr_zonecut_init(&cut, NULL, NULL), 0);
	kr_zonecut_deinit(NULL);
	kr_zonecut_set(NULL, NULL);
	kr_zonecut_set(&cut, NULL);
	assert_int_not_equal(kr_zonecut_add(NULL, NULL, NULL), 0);
	assert_null((void *)kr_zonecut_find(NULL, NULL));
	assert_null((void *)kr_zonecut_find(&cut, NULL));
	assert_int_not_equal(kr_zonecut_set_sbelt(NULL), 0);
	assert_int_not_equal(kr_zonecut_find_cached(NULL, NULL, 0), 0);
}

int main(void)
{
	const UnitTest tests[] = {
	        unit_test(test_zonecut_params)
	};

	return run_tests(tests);
}
