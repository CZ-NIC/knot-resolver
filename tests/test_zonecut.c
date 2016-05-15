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

#include <netinet/in.h>

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
	assert_int_not_equal(kr_zonecut_set_sbelt(NULL, NULL), 0);
	assert_int_not_equal(kr_zonecut_find_cached(NULL, NULL, NULL, 0, 0), 0);
}

static void test_zonecut_copy(void **state)
{
	const knot_dname_t *root = (const uint8_t *)"";
	struct kr_zonecut cut1, cut2;
	kr_zonecut_init(&cut1, root, NULL);
	kr_zonecut_init(&cut2, root, NULL);
	/* Insert some values */
	assert_int_equal(kr_zonecut_add(&cut1, (const uint8_t *)"dead", NULL), 0);
	assert_int_equal(kr_zonecut_add(&cut1, (const uint8_t *)"beef", NULL), 0);
	/* Copy */
	assert_int_equal(kr_zonecut_copy(&cut2, &cut1), 0);
	/* Check if exist */
	assert_non_null(kr_zonecut_find(&cut2, (const uint8_t *)"dead"));
	assert_non_null(kr_zonecut_find(&cut2, (const uint8_t *)"beef"));
	assert_null(kr_zonecut_find(&cut2, (const uint8_t *)"corn"));
	kr_zonecut_deinit(&cut1);
	kr_zonecut_deinit(&cut2);
}

int main(void)
{
	const UnitTest tests[] = {
	        unit_test(test_zonecut_params),
	        unit_test(test_zonecut_copy)
	};

	return run_tests(tests);
}
