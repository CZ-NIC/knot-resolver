/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <netinet/in.h>

#include "tests/unit/test.h"
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
	/* TODO triggerring inner assert:
	assert_int_not_equal(kr_zonecut_add(NULL, NULL, NULL, 0), 0);
	*/
	assert_null((void *)kr_zonecut_find(NULL, NULL));
	assert_null((void *)kr_zonecut_find(&cut, NULL));
	assert_int_not_equal(kr_zonecut_set_sbelt(NULL, NULL), 0);
	assert_int_not_equal(kr_zonecut_find_cached(NULL, NULL, NULL, 0, 0), 0);
}

static void test_zonecut_copy(void **state)
{
	const knot_dname_t *n_root = (const uint8_t *)"";
	struct kr_zonecut cut1, cut2;
	kr_zonecut_init(&cut1, n_root, NULL);
	kr_zonecut_init(&cut2, n_root, NULL);
	/* Insert some values */
	const knot_dname_t
		*n_1 = (const uint8_t *)"\4dead",
		*n_2 = (const uint8_t *)"\3bee\1f";
	assert_int_equal(kr_zonecut_add(&cut1, n_1, NULL, 0), 0);
	assert_int_equal(kr_zonecut_add(&cut1, n_2, NULL, 0), 0);
	/* Copy */
	assert_int_equal(kr_zonecut_copy(&cut2, &cut1), 0);
	/* Check if exist */
	assert_non_null(kr_zonecut_find(&cut2, n_1));
	assert_non_null(kr_zonecut_find(&cut2, n_2));
	assert_null(kr_zonecut_find(&cut2, (const uint8_t *)"\5death"));
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
