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
#include "lib/resolve.h"
#include "lib/rplan.h"

static void test_rplan_params(void **state)
{
	/* NULL rplan */

	assert_int_equal(kr_rplan_init(NULL, NULL, NULL), KNOT_EINVAL);
	assert_null(kr_rplan_push(NULL, NULL, NULL, 0, 0));
	assert_int_equal(kr_rplan_pop(NULL, NULL), KNOT_EINVAL);
	assert_true(kr_rplan_empty(NULL));
	assert_null(kr_rplan_current(NULL));
	kr_rplan_deinit(NULL);

	/* NULL mandatory parameters */

	struct kr_rplan rplan;
	assert_int_equal(kr_rplan_init(&rplan, NULL, NULL), KNOT_EOK);
	assert_null(kr_rplan_push(&rplan, NULL, NULL, 0, 0));
	assert_int_equal(kr_rplan_pop(&rplan, NULL), KNOT_EINVAL);
	assert_true(kr_rplan_empty(&rplan));
	assert_null(kr_rplan_current(&rplan));
	kr_rplan_deinit(&rplan);
}

static void test_rplan_push(void **state)
{
	mm_ctx_t mm;
	test_mm_ctx_init(&mm);
	struct kr_context context = {
		.pool = &mm,
	};

	struct kr_rplan rplan;
	kr_rplan_init(&rplan, &context, &mm);

	/* Push query. */
	assert_non_null(kr_rplan_push(&rplan, NULL, (knot_dname_t *)"", 0, 0));

	kr_rplan_deinit(&rplan);
}

int main(void)
{
	const UnitTest tests[] = {
	        unit_test(test_rplan_params),
	        unit_test(test_rplan_push)
	};

	return run_tests(tests);
}
