/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "tests/unit/test.h"
#include "lib/resolve.h"
#include "lib/rplan.h"

static void test_rplan_params(void **state)
{
	/* NULL rplan */

	assert_int_equal(kr_rplan_init(NULL, NULL, NULL), KNOT_EINVAL);
	assert_null((void *)kr_rplan_push(NULL, NULL, NULL, 0, 0));
	assert_int_equal(kr_rplan_pop(NULL, NULL), KNOT_EINVAL);
	assert_true(kr_rplan_empty(NULL) == true);
	kr_rplan_deinit(NULL);

	/* NULL mandatory parameters */

	struct kr_rplan rplan;
	assert_int_equal(kr_rplan_init(&rplan, NULL, NULL), KNOT_EOK);
	assert_null((void *)kr_rplan_push(&rplan, NULL, NULL, 0, 0));
	assert_int_equal(kr_rplan_pop(&rplan, NULL), KNOT_EINVAL);
	assert_true(kr_rplan_empty(&rplan) == true);
	kr_rplan_deinit(&rplan);
}

static void test_rplan_push(void **state)
{
	knot_mm_t mm = { 0 };
	test_mm_ctx_init(&mm);
	struct kr_request request = {
		.pool = mm,
		.options = { 0 },
	};

	struct kr_rplan rplan;
	kr_rplan_init(&rplan, &request, &mm);

	/* Push query. */
	assert_non_null((void *)kr_rplan_push(&rplan, NULL, (knot_dname_t *)"", 0, 0));

	kr_rplan_deinit(&rplan);
}

/**
 * Set and clear must not omit any bit, especially around byte boundaries.
 */
static void test_rplan_flags(void **state)
{
	static struct kr_qflags f1, f2, ones, zeros; /* static => initialized to zeroes */
	assert_true(memcmp(&f1, &f2, sizeof(f1)) == 0); /* sanity check */
	memset(&ones, 0xff, sizeof(ones)); /* all ones */

	/* test set */
	kr_qflags_set(&f1, ones);
	assert_true(memcmp(&f1, &ones, sizeof(f1)) == 0);  /* 1 == 1 */

	/* test clear */
	memset(&f2, 0xff, sizeof(f2)); /* all ones */
	kr_qflags_clear(&f2, ones);
	assert_true(memcmp(&f2, &zeros, sizeof(f1)) == 0);  /* 0 == 0 */
}

int main(void)
{
	const UnitTest tests[] = {
	        unit_test(test_rplan_params),
	        unit_test(test_rplan_push),
	        unit_test(test_rplan_flags)
	};

	return run_tests(tests);
}
