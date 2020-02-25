/*  Copyright (C) 201 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "tests/unit/test.h"
#include "lib/module.h"

static void test_module_params(void **state)
{
	struct kr_module module;
	assert_int_equal(kr_module_load(NULL, NULL, NULL), kr_error(EINVAL));
	assert_int_equal(kr_module_load(&module, NULL, NULL), kr_error(EINVAL));
	kr_module_unload(NULL);
}

static void test_module_builtin(void **state)
{
	struct kr_module module;
	assert_int_equal(kr_module_load(&module, "iterate", NULL), 0);
	kr_module_unload(&module);
}

static void test_module_c(void **state)
{
	struct kr_module module;
	assert_int_equal(kr_module_load(&module, "mock_cmodule", "tests/unit"), 0);
	kr_module_unload(&module);
}

int main(void)
{
	const UnitTest tests[] = {
		unit_test(test_module_params),
		unit_test(test_module_builtin),
		unit_test(test_module_c),
	};

	return run_tests(tests);
}
