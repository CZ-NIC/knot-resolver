/*  Copyright (C) 201 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "lib/module.h"

mm_ctx_t global_mm;

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
	assert_int_equal(kr_module_load(&module, "mock_cmodule", "tests"), 0);
	kr_module_unload(&module);
}

static void test_module_go(void **state)
{
	struct kr_module module;
	assert_int_equal(kr_module_load(&module, "mock_gomodule", "tests"), kr_error(ENOTSUP));
	kr_module_unload(&module);
}

int main(void)
{
	test_mm_ctx_init(&global_mm);

	const UnitTest tests[] = {
		unit_test(test_module_params),
		unit_test(test_module_builtin),
		unit_test(test_module_c),
		unit_test(test_module_go)
	};

	return run_tests(tests);
}
