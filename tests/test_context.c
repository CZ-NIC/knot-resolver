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

#include "lib/context.h"

mm_ctx_t global_mm;
static struct kr_context global_context;

/* Create resolution context */
static void text_context_init(void **state)
{
	int ret = kr_context_init(&global_context, &global_mm);
	assert_int_equal(ret, KNOT_EOK);
	*state = &global_context;
}

/* Delete it */
static void text_context_deinit(void **state)
{
	int ret = kr_context_deinit(*state);
	assert_int_equal(ret, KNOT_EOK);
}

int main(void)
{
	test_mm_ctx_init(&global_mm);

	const UnitTest tests[] = {
	        unit_test_teardown(text_context_init, text_context_deinit),
	};

	return run_tests(tests);
}
