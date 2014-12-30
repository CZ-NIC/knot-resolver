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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <libknot/mempattern.h>
#include "lib/context.h"

/* \note Create context and close it. */
static void tests_ctx_create(void **state)
{
	mm_ctx_t mm;
	mm_ctx_init(&mm);
	struct kr_context ctx;
	assert_int_equal(kr_context_init(&ctx, &mm), 0);
	assert_int_equal(kr_context_deinit(&ctx), 0);
}

int main(void)
{
	const UnitTest tests[] = {
	        unit_test(tests_ctx_create),
	};

	return run_tests(tests);
}
