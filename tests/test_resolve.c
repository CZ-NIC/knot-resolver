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
#include <cmocka.h>

#include "lib/resolve.h"

static void test_resolve_nullparams(void **state)
{
	int ret = KNOT_EOK;

	/* NULL parameter check */
	void *non_null = (void *)0xDEADBEEF;
	ret = kr_resolve(NULL, non_null, non_null, KNOT_CLASS_NONE, KNOT_RRTYPE_ANY, 0);
	assert_int_equal(ret, KNOT_EINVAL);
	ret = kr_resolve(non_null, NULL, non_null, KNOT_CLASS_NONE, KNOT_RRTYPE_ANY, 0);
	assert_int_equal(ret, KNOT_EINVAL);
	ret = kr_resolve(non_null, non_null, NULL, KNOT_CLASS_NONE, KNOT_RRTYPE_ANY, 0);
	assert_int_equal(ret, KNOT_EINVAL);
}

int main(void)
{
	const UnitTest tests[] = {
	        /* Parameter sanity checks */
	        unit_test(test_resolve_nullparams)
	};

	return run_tests(tests);
}
