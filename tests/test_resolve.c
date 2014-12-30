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
#include <libknot/descriptor.h>
#include "lib/resolve.h"

/* \note Synchronous resolution. */
void test_resolve_sync(void **state)
{
	struct kr_context ctx;
	kr_context_init(&ctx, NULL);
	struct kr_result res;
	const knot_dname_t *qname = (const uint8_t *)"\x06""dnssec""\x02""cz";
	int ret = kr_resolve(&ctx, &res, qname, KNOT_CLASS_IN, KNOT_RRTYPE_A);
	assert_int_equal(ret, 0);
	kr_result_deinit(&res);
	qname = (const uint8_t *)"\x04""mail""\x07""vavrusa""\x03""com";
	ret = kr_resolve(&ctx, &res, qname, KNOT_CLASS_IN, KNOT_RRTYPE_A);
	assert_int_equal(ret, 0);
	kr_context_deinit(&ctx);
}

int main(void)
{
	const UnitTest tests[] = {
	        unit_test(test_resolve_sync),
	};

	return run_tests(tests);
}
