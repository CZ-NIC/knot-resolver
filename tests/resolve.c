
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
	struct kresolve_ctx ctx;
	kresolve_ctx_init(&ctx, NULL);
	struct kresolve_result res;
	const knot_dname_t *qname = (const uint8_t *)"\x06""dnssec""\x02""cz";
	int ret = kresolve_resolve(&ctx, &res, qname, KNOT_CLASS_IN, KNOT_RRTYPE_A);
	assert_int_equal(ret, 0);
	kresolve_ctx_close(&ctx);
}

int main(void)
{
	const UnitTest tests[] = {
	        unit_test(test_resolve_sync),
	};

	return run_tests(tests);
}
