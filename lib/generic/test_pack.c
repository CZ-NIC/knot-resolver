/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "tests/unit/test.h"
#include "lib/generic/pack.h"

#define U8(x) (const uint8_t *)(x)
knot_mm_t global_mm;

static void test_pack_std(void **state)
{
	int ret = 0;
	pack_t pack;
	pack_init(pack);
	assert_int_equal(pack.len, 0);

	/* Test that iterator on empty pack works */
	assert_null(pack_head(pack));
	assert_null(pack_tail(pack));
	assert_null(pack_obj_find(&pack, U8(""), 1));
	assert_int_equal(pack_obj_len(pack_head(pack)), 0);
	assert_int_equal(pack_obj_del(&pack, U8(""), 1), -1);

	/* Push/delete without reservation. */
	assert_int_not_equal(pack_obj_push(&pack, U8(""), 1), 0);
	assert_int_not_equal(pack_obj_del(&pack, U8(""), 1), 0);

	/* Reserve capacity and fill. */
	assert_true(pack_reserve(pack, 10, 10 * 2) >= 0);
	for (unsigned i = 0; i < 10; ++i) {
		ret = pack_obj_push(&pack, U8("de"), 2);
		assert_true(ret >= 0);
	}

	/* Iterate */
	uint8_t *it = pack_head(pack);
	assert_non_null(it);
	while (it != pack_tail(pack)) {
		assert_int_equal(pack_obj_len(it), 2);
		assert_true(memcmp(pack_obj_val(it), "de", 2) == 0);
		it = pack_obj_next(it);
	}

	/* Find */
	it = pack_obj_find(&pack, U8("de"), 2);
	assert_non_null(it);
	it = pack_obj_find(&pack, U8("ed"), 2);
	assert_null(it);

	/* Delete */
	assert_int_not_equal(pack_obj_del(&pack, U8("be"), 2), 0);
	assert_int_equal(pack_obj_del(&pack, U8("de"), 2), 0);
	assert_int_equal(pack.len, 9*(2+2)); /* 9 objects, length=2 */

	pack_clear(pack);
}

int main(void)
{
	test_mm_ctx_init(&global_mm);

	const UnitTest tests[] = {
		unit_test(test_pack_std),
	};

	return run_tests(tests);
}
