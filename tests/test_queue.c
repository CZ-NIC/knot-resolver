/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "tests/test.h"
#include "lib/generic/queue.h"

/* The main intention is to use queues with pointers, so we test the same-sized int. */
typedef queue_t(ptrdiff_t) queue_int_t;

static void test_int(void **state_)
{
	queue_int_t q;
	queue_init(q);

	queue_push_head(q, 2);
	queue_push_head(q, 1);
	queue_push_head(q, 0);
	for (int i = 0; i < 100; ++i) {
		assert_int_equal(queue_head(q), i);
		queue_push(q, i + 3);
		queue_pop(q);
	}
	assert_int_equal(queue_len(q), 3);
	for (int i = 99; i > 0; --i) {
		assert_int_equal(queue_head(q), i + 1);
		queue_push_head(q, i);
	}
	assert_int_equal(queue_len(q), 3 + 99);

	queue_deinit(q);
	queue_init(q);

	for (int i = 0; i < 100; ++i) {
		queue_push(q, 2*i);
		queue_push(q, 2*i + 1);
		assert_int_equal(queue_head(q), i);
		queue_pop(q);
	}

	queue_deinit(q);
}


int main(void)
{
	const UnitTest tests[] = {
		unit_test(test_int),
	};

	return run_tests(tests);
}

