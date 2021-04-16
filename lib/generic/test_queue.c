/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "tests/unit/test.h"
#include "lib/generic/queue.h"

/* The main intention is to use queues with pointers, so we test the same-sized int. */
typedef queue_t(ptrdiff_t) queue_int_t;
typedef queue_it_t(int) queue_int_it_t;

static void test_int(void **state_)
{
	queue_int_t q;
	queue_init(q);

	/* Case of emptying the queue (and using again) has been broken for a long time. */
	queue_push(q, 2);
	queue_pop(q);
	queue_push(q, 4);
	queue_pop(q);

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

	/* Basic iterator test. */
	{
		int i = 0;
		for (queue_int_it_t it = queue_it_begin(q); !queue_it_finished(it);
		     queue_it_next(it)) {
			++queue_it_val(it);
			++i;
		}
		assert_int_equal(queue_len(q), i);
	}

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

