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

#include <libknot/internal/mempool.h>
#include "lib/cache.h"


mm_ctx_t global_mm;
namedb_txn_t global_txn;
knot_rrset_t global_rr;
const char *global_env;

#define CACHE_SIZE 100*1024
#define CACHE_TTL  1

/* Test cache open */
static void test_open(void **state)
{
	*state = kr_cache_open(global_env, &global_mm, CACHE_SIZE);
	assert_non_null(*state);
}

/* Test cache teardown. */
static void test_close(void **state)
{
	kr_cache_close(*state);
	*state = NULL;
}


/* Open transaction */
static namedb_txn_t *test_txn_write(void **state)
{
	assert_non_null(*state);
	assert_int_equal(kr_cache_txn_begin(*state, &global_txn, 0), KNOT_EOK);
	return &global_txn;
}

/* Open transaction */
static namedb_txn_t *test_txn_rdonly(void **state)
{
	assert_non_null(*state);
	assert_int_equal(kr_cache_txn_begin(*state, &global_txn, NAMEDB_RDONLY), KNOT_EOK);
	return &global_txn;
}

/* Test cache write */
static void test_insert(void **state)
{
	test_random_rr(&global_rr, CACHE_TTL);

	namedb_txn_t *txn = test_txn_write(state);
	int ret = kr_cache_insert(txn, &global_rr, 0);
	if (ret == KNOT_EOK) {
		ret = kr_cache_txn_commit(txn);
	} else {
		kr_cache_txn_abort(txn);
	}

	assert_int_equal(ret, KNOT_EOK);
}

/* Test cache read */
static void test_query(void **state)
{

	uint32_t timestamp = 0;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	namedb_txn_t *txn = test_txn_rdonly(state);
	int query_ret = kr_cache_peek(txn, &cache_rr, &timestamp);
	bool rr_equal = knot_rrset_equal(&global_rr, &cache_rr, KNOT_RRSET_COMPARE_WHOLE);
	kr_cache_txn_abort(txn);

	assert_int_equal(query_ret, KNOT_EOK);
	assert_true(rr_equal);
}

/* Test cache read (simulate aged entry) */
static void test_query_aged(void **state)
{
	uint32_t timestamp = CACHE_TTL;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	namedb_txn_t *txn = test_txn_rdonly(state);
	int ret = kr_cache_peek(txn, &cache_rr, &timestamp);
	assert_int_equal(ret, KNOT_ENOENT);
}

/* Test cache fill */
static void test_fill(void **state)
{
	namedb_txn_t *txn = test_txn_write(state);

	/* Fill with random values. */
	int ret = KNOT_EOK;
	for (unsigned i = 0; i < CACHE_SIZE; ++i) {
		knot_rrset_t rr;
		test_random_rr(&rr, CACHE_TTL);
		ret = kr_cache_insert(txn, &rr, 0);
		if (ret != KNOT_EOK) {
			break;
		}
		/* Intermediate commit */
		if (i % 10 == 0) {
			ret = kr_cache_txn_commit(txn);
			if (ret != KNOT_EOK) {
				txn = NULL;
				break;
			}
			txn = test_txn_write(state);
		}
	}
	/* Size reached, commit may fail. */
	(void) kr_cache_txn_commit(txn);

	/* Expect we run out of space */
	assert_int_equal(ret, KNOT_ESPACE);
}

/* Test cache clear */
static void test_clear(void **state)
{
	namedb_txn_t *txn = test_txn_write(state);
	int preempt_ret = kr_cache_clear(txn);
	int commit_ret = kr_cache_txn_commit(txn);
	assert_int_equal(preempt_ret, KNOT_EOK);
	assert_int_equal(commit_ret, KNOT_EOK);
}

int main(void)
{
	/* Initialize */
	test_mm_ctx_init(&global_mm);
	global_env = test_tmpdir_create();

	const UnitTest tests[] = {
	        /* Cache persistence */
	        group_test_setup(test_open),
	        unit_test(test_insert),
	        unit_test(test_query),
	        /* Cache aging */
	        unit_test(test_query_aged),
	        /* Cache fill */
	        unit_test(test_fill),
	        unit_test(test_clear),
	        group_test_teardown(test_close)
	};

	int ret = run_group_tests(tests);

	/* Cleanup */
	test_tmpdir_remove(global_env);

	return ret;
}
