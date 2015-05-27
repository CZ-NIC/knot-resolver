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

#include <libknot/internal/mempool.h>
#include <libknot/internal/namedb/namedb_lmdb.h>

#include "tests/test.h"
#include "lib/cache.h"

#include <execinfo.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <dlfcn.h>

mm_ctx_t global_mm;
namedb_txn_t global_txn;
knot_rrset_t global_rr;
const char *global_env;
struct kr_cache_entry global_fake_ce;
const namedb_api_t *(*kr_cache_storage_saved)(void);

#define NAMEDB_INTS 256
#define NAMEDB_DATA_SIZE (NAMEDB_INTS * sizeof(int))
uint8_t namedb_data[NAMEDB_DATA_SIZE];
namedb_val_t global_namedb_data = {namedb_data, NAMEDB_DATA_SIZE};
bool is_malloc_mocked = false;
#define BACKTRACE_ARRAY_SIZE 1024
void* callstack[BACKTRACE_ARRAY_SIZE];

#define CACHE_SIZE 10 * 4096
#define CACHE_TTL 10
#define CACHE_TIME 0

void * (*original_malloc) (size_t __size);
int (*original_knot_rdataset_add)(knot_rdataset_t *rrs, const knot_rdata_t *rr, mm_ctx_t *mm) = NULL;

void *malloc(size_t __size)
{
	Dl_info dli = {0};
	char insert_name[] = "kr_cache_insert";
	int err_mock = KNOT_EOK, insert_namelen = strlen(insert_name);

	if (original_malloc == NULL)
	{
		original_malloc = dlsym(RTLD_NEXT,"malloc");
		assert_non_null (malloc);
	}
	if (is_malloc_mocked)
	{
	    dladdr (__builtin_return_address (0), &dli);
	    if (dli.dli_sname && (strncmp(insert_name,dli.dli_sname,insert_namelen) == 0))
		    err_mock = mock();
	}
	return (err_mock != KNOT_EOK) ? NULL : original_malloc (__size);
}

int knot_rdataset_add(knot_rdataset_t *rrs, const knot_rdata_t *rr, mm_ctx_t *mm)
{
	int err, err_mock;
	err_mock = (int)mock();
	if (original_knot_rdataset_add == NULL)
	{
		original_knot_rdataset_add = dlsym(RTLD_NEXT,"knot_rdataset_add");
		assert_non_null (original_knot_rdataset_add);
	}	
	err = original_knot_rdataset_add(rrs, rr, mm);
	if (err_mock != KNOT_EOK)
	    err = err_mock;
	return err;
}

/* Simulate init failure */
static int test_init_failure(namedb_t **db_ptr, mm_ctx_t *mm, void *arg)
{
	return KNOT_EINVAL;
}

/* Simulate commit failure */
static int test_commit_failure(namedb_txn_t *txn)
{
	return KNOT_ESPACE;
}

/* Dummy abort */
static void test_abort(namedb_txn_t *txn)
{
	return;
}

/* Stub for find */
static int test_find(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags)
{
	val->data = &global_fake_ce;
	return KNOT_EOK;
}

/* Stub for insert */
static int test_ins(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags)
{
	struct kr_cache_entry *header = val->data;
	int  res_cmp, err = (int)mock();
	if (val->len == sizeof (*header) + NAMEDB_DATA_SIZE)
	{
	    header = val->data;
	    res_cmp  = memcmp(header->data,namedb_data,NAMEDB_DATA_SIZE);
	    if (header->timestamp != global_fake_ce.timestamp ||
		header->ttl != global_fake_ce.ttl ||
		header->ttl != global_fake_ce.ttl ||
		res_cmp != 0)
	    {
		err = KNOT_EINVAL;
	    }
	}
	return err;
}


/* Fake api */
static const namedb_api_t *namedb_lmdb_api_fake(void)
{
	static const namedb_api_t api_fake = {
		"lmdb_api_fake",
		test_init_failure, NULL,
		NULL, test_commit_failure, test_abort,
		NULL, NULL, test_find, test_ins, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL
	};

	return &api_fake;
}

/* fake api test open */
static void test_fake_api_prepare(void **state)
{
	/* save original api */
	kr_cache_storage_saved = kr_cache_storage;
	/* fake to simulate failures or constant success */
	kr_cache_storage_set(namedb_lmdb_api_fake);
}

/* fake api test close */
static void test_fake_api_close(void **state)
{
	/* restore original api*/
	kr_cache_storage_set(kr_cache_storage_saved);
}

/* test invalid parameters and some api failures */
static void test_fake_invalid (void **state)
{
	knot_dname_t dname[] = "";
	assert_null(kr_cache_open(NULL, NULL));
	assert_int_equal(kr_cache_peek(&global_txn, KR_CACHE_USER, dname, KNOT_RRTYPE_TSIG, 0),
		&global_fake_ce);
	assert_int_not_equal(kr_cache_txn_commit(&global_txn), KNOT_EOK);
}

static void test_fake_insert(void **state)
{
	int ret_cache_ins_ok, ret_cache_lowmem, ret_cache_ins_inval;
	knot_dname_t dname[] = "";
	test_randstr((char *)&global_fake_ce,sizeof(global_fake_ce));
	test_randstr((char *)namedb_data,NAMEDB_DATA_SIZE);

	is_malloc_mocked = true;
	will_return(malloc,KNOT_EINVAL);
	ret_cache_lowmem = kr_cache_insert(&global_txn, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data);
	is_malloc_mocked = false;
	will_return(test_ins,KNOT_EOK);
	ret_cache_ins_ok = kr_cache_insert(&global_txn, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data);
	will_return(test_ins,KNOT_EINVAL);
	ret_cache_ins_inval = kr_cache_insert(&global_txn, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data);
	assert_int_equal(ret_cache_lowmem, KNOT_ENOMEM);
	assert_int_equal(ret_cache_ins_ok, KNOT_EOK);
	assert_int_equal(ret_cache_ins_inval, KNOT_EINVAL);
}

/* Test invalid parameters */
static void test_invalid(void **state)
{
	uint32_t timestamp = CACHE_TIME;
	knot_dname_t dname[] = "";

	assert_int_not_equal(kr_cache_txn_begin(NULL, &global_txn, 0), 0);
	assert_int_not_equal(kr_cache_txn_begin(&global_env, NULL, 0), 0);
	assert_int_not_equal(kr_cache_txn_commit(NULL), 0);
	assert_null(kr_cache_peek(NULL, KR_CACHE_USER, dname, KNOT_RRTYPE_TSIG, &timestamp));
	assert_null(kr_cache_peek(&global_txn, 0, dname, KNOT_RRTYPE_TSIG, &timestamp));
	assert_null(kr_cache_peek(&global_txn, KR_CACHE_USER, NULL, KNOT_RRTYPE_TSIG, &timestamp));
	assert_int_not_equal(kr_cache_peek_rr(NULL, NULL, NULL), 0);
	assert_int_not_equal(kr_cache_peek_rr(&global_txn, NULL, NULL), 0);
	assert_int_not_equal(kr_cache_insert_rr(&global_txn, NULL, 0), 0);
	assert_int_not_equal(kr_cache_insert_rr(NULL, NULL, 0), 0);
	assert_int_not_equal(kr_cache_insert(NULL, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data), 0);
	assert_int_not_equal(kr_cache_insert(&global_txn, 0, dname,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data), 0);
	assert_int_not_equal(kr_cache_insert(&global_txn, KR_CACHE_USER, NULL,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data), 0);
	assert_int_not_equal(kr_cache_insert(&global_txn, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, NULL, global_namedb_data), 0);
	assert_int_not_equal(kr_cache_remove(&global_txn, 0, NULL, 0), 0);
	assert_int_not_equal(kr_cache_remove(&global_txn, KR_CACHE_RR, NULL, 0), 0);
	assert_int_not_equal(kr_cache_remove(NULL, 0, NULL, 0), 0);
	assert_int_not_equal(kr_cache_clear(NULL), 0);
}

/* Test cache open */
static void test_open(void **state)
{
	struct namedb_lmdb_opts opts;
	memset(&opts, 0, sizeof(opts));
	opts.path = global_env;
	opts.mapsize = CACHE_SIZE;
	*state = kr_cache_open(&opts, &global_mm);
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
	assert_int_equal(kr_cache_txn_begin(*state, &global_txn, NAMEDB_RDONLY), 0);
	return &global_txn;
}

/* Test cache write */
static void test_insert_rr(void **state)
{
	test_random_rr(&global_rr, CACHE_TTL);
	namedb_txn_t *txn = test_txn_write(state);
	int ret = kr_cache_insert_rr(txn, &global_rr, CACHE_TIME);
	if (ret == KNOT_EOK) {
		ret = kr_cache_txn_commit(txn);
	} else {
		kr_cache_txn_abort(txn);
	}
	assert_int_equal(ret, KNOT_EOK);
}

static void test_materialize(void **state)
{
	knot_rrset_t output_rr;
	bool res_cmp_ok, res_cmp_fail;

	knot_rrset_init(&output_rr, NULL, 0, 0);
	will_return (knot_rdataset_add,KNOT_EOK);
	output_rr = kr_cache_materialize(&global_rr, 0, &global_mm);
	res_cmp_ok = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_WHOLE);
	knot_rrset_clear(&output_rr,&global_mm);
	assert_true(res_cmp_ok);

	knot_rrset_init(&output_rr, NULL, 0, 0);
	will_return (knot_rdataset_add,KNOT_EINVAL);
	output_rr = kr_cache_materialize(&global_rr, 0, &global_mm);
	res_cmp_fail = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_WHOLE);
	knot_rrset_clear(&output_rr,&global_mm);
	assert_false(res_cmp_fail);
}

/* Test cache read */
static void test_query(void **state)
{

	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	namedb_txn_t *txn = test_txn_rdonly(state);

	for (uint32_t timestamp = CACHE_TIME; timestamp < CACHE_TIME + CACHE_TTL; ++timestamp) {
		uint32_t drift = timestamp;
		int query_ret = kr_cache_peek_rr(txn, &cache_rr, &drift);
		bool rr_equal = knot_rrset_equal(&global_rr, &cache_rr, KNOT_RRSET_COMPARE_WHOLE);
		assert_int_equal(query_ret, KNOT_EOK);
		assert_true(rr_equal);
	}

	kr_cache_txn_abort(txn);
}

/* Test cache read (simulate aged entry) */
static void test_query_aged(void **state)
{
	uint32_t timestamp = CACHE_TIME + CACHE_TTL;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	namedb_txn_t *txn = test_txn_rdonly(state);
	int ret = kr_cache_peek_rr(txn, &cache_rr, &timestamp);
	assert_int_equal(ret, KNOT_ENOENT);
	kr_cache_txn_abort(txn);
}

/* Test cache removal */
static void test_remove(void **state)
{
	uint32_t timestamp = CACHE_TIME;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	namedb_txn_t *txn = test_txn_write(state);
	int ret = kr_cache_remove(txn, KR_CACHE_RR, cache_rr.owner, cache_rr.type);
	assert_int_equal(ret, KNOT_EOK);
	ret = kr_cache_peek_rr(txn, &cache_rr, &timestamp);
	assert_int_equal(ret, KNOT_ENOENT);
	kr_cache_txn_commit(txn);
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
		ret = kr_cache_insert_rr(txn, &rr, CACHE_TTL - 1);
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

	/* Abort last transaction (if valid) */
	kr_cache_txn_abort(txn);

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
		/* Invalid input */
		unit_test(test_invalid),
	        /* Cache persistence */
	        group_test_setup(test_open),
	        unit_test(test_insert_rr),
	        unit_test(test_materialize),
	        unit_test(test_query),
	        /* Cache aging */
	        unit_test(test_query_aged),
	        /* Removal */
	        unit_test(test_remove),
	        /* Cache fill */
	        unit_test(test_fill),
	        unit_test(test_clear),
	        group_test_teardown(test_close)
	};
	const UnitTest fake_api_tests[] = {
	        group_test_setup(test_fake_api_prepare),
		/* Invalid input and failures */
	        unit_test(test_fake_invalid),
	        unit_test(test_fake_insert),
	        group_test_teardown(test_fake_api_close)
	};

	int ret		= run_group_tests(tests);
	int ret_fake	= run_group_tests(fake_api_tests);

	/* Cleanup */
	test_tmpdir_remove(global_env);

	return (ret != 0 || ret_fake != 0);
}
