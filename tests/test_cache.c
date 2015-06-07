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

#include <libknot/internal/namedb/namedb_lmdb.h>
#include <ucw/mempool.h>

#include "tests/test.h"
#include "lib/cache.h"

#include <stdlib.h>
#include <time.h>
#include <dlfcn.h>

mm_ctx_t global_mm;
struct kr_cache_txn global_txn;
knot_rrset_t global_rr;
const char *global_env;
struct kr_cache_entry global_fake_ce;

#define NAMEDB_INTS 256
#define NAMEDB_DATA_SIZE (NAMEDB_INTS * sizeof(int))
uint8_t namedb_data[NAMEDB_DATA_SIZE];
namedb_val_t global_namedb_data = {namedb_data, NAMEDB_DATA_SIZE};
bool is_malloc_mocked = false;

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
static int fake_test_init(namedb_t **db_ptr, mm_ctx_t *mm, void *arg)
{
	static char db[1024];
	*db_ptr = db;
	return mock();
}

static void fake_test_deinit(namedb_t *db)
{
    return;
}

/* Simulate commit failure */
static int fake_test_commit(namedb_txn_t *txn)
{
	return KNOT_ESPACE;
}

/* Dummy abort */
static void fake_test_abort(namedb_txn_t *txn)
{
	return;
}

/* Stub for find */
static int fake_test_find(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags)
{
	val->data = &global_fake_ce;
	return KNOT_EOK;
}

/* Stub for insert */
static int fake_test_ins(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags)
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

static int fake_test_txn_begin(namedb_t *db, namedb_txn_t *txn, unsigned flags)
{
    return KNOT_EOK;
}

/* Fake api */
static namedb_api_t *fake_namedb_lmdb_api(void)
{
	static namedb_api_t fake_api = {
		"lmdb_fake_api",
		fake_test_init, fake_test_deinit,
		fake_test_txn_begin, fake_test_commit, fake_test_abort,
		NULL, NULL, fake_test_find, fake_test_ins, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL
	};

	return &fake_api;
}

/* Test cache open */
static int test_open(void **state, namedb_api_t *api)
{
	static struct kr_cache cache;
	struct namedb_lmdb_opts opts;
	memset(&cache, 0, sizeof(cache));
	memset(&opts, 0, sizeof(opts));
	opts.path = global_env;
	opts.mapsize = CACHE_SIZE;
	*state = &cache;
	return kr_cache_open(&cache, api, &opts, &global_mm);
}

/* fake api test open */
static void test_open_fake_api(void **state)
{
	bool res;
	will_return(fake_test_init,KNOT_EINVAL);
	assert_int_equal(test_open(state, fake_namedb_lmdb_api()),KNOT_EINVAL);
	will_return(fake_test_init,KNOT_EOK);
	assert_int_equal(test_open(state, fake_namedb_lmdb_api()),KNOT_EOK);
	res = (((struct kr_cache *)(*state))->api == fake_namedb_lmdb_api());
	assert_true(res);
}

static void test_open_conventional_api(void **state)
{
	bool res;
	assert_int_equal(test_open(state, NULL),KNOT_EOK);
	res = (((struct kr_cache *)(*state))->api == namedb_lmdb_api());
	assert_true(res);
}


/* Test cache teardown. */
static void test_close(void **state)
{
	kr_cache_close(*state);
	*state = NULL;
}

/* Open transaction */
static struct kr_cache_txn *test_txn_write(void **state)
{
	assert_non_null(*state);
	assert_int_equal(kr_cache_txn_begin(*state, &global_txn, 0), KNOT_EOK);
	return &global_txn;
}

/* Open transaction */
static struct kr_cache_txn *test_txn_rdonly(void **state)
{
	assert_non_null(*state);
	assert_int_equal(kr_cache_txn_begin(*state, &global_txn, NAMEDB_RDONLY), 0);
	return &global_txn;
}

/* test invalid parameters and some api failures */
static void test_fake_invalid (void **state)
{
	struct kr_cache_txn *txn = NULL;
	const namedb_api_t *api_saved = NULL;
	knot_dname_t dname[] = "";
	struct kr_cache_entry *entry = NULL;
	int ret = 0;

	assert_int_not_equal(kr_cache_txn_commit(txn), 0);
	txn = test_txn_write(state);
	assert_int_not_equal(kr_cache_txn_commit(txn), 0);
	ret = kr_cache_peek(txn, KR_CACHE_USER, dname, KNOT_RRTYPE_TSIG, &entry, 0);
	assert_int_equal(ret, 0);
	api_saved = txn->owner->api;
	txn->owner->api = NULL;
	ret = kr_cache_peek(txn, KR_CACHE_USER, dname, KNOT_RRTYPE_TSIG, &entry, 0);
	txn->owner->api = api_saved;
	assert_int_not_equal(ret, 0);
}

static void test_fake_insert(void **state)
{
	int ret_cache_ins_ok, ret_cache_lowmem, ret_cache_ins_inval;
	knot_dname_t dname[] = "";
	struct kr_cache_txn *txn = test_txn_write(state);
	test_randstr((char *)&global_fake_ce,sizeof(global_fake_ce));
	test_randstr((char *)namedb_data,NAMEDB_DATA_SIZE);

	is_malloc_mocked = true;
	will_return(malloc,KNOT_EINVAL);
	ret_cache_lowmem = kr_cache_insert(txn, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data);
	is_malloc_mocked = false;
	will_return(fake_test_ins,KNOT_EOK);
	ret_cache_ins_ok = kr_cache_insert(txn, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data);
	will_return(fake_test_ins,KNOT_EINVAL);
	ret_cache_ins_inval = kr_cache_insert(txn, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data);
	assert_int_equal(ret_cache_lowmem, KNOT_ENOMEM);
	assert_int_equal(ret_cache_ins_ok, KNOT_EOK);
	assert_int_equal(ret_cache_ins_inval, KNOT_EINVAL);
}

/* Test invalid parameters and some api failures. */
static void test_invalid(void **state)
{
	knot_dname_t dname[] = "";
	uint32_t timestamp = CACHE_TIME;
	struct namedb_lmdb_opts opts;
	struct kr_cache_entry *entry = NULL;

	memset(&opts, 0, sizeof(opts));
	opts.path = global_env;
	opts.mapsize = CACHE_SIZE;

	knot_rrset_init_empty(&global_rr);

	assert_int_equal(kr_cache_open(NULL, NULL, &opts, &global_mm),KNOT_EINVAL);
	assert_int_not_equal(kr_cache_txn_begin(NULL, &global_txn, 0), 0);
	assert_int_not_equal(kr_cache_txn_begin(*state, NULL, 0), 0);
	assert_int_not_equal(kr_cache_txn_commit(NULL), 0);
	assert_int_not_equal(kr_cache_peek(NULL, KR_CACHE_USER, dname, KNOT_RRTYPE_TSIG, NULL, &timestamp), 0);
	assert_int_not_equal(kr_cache_peek(&global_txn, 0, dname, KNOT_RRTYPE_TSIG, &entry, &timestamp), 0);
	assert_int_not_equal(kr_cache_peek(&global_txn, KR_CACHE_USER, NULL, KNOT_RRTYPE_TSIG, &entry, &timestamp), 0);
	assert_int_not_equal(kr_cache_peek_rr(NULL, NULL, NULL), 0);
	assert_int_not_equal(kr_cache_peek_rr(&global_txn, NULL, NULL), 0);
	assert_int_not_equal(kr_cache_insert_rr(&global_txn, NULL, 0), 0);
	assert_int_not_equal(kr_cache_insert_rr(NULL, NULL, 0), 0);
	assert_int_equal(kr_cache_insert_rr(&global_txn, &global_rr, 0), 0);
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

/* Test cache write */
static void test_insert_rr(void **state)
{
	test_random_rr(&global_rr, CACHE_TTL);
	struct kr_cache_txn *txn = test_txn_write(state);
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
	knot_dname_t * owner_saved = global_rr.owner;
	bool res_cmp_ok_empty, res_cmp_fail_empty;
	bool res_cmp_ok, res_cmp_fail;

	global_rr.owner = NULL;
	knot_rrset_init(&output_rr, NULL, 0, 0);
	kr_cache_materialize(&output_rr, &global_rr, 0, &global_mm);
	res_cmp_ok_empty = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_HEADER);
	res_cmp_fail_empty = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_WHOLE);
	knot_rrset_clear(&output_rr,&global_mm);
	global_rr.owner = owner_saved;
	assert_true(res_cmp_ok_empty);
	assert_false(res_cmp_fail_empty);

	knot_rrset_init(&output_rr, NULL, 0, 0);
	will_return (knot_rdataset_add,KNOT_EOK);
	kr_cache_materialize(&output_rr, &global_rr, 0, &global_mm);
	res_cmp_ok = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_WHOLE);
	knot_rrset_clear(&output_rr,&global_mm);
	assert_true(res_cmp_ok);

	knot_rrset_init(&output_rr, NULL, 0, 0);
	will_return (knot_rdataset_add,KNOT_EINVAL);
	kr_cache_materialize(&output_rr, &global_rr, 0, &global_mm);
	res_cmp_fail = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_WHOLE);
	knot_rrset_clear(&output_rr,&global_mm);
	assert_false(res_cmp_fail);
}

/* Test cache read */
static void test_query(void **state)
{

	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	struct kr_cache_txn *txn = test_txn_rdonly(state);

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
	uint32_t timestamp = CACHE_TIME + CACHE_TTL + 1;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	struct kr_cache_txn *txn = test_txn_rdonly(state);
	int ret = kr_cache_peek_rr(txn, &cache_rr, &timestamp);
	assert_int_equal(ret, kr_error(ESTALE));
	kr_cache_txn_abort(txn);
}

/* Test cache removal */
static void test_remove(void **state)
{
	uint32_t timestamp = CACHE_TIME;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	struct kr_cache_txn *txn = test_txn_write(state);
	int ret = kr_cache_remove(txn, KR_CACHE_RR, cache_rr.owner, cache_rr.type);
	assert_int_equal(ret, KNOT_EOK);
	ret = kr_cache_peek_rr(txn, &cache_rr, &timestamp);
	assert_int_equal(ret, KNOT_ENOENT);
	kr_cache_txn_commit(txn);
}

/* Test cache fill */
static void test_fill(void **state)
{
	struct kr_cache_txn *txn = test_txn_write(state);

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
	struct kr_cache_txn *txn = test_txn_write(state);
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

	/* Invalid input */
	const UnitTest tests_bad[] = {
		group_test_setup(test_open_fake_api),
		unit_test(test_fake_invalid),
	        unit_test(test_fake_insert),
		group_test_teardown(test_close)
	};

	const UnitTest tests[] = {
		/* Invalid input */
	        unit_test(test_invalid),
	        /* Cache persistence */
	        group_test_setup(test_open_conventional_api),
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

	int ret = run_group_tests(tests_bad);
	if (ret == 0) {
		ret = run_group_tests(tests);
	}

	/* Cleanup */
	test_tmpdir_remove(global_env);
	return ret;
}
