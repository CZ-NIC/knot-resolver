/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <time.h>
#include <dlfcn.h>
#include <ucw/mempool.h>

#include "tests/unit/test.h"
#include "lib/cache.h"
#include "lib/cache/cdb_lmdb.h"



knot_mm_t global_mm;
knot_rrset_t global_rr;
const char *global_env;
struct kr_cache_entry global_fake_ce;

#define NAMEDB_INTS 256
#define NAMEDB_DATA_SIZE (NAMEDB_INTS * sizeof(int))
uint8_t namedb_data[NAMEDB_DATA_SIZE];
knot_db_val_t global_namedb_data = {namedb_data, NAMEDB_DATA_SIZE};

#define CACHE_SIZE (64 * CPU_PAGE_SIZE)
#define CACHE_TTL 10
#define CACHE_TIME 0

int (*original_knot_rdataset_gather)(knot_rdataset_t *dst, knot_rdata_t **src,
		uint16_t count, knot_mm_t *mm) = NULL;

int knot_rdataset_gather(knot_rdataset_t *dst, knot_rdata_t **src, uint16_t count,
		knot_mm_t *mm)
{
	int err, err_mock;
	err_mock = (int)mock();
	if (original_knot_rdataset_gather == NULL) {
		original_knot_rdataset_gather = dlsym(RTLD_NEXT,"knot_rdataset_gather");
		assert_non_null (original_knot_rdataset_gather);
	}
	err = original_knot_rdataset_gather(dst, src, count, mm);
	if (err_mock != 0)
	    err = err_mock;
	return err;
}

/* Simulate init failure */
static int fake_test_init(knot_db_t **db, struct kr_cdb_opts *opts, knot_mm_t *pool)
{
	static char static_buffer[1024];
	*db = static_buffer;
	return mock();
}

static int fake_test_sync(knot_db_t *db)
{
	return 0;
}

static void fake_test_deinit(knot_db_t *db)
{
}

/* Stub for find */
static int fake_test_find(knot_db_t *db, knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	val->data = &global_fake_ce;
	return 0;
}

/* Stub for insert */
static int fake_test_ins(knot_db_t *db, knot_db_val_t *key, knot_db_val_t *val, int maxcount)
{
	struct kr_cache_entry *header = val->data;
	int  ret, err = (int)mock();
	if (val->len == sizeof(*header) + NAMEDB_DATA_SIZE) {
		header = val->data;
		ret = memcmp(header->data,namedb_data,NAMEDB_DATA_SIZE);
		if (header->timestamp != global_fake_ce.timestamp || header->ttl != global_fake_ce.ttl || ret != 0) {
			err = KNOT_EINVAL;
		}
	}
	return err;
}

/* Fake api */
static const struct kr_cdb_api *fake_knot_db_lmdb_api(void)
{
	static const struct kr_cdb_api api = {
		"lmdb_fake_api",
		fake_test_init, fake_test_deinit, NULL, NULL, fake_test_sync,
		fake_test_find, fake_test_ins, NULL,
		NULL, NULL
	};

	return &api;
}

/* Test cache open */
static int test_open(void **state, const struct kr_cdb_api *api)
{
	static struct kr_cache cache;
	struct kr_cdb_opts opts = {
		global_env,
		CACHE_SIZE,
	};
	memset(&cache, 0, sizeof(cache));
	*state = &cache;
	return kr_cache_open(&cache, api, &opts, &global_mm);
}

/* fake api test open */
static void test_open_fake_api(void **state)
{
	bool res = false;
	will_return(fake_test_init, KNOT_EINVAL);
	assert_int_equal(test_open(state, fake_knot_db_lmdb_api()), KNOT_EINVAL);
	will_return(fake_test_init, 0);
	assert_int_equal(test_open(state, fake_knot_db_lmdb_api()), 0);
	res = (((struct kr_cache *)(*state))->api == fake_knot_db_lmdb_api());
	assert_true(res);
}

static void test_open_conventional_api(void **state)
{
	bool res = false;
	assert_int_equal(test_open(state, NULL),0);
	res = (((struct kr_cache *)(*state))->api == kr_cdb_lmdb());
	assert_true(res);
}


/* Test cache teardown. */
static void test_close(void **state)
{
	kr_cache_close(*state);
	*state = NULL;
}

/* test invalid parameters and some api failures */
static void test_fake_invalid (void **state)
{
	const struct kr_cdb_api *api_saved = NULL;
	knot_dname_t dname[] = "";
	struct kr_cache *cache = *state;
	struct kr_cache_entry *entry = NULL;
	int ret = 0;

	ret = kr_cache_peek(cache, KR_CACHE_USER, dname, KNOT_RRTYPE_TSIG, &entry, 0);
	assert_int_equal(ret, 0);
	api_saved = cache->api;
	cache->api = NULL;
	ret = kr_cache_peek(cache, KR_CACHE_USER, dname, KNOT_RRTYPE_TSIG, &entry, 0);
	cache->api = api_saved;
	assert_int_not_equal(ret, 0);
	kr_cache_sync(cache);
}

static void test_fake_insert(void **state)
{
	int ret_cache_ins_ok, ret_cache_ins_inval;
	knot_dname_t dname[] = "";
	struct kr_cache *cache = (*state);
	test_randstr((char *)&global_fake_ce, sizeof(global_fake_ce));
	test_randstr((char *)namedb_data, NAMEDB_DATA_SIZE);

	will_return(fake_test_ins, 0);
	ret_cache_ins_ok = kr_cache_insert(cache, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data);
	will_return(fake_test_ins,KNOT_EINVAL);
	ret_cache_ins_inval = kr_cache_insert(cache, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data);
	assert_int_equal(ret_cache_ins_ok, 0);
	assert_int_equal(ret_cache_ins_inval, KNOT_EINVAL);
	kr_cache_sync(cache);
}

/* Test invalid parameters and some api failures. */
static void test_invalid(void **state)
{
	knot_dname_t dname[] = "";
	uint32_t timestamp = CACHE_TIME;
	struct kr_cache_entry *entry = NULL;
	struct kr_cache *cache = (*state);
	struct kr_cdb_opts opts = {
		global_env,
		CACHE_SIZE,
	};

	knot_rrset_init_empty(&global_rr);

	assert_int_equal(kr_cache_open(NULL, NULL, &opts, &global_mm),KNOT_EINVAL);
	assert_int_not_equal(kr_cache_peek(NULL, KR_CACHE_USER, dname, KNOT_RRTYPE_TSIG, NULL, &timestamp), 0);
	assert_int_not_equal(kr_cache_peek(cache, KR_CACHE_USER, NULL, KNOT_RRTYPE_TSIG, &entry, &timestamp), 0);
	assert_int_not_equal(kr_cache_peek_rr(NULL, NULL, NULL, NULL, NULL), 0);
	assert_int_not_equal(kr_cache_peek_rr(cache, NULL, NULL, NULL, NULL), 0);
	assert_int_not_equal(kr_cache_insert_rr(cache, NULL, 0, 0, 0), 0);
	assert_int_not_equal(kr_cache_insert_rr(NULL, NULL, 0, 0, 0), 0);
	assert_int_not_equal(kr_cache_insert(NULL, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data), 0);
	assert_int_not_equal(kr_cache_insert(cache, KR_CACHE_USER, NULL,
		KNOT_RRTYPE_TSIG, &global_fake_ce, global_namedb_data), 0);
	assert_int_not_equal(kr_cache_insert(cache, KR_CACHE_USER, dname,
		KNOT_RRTYPE_TSIG, NULL, global_namedb_data), 0);
	assert_int_not_equal(kr_cache_remove(cache, 0, NULL, 0), 0);
	assert_int_not_equal(kr_cache_remove(cache, KR_CACHE_RR, NULL, 0), 0);
	assert_int_not_equal(kr_cache_remove(NULL, 0, NULL, 0), 0);
	assert_int_not_equal(kr_cache_clear(NULL), 0);
	kr_cache_sync(cache);
}

/* Test cache write */
static void test_insert_rr(void **state)
{
	test_random_rr(&global_rr, CACHE_TTL);
	struct kr_cache *cache = (*state);
	int ret = kr_cache_insert_rr(cache, &global_rr, 0, 0, CACHE_TIME);
	assert_int_equal(ret, 0);
	kr_cache_sync(cache);
}

static void test_materialize(void **state)
{
	return; /* will be gone or need big rework in 2.0.0 anyway */
	knot_rrset_t output_rr;
	knot_dname_t * owner_saved = global_rr.owner;
	bool res_cmp_ok_empty, res_cmp_fail_empty;
	bool res_cmp_ok, res_cmp_fail;

	global_rr.owner = NULL;
	knot_rrset_init(&output_rr, NULL, 0, 0);
	kr_cache_materialize(&output_rr, &global_rr, 0, &global_mm);
	res_cmp_ok_empty = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_HEADER);
	res_cmp_fail_empty = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_WHOLE);
	knot_rrset_clear(&output_rr, &global_mm);
	global_rr.owner = owner_saved;
	assert_true(res_cmp_ok_empty);
	assert_false(res_cmp_fail_empty);

	knot_rrset_init(&output_rr, NULL, 0, 0);
	will_return (knot_rdataset_gather, 0);
	kr_cache_materialize(&output_rr, &global_rr, 0, &global_mm);
	res_cmp_ok = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_WHOLE);
	knot_rrset_clear(&output_rr, &global_mm);
	assert_true(res_cmp_ok);

	knot_rrset_init(&output_rr, NULL, 0, 0);
	will_return (knot_rdataset_gather, KNOT_ENOMEM);
	kr_cache_materialize(&output_rr, &global_rr, 0, &global_mm);
	res_cmp_fail = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_WHOLE);
	knot_rrset_clear(&output_rr, &global_mm);
	assert_false(res_cmp_fail);
}

/* Test cache read */
static void test_query(void **state)
{
	struct kr_cache *cache = (*state);
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	for (uint32_t timestamp = CACHE_TIME; timestamp < CACHE_TIME + CACHE_TTL; ++timestamp) {
		uint8_t rank = 0;
		uint8_t flags = 0;
		uint32_t drift = timestamp;
		int query_ret = kr_cache_peek_rr(cache, &cache_rr, &rank, &flags, &drift);
		bool rr_equal = knot_rrset_equal(&global_rr, &cache_rr, KNOT_RRSET_COMPARE_WHOLE);
		assert_int_equal(query_ret, 0);
		assert_true(rr_equal);
	}
	kr_cache_sync(cache);
}

/* Test cache read (simulate aged entry) */
static void test_query_aged(void **state)
{
	uint8_t rank = 0;
	uint8_t flags = 0;
	uint32_t timestamp = CACHE_TIME + CACHE_TTL + 1;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	struct kr_cache *cache = (*state);
	int ret = kr_cache_peek_rr(cache, &cache_rr, &rank, &flags, &timestamp);
	assert_int_equal(ret, kr_error(ESTALE));
	kr_cache_sync(cache);
}

/* Test cache removal */
static void test_remove(void **state)
{
	uint8_t rank = 0;
	uint8_t flags = 0;
	uint32_t timestamp = CACHE_TIME;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	struct kr_cache *cache = (*state);
	int ret = kr_cache_remove(cache, KR_CACHE_RR, cache_rr.owner, cache_rr.type);
	assert_int_equal(ret, 0);
	ret = kr_cache_peek_rr(cache, &cache_rr, &rank, &flags, &timestamp);
	assert_int_equal(ret, KNOT_ENOENT);
	kr_cache_sync(cache);
}

/* Test cache fill */
static void test_fill(void **state)
{
	struct kr_cache *cache = (*state);

	/* Fill with random values. */
	int ret = 0;
	for (unsigned i = 0; i < CACHE_SIZE; ++i) {
		knot_rrset_t rr;
		test_random_rr(&rr, CACHE_TTL);
		ret = kr_cache_insert_rr(cache, &rr, 0, 0, CACHE_TTL - 1);
		if (ret != 0) {
			break;
		}
		ret = kr_cache_sync(cache);
		if (ret != 0) {
			break;
		}
	}

	/* Expect we run out of space */
	assert_int_equal(ret, kr_error(ENOSPC));
	kr_cache_sync(cache);
}

/* Test cache clear */
static void test_clear(void **state)
{
	struct kr_cache *cache = (*state);
	int preempt_ret = kr_cache_clear(cache);
	int count_ret = cache->api->count(cache->db);

	assert_int_equal(preempt_ret, 0);
	assert_int_equal(count_ret, 1); /* Version record */
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
