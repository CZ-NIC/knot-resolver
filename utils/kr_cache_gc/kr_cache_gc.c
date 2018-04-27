// standard includes
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>

// libknot includes
#include <libknot/libknot.h>

// resolver includes
#include <contrib/dynarray.h>
#include <lib/cache/api.h>
#include <lib/cache/impl.h>
#include <lib/defines.h>

#include "kr_cache_gc.h"

// TODO remove and use time(NULL) ! this is just for debug with pre-generated cache
int64_t now = 1524301784;

// section: timer
// TODO replace/move to contrib

typedef struct timespec gc_timer_t;
static gc_timer_t gc_timer_internal = { 0 };

static void gc_timer_start(gc_timer_t *t)
{
	(void)clock_gettime(CLOCK_MONOTONIC, t == NULL ? &gc_timer_internal : t);
}

static double gc_timer_end(gc_timer_t *t)
{
	gc_timer_t *start = t == NULL ? &gc_timer_internal : t;
	gc_timer_t end = { 0 };
	(void)clock_gettime(CLOCK_MONOTONIC, &end);
	return (((double)end.tv_sec - (double)start->tv_sec) + ((double)end.tv_nsec - (double)start->tv_nsec) / 1e9);
}

static unsigned long gc_timer_usecs(gc_timer_t *t)
{
	gc_timer_t *start = t == NULL ? &gc_timer_internal : t;
	gc_timer_t end = { 0 };
	(void)clock_gettime(CLOCK_MONOTONIC, &end);
	return ((end.tv_sec - start->tv_sec) * 1000000UL + (end.tv_nsec - start->tv_nsec) / 1000UL);
}

// section: function key_consistent

static const uint16_t *key_consistent(knot_db_val_t key)
{
	const static uint16_t NSEC1 = KNOT_RRTYPE_NSEC;
	uint8_t *p = key.data;
	while(*p != 0) {
		while(*p++ != 0) {
			if (p - (uint8_t *)key.data >= key.len) {
				return NULL;
			}
		}
	}
	if (p - (uint8_t *)key.data >= key.len) {
		return NULL;
	}
	switch (*++p) {
	case 'E':
		return (p + 2 - (uint8_t *)key.data >= key.len ? NULL : (uint16_t *)(p + 1));
	case '1':
		return &NSEC1;
	default:
		return NULL;
	}
}

// section: converting struct lmdb_env from resolver-format to libknot-format

struct libknot_lmdb_env
{
	bool shared;
	unsigned dbi;
	void *env;
	knot_mm_t *pool;
};

struct kres_lmdb_env
{
	size_t mapsize;
	unsigned dbi;
	void *env;
	// sub-struct txn ommited
};

static knot_db_t *knot_db_t_kres2libknot(const knot_db_t *db)
{
	const struct kres_lmdb_env *kres_db = db; // this is struct lmdb_env as in resolver/cdb_lmdb.c
	struct libknot_lmdb_env *libknot_db = malloc(sizeof(*libknot_db));
	if (libknot_db != NULL) {
		libknot_db->shared = false;
		libknot_db->pool = NULL;
		libknot_db->env = kres_db->env;
		libknot_db->dbi = kres_db->dbi;
	}
	return libknot_db;
}

// section: dbval_copy

static knot_db_val_t *dbval_copy(const knot_db_val_t *from)
{
	knot_db_val_t *to = malloc(sizeof(knot_db_val_t) + from->len);
	if (to != NULL) {
		memcpy(to, from, sizeof(knot_db_val_t));
		to->data = to + 1; // == ((uit8_t *)to) + sizeof(knot_db_val_t)
		memcpy(to->data, from->data, from->len);
	}
	return to;
}

// section: rrtype list

dynarray_declare(rrtype, uint16_t, DYNARRAY_VISIBILITY_STATIC, 64);
dynarray_define(rrtype, uint16_t, DYNARRAY_VISIBILITY_STATIC);

static void rrtypelist_add(rrtype_dynarray_t *arr, uint16_t add_type)
{
	bool already_present = false;
	dynarray_foreach(rrtype, uint16_t, i, *arr) {
		if (*i == add_type) {
			already_present = true;
			break;
		}
	}
	if (!already_present) {
		rrtype_dynarray_add(arr, &add_type);
	}
}

static void rrtypelist_print(rrtype_dynarray_t *arr)
{
	char type_s[32] = { 0 };
	dynarray_foreach(rrtype, uint16_t, i, *arr) {
		knot_rrtype_to_string(*i, type_s, sizeof(type_s));
		printf(" %s", type_s);
	}
	printf("\n");
}

// section: main

dynarray_declare(entry, knot_db_val_t*, DYNARRAY_VISIBILITY_STATIC, 256);
dynarray_define(entry, knot_db_val_t*, DYNARRAY_VISIBILITY_STATIC);


int kr_cache_gc(kr_cache_gc_cfg_t *cfg)
{
	char cache_data[strlen(cfg->cache_path) + 10];
	snprintf(cache_data, sizeof(cache_data), "%s/data.mdb", cfg->cache_path);

	struct stat st = { 0 };
	if (stat(cfg->cache_path, &st) || !(st.st_mode & S_IFDIR) || stat(cache_data, &st)) {
		printf("Error: %s does not exist or is not a LMDB.\n", cfg->cache_path);
		return -ENOENT;
	}

	size_t cache_size = st.st_size;

	struct kr_cdb_opts opts = { cfg->cache_path, cache_size };
	struct kr_cache krc = { 0 };

	int ret = kr_cache_open(&krc, NULL, &opts, NULL);
	if (ret || krc.db == NULL) {
		printf("Error opening Resolver cache (%s).\n", kr_strerror(ret));
		return -EINVAL;
	}

	entry_dynarray_t to_del = { 0 };
	rrtype_dynarray_t cache_rrtypes = { 0 };

	gc_timer_t timer_analyze = { 0 }, timer_delete = { 0 }, timer_rw_txn = { 0 };

	const knot_db_api_t *api = knot_db_lmdb_api();
	knot_db_txn_t txn = { 0 };
	knot_db_iter_t *it = NULL;
	knot_db_t *db = knot_db_t_kres2libknot(krc.db);
	if (db == NULL) {
		printf("Out of memory.\n");
		ret = KNOT_ENOMEM;
		goto fail;
	}

	size_t real_size = knot_db_lmdb_get_mapsize(db), usage = knot_db_lmdb_get_usage(db);
	printf("Cache size: %zu, Usage: %zu (%.2lf%%)\n", real_size, usage, (double)usage / real_size * 100.0);

	gc_timer_start(&timer_analyze);

	ret = api->txn_begin(db, &txn, KNOT_DB_RDONLY);
	if (ret != KNOT_EOK) {
		printf("Error starting DB transaction (%s).\n", knot_strerror(ret));
		goto fail;
	}

	it = api->iter_begin(&txn, KNOT_DB_FIRST);
	if (it == NULL) {
		printf("Error iterating DB.\n");
		ret = KNOT_ERROR;
		goto fail;
	}

	size_t cache_records = 0, deleted_records = 0;
	size_t oversize_records = 0, already_gone = 0;;
	size_t used_space = 0, rw_txn_count = 1;
	int64_t min_expire = INT64_MAX;

	while (it != NULL) {
		knot_db_val_t key = { 0 }, val = { 0 };
		if ((ret = api->iter_key(it, &key)) != KNOT_EOK ||
		    (ret = api->iter_val(it, &val)) != KNOT_EOK) {
			printf("Warning: skipping a key due to error (%s).\n", knot_strerror(ret));
		}
		const uint16_t *entry_type = ret == KNOT_EOK ? key_consistent(key) : NULL;
		if (entry_type != NULL) {
			cache_records++;
			rrtypelist_add(&cache_rrtypes, *entry_type);

			struct entry_h *entry = entry_h_consistent(val, *entry_type);
			int64_t over = entry->time + entry->ttl;
			over -= now;
			if (over < min_expire) {
				min_expire = over;
			}
			if (over < 0) {
				knot_db_val_t *todelete;
				if ((cfg->temp_keys_space > 0 &&
				     used_space + key.len + sizeof(key) > cfg->temp_keys_space) ||
				    (todelete = dbval_copy(&key)) == NULL) {
					oversize_records++;
				} else {
					used_space += todelete->len + sizeof(*todelete);
					entry_dynarray_add(&to_del, &todelete);
				}
			}
		}

		it = api->iter_next(it);
	}

	api->txn_abort(&txn);

	printf("Cache analyzed in %.2lf secs, %zu records types", gc_timer_end(&timer_analyze), cache_records);
	rrtypelist_print(&cache_rrtypes);
	if (min_expire < INT64_MAX) {
		printf("Minimum expire in %"PRId64" secs\n", min_expire);
	}
	printf("%zu records to be deleted using %.2lf MBytes of temporary memory, %zu records skipped due to memory limit.\n",
	       to_del.size, ((double)used_space / 1048576.0), oversize_records);
	rrtype_dynarray_free(&cache_rrtypes);

	gc_timer_start(&timer_delete);
	gc_timer_start(&timer_rw_txn);
	rrtype_dynarray_t deleted_rrtypes = { 0 };

	ret = api->txn_begin(db, &txn, 0);
	if (ret != KNOT_EOK) {
		printf("Error starting DB transaction (%s).\n", knot_strerror(ret));
		goto fail;
	}

	dynarray_foreach(entry, knot_db_val_t*, i, to_del) {
		ret = api->del(&txn, *i);
		switch (ret) {
		case KNOT_EOK:
			deleted_records++;
			const uint16_t *entry_type = ret == KNOT_EOK ? key_consistent(**i) : NULL;
			assert(entry_type != NULL);
			rrtypelist_add(&deleted_rrtypes, *entry_type);
			break;
		case KNOT_ENOENT:
			already_gone++;
			break;
		default:
			printf("Warning: skipping deleting because of error (%s)\n", knot_strerror(ret));
			continue;
		}
		if ((cfg->rw_txn_items > 0 &&
		     (deleted_records + already_gone) % cfg->rw_txn_items == 0) ||
		    (cfg->rw_txn_duration > 0 &&
		     gc_timer_usecs(&timer_rw_txn) > cfg->rw_txn_duration)) {
			ret = api->txn_commit(&txn);
			if (ret == KNOT_EOK) {
				rw_txn_count++;
				usleep(cfg->rw_txn_delay);
				gc_timer_start(&timer_rw_txn);
				ret = api->txn_begin(db, &txn, 0);
			}
			if (ret != KNOT_EOK) {
				printf("Error restarting DB transaction (%s)\n", knot_strerror(ret));
				goto fail;
			}
		}
	}

	printf("Deleted %zu records (%zu already gone) types", deleted_records, already_gone);
	rrtypelist_print(&deleted_rrtypes);
	printf("It took %.2lf secs, %zu transactions \n", gc_timer_end(&timer_delete), rw_txn_count);

	ret = api->txn_commit(&txn);
	txn.txn = NULL;

fail:
	rrtype_dynarray_free(&deleted_rrtypes);
	dynarray_foreach(entry, knot_db_val_t*, i, to_del) {
		free(*i);
	}
	entry_dynarray_free(&to_del);

	api->iter_finish(it);
	if (txn.txn) {
		api->txn_abort(&txn);
	}

	free(db);
	kr_cache_close(&krc);

	return ret;
}
