/* SPDX-License-Identifier: GPL-3.0-or-later */
// standard includes
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>

// libknot includes
#include <libknot/libknot.h>

// resolver includes
#include <contrib/dynarray.h>
#include <lib/cache/api.h>
#include <lib/cache/impl.h>
#include <lib/defines.h>
#include "lib/cache/cdb_lmdb.h"
#include "lib/utils.h"

#include "kr_cache_gc.h"

#include "categories.h"
#include "db.h"

// section: timer
// TODO replace/move to contrib

typedef struct timespec gc_timer_t;
static gc_timer_t gc_timer_internal = { 0 };

static void gc_timer_start(gc_timer_t * t)
{
	(void)clock_gettime(CLOCK_MONOTONIC, t == NULL ? &gc_timer_internal : t);
}

static double gc_timer_end(gc_timer_t * t)
{
	gc_timer_t *start = t == NULL ? &gc_timer_internal : t;
	gc_timer_t end = { 0 };
	(void)clock_gettime(CLOCK_MONOTONIC, &end);
	return (((double)end.tv_sec - (double)start->tv_sec) +
		((double)end.tv_nsec - (double)start->tv_nsec) / 1e9);
}

static unsigned long gc_timer_usecs(gc_timer_t * t)
{
	gc_timer_t *start = t == NULL ? &gc_timer_internal : t;
	gc_timer_t end = { 0 };
	(void)clock_gettime(CLOCK_MONOTONIC, &end);
	return ((end.tv_sec - start->tv_sec) * 1000000UL +
		(end.tv_nsec - start->tv_nsec) / 1000UL);
}

// section: dbval_copy

static knot_db_val_t *dbval_copy(const knot_db_val_t * from)
{
	knot_db_val_t *to = malloc(sizeof(knot_db_val_t) + from->len);
	if (to != NULL) {
		memcpy(to, from, sizeof(knot_db_val_t));
		to->data = to + 1;	// == ((uit8_t *)to) + sizeof(knot_db_val_t)
		memcpy(to->data, from->data, from->len);
	}
	return to;
}

// section: rrtype list

dynarray_declare(rrtype, uint16_t, DYNARRAY_VISIBILITY_STATIC, 64)
    dynarray_define(rrtype, uint16_t, DYNARRAY_VISIBILITY_STATIC)
static void rrtypelist_add(rrtype_dynarray_t * arr, uint16_t add_type)
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

static void rrtypelist_print(rrtype_dynarray_t * arr)
{
	char type_s[32] = { 0 };
	dynarray_foreach(rrtype, uint16_t, i, *arr) {
		knot_rrtype_to_string(*i, type_s, sizeof(type_s));
		printf(" %s", type_s);
	}
	printf("\n");
}

dynarray_declare(entry, knot_db_val_t *, DYNARRAY_VISIBILITY_STATIC, 256)
    dynarray_define(entry, knot_db_val_t *, DYNARRAY_VISIBILITY_STATIC)
static void entry_dynarray_deep_free(entry_dynarray_t * d)
{
	dynarray_foreach(entry, knot_db_val_t *, i, *d) {
		free(*i);
	}
	entry_dynarray_free(d);
}

typedef struct {
	size_t categories_sizes[CATEGORIES];
	size_t records;
} ctx_compute_categories_t;

int cb_compute_categories(const knot_db_val_t * key, gc_record_info_t * info,
			  void *vctx)
{
	ctx_compute_categories_t *ctx = vctx;
	category_t cat = kr_gc_categorize(info);
	(void)key;
	ctx->categories_sizes[cat] += info->entry_size;
	ctx->records++;
	return KNOT_EOK;
}

typedef struct {
	category_t limit_category;
	entry_dynarray_t to_delete;
	size_t cfg_temp_keys_space;
	size_t used_space;
	size_t oversize_records;
} ctx_delete_categories_t;

int cb_delete_categories(const knot_db_val_t * key, gc_record_info_t * info,
			 void *vctx)
{
	ctx_delete_categories_t *ctx = vctx;
	category_t cat = kr_gc_categorize(info);
	if (cat >= ctx->limit_category) {
		knot_db_val_t *todelete = dbval_copy(key);
		size_t used = ctx->used_space + key->len + sizeof(*key);
		if ((ctx->cfg_temp_keys_space > 0 &&
		     used > ctx->cfg_temp_keys_space) || todelete == NULL) {
			ctx->oversize_records++;
		} else {
			entry_dynarray_add(&ctx->to_delete, &todelete);
			ctx->used_space = used;
		}
	}
	return KNOT_EOK;
}

struct kr_cache_gc_state {
	struct kr_cache kres_db;
	knot_db_t *db;
};

void kr_cache_gc_free_state(kr_cache_gc_state_t **state)
{
	assert(state);
	if (!*state) { // not open
		return;
	}
	kr_gc_cache_close(&(*state)->kres_db, (*state)->db);
	free(*state);
	*state = NULL;
}

int kr_cache_gc(kr_cache_gc_cfg_t *cfg, kr_cache_gc_state_t **state)
{
	// The whole function works in four "big phases":
	//// 1. find out whether we should even do analysis and deletion.
	assert(cfg && state);
	int ret;
	// Ensure that we have open and "healthy" cache.
	if (!*state) {
		*state = calloc(1, sizeof(**state));
		if (!*state) {
			return KNOT_ENOMEM;
		}
		ret = kr_gc_cache_open(cfg->cache_path, &(*state)->kres_db,
					   &(*state)->db);
	} else { // To be sure, we guard against the file getting replaced.
		ret = kr_gc_cache_check_health(&(*state)->kres_db, &(*state)->db);
		// In particular, missing data.mdb gives us kr_error(ENOENT) == KNOT_ENOENT
	}
	if (ret) {
		free(*state);
		*state = NULL;
		return ret;
	}
	knot_db_t *const db = (*state)->db; // frequently used shortcut

	const double db_usage = kr_cdb_lmdb()->usage_percent(db);
	const bool large_usage = db_usage >= cfg->cache_max_usage;
	if (cfg->dry_run || large_usage) {	// don't print this on every size check
		printf("Usage: %.2lf%%\n", db_usage);
	}
	if (cfg->dry_run || !large_usage) {
		return KNOT_EOK;
	}

	//// 2. classify all cache items into categories
	//      and compute which categories to delete.
	gc_timer_t timer_analyze = { 0 }, timer_choose = { 0 }, timer_delete =
	    { 0 }, timer_rw_txn = { 0 };

	gc_timer_start(&timer_analyze);
	ctx_compute_categories_t cats = { { 0 }
	};
	ret = kr_gc_cache_iter(db, cfg, cb_compute_categories, &cats);
	if (ret != KNOT_EOK) {
		kr_cache_gc_free_state(state);
		return ret;
	}

	//ssize_t amount_tofree = knot_db_lmdb_get_mapsize(db) * cfg->cache_to_be_freed / 100;
	// Mixing ^^ page usage and entry sizes (key+value lengths) didn't work
	// too well, probably due to internal fragmentation after some GC cycles.
	// Therefore let's scale this by the ratio of these two sums.
	ssize_t cats_sumsize = 0;
	for (int i = 0; i < CATEGORIES; ++i) {
		cats_sumsize += cats.categories_sizes[i];
	}
	/* use less precise variant to avoid 32-bit overflow */
	ssize_t amount_tofree = cats_sumsize / 100 * cfg->cache_to_be_freed;

	kr_log_verbose("tofree: %zd / %zd\n", amount_tofree, cats_sumsize);
	if (VERBOSE_STATUS) {
		for (int i = 0; i < CATEGORIES; i++) {
			if (cats.categories_sizes[i] > 0) {
				printf("category %.2d size %zu\n", i,
				       cats.categories_sizes[i]);
			}
		}
	}

	category_t limit_category = CATEGORIES;
	while (limit_category > 0 && amount_tofree > 0) {
		amount_tofree -= cats.categories_sizes[--limit_category];
	}

	printf("Cache analyzed in %.0lf msecs, %zu records, limit category is %d.\n",
	       gc_timer_end(&timer_analyze) * 1000, cats.records, limit_category);

	//// 3. pass whole cache again to collect a list of keys that should be deleted.
	gc_timer_start(&timer_choose);
	ctx_delete_categories_t to_del = { 0 };
	to_del.cfg_temp_keys_space = cfg->temp_keys_space;
	to_del.limit_category = limit_category;
	ret = kr_gc_cache_iter(db, cfg, cb_delete_categories, &to_del);
	if (ret != KNOT_EOK) {
		entry_dynarray_deep_free(&to_del.to_delete);
		kr_cache_gc_free_state(state);
		return ret;
	}
	printf
	    ("%zu records to be deleted using %.2lf MBytes of temporary memory, %zu records skipped due to memory limit.\n",
	     to_del.to_delete.size, ((double)to_del.used_space / 1048576.0),
	     to_del.oversize_records);

	//// 4. execute the planned deletions.
	const knot_db_api_t *api = knot_db_lmdb_api();
	knot_db_txn_t txn = { 0 };
	size_t deleted_records = 0, already_gone = 0, rw_txn_count = 0;

	gc_timer_start(&timer_delete);
	gc_timer_start(&timer_rw_txn);
	rrtype_dynarray_t deleted_rrtypes = { 0 };

	ret = api->txn_begin(db, &txn, 0);
	if (ret != KNOT_EOK) {
		printf("Error starting R/W DB transaction (%s).\n",
		       knot_strerror(ret));
		entry_dynarray_deep_free(&to_del.to_delete);
		kr_cache_gc_free_state(state);
		return ret;
	}

	dynarray_foreach(entry, knot_db_val_t *, i, to_del.to_delete) {
		ret = api->del(&txn, *i);
		switch (ret) {
		case KNOT_EOK:
			deleted_records++;
			const uint16_t *entry_type = kr_gc_key_consistent(**i);
			assert(entry_type != NULL);
			rrtypelist_add(&deleted_rrtypes, *entry_type);
			break;
		case KNOT_ENOENT:
			already_gone++;
			if (VERBOSE_STATUS) {
				// kresd normally only inserts (or overwrites),
				// so it's generally suspicious when a key goes missing.
				printf("Record already gone (key len %zu): ", (*i)->len);
				debug_printbin((*i)->data, (*i)->len);
				printf("\n");
			}
			break;
		case KNOT_ESPACE:
			printf("Warning: out of space, bailing out to retry later.\n");
			api->txn_abort(&txn);
			goto finish;
		default:
			printf("Warning: skipping deletion because of error (%s)\n",
			       knot_strerror(ret));
			api->txn_abort(&txn);
			ret = api->txn_begin(db, &txn, 0);
			if (ret != KNOT_EOK) {
				printf
				    ("Error: can't begin txn because of error (%s)\n",
				     knot_strerror(ret));
				goto finish;
			}
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
				printf("Error: transaction failed (%s)\n",
				       knot_strerror(ret));
				goto finish;
			}
		}
	}
	ret = api->txn_commit(&txn);

finish:
	printf("Deleted %zu records (%zu already gone) types", deleted_records,
	       already_gone);
	rrtypelist_print(&deleted_rrtypes);
	printf("It took %.0lf msecs, %zu transactions (%s)\n\n",
	       gc_timer_end(&timer_delete) * 1000, rw_txn_count, knot_strerror(ret));

	rrtype_dynarray_free(&deleted_rrtypes);
	entry_dynarray_deep_free(&to_del.to_delete);

	// OK, let's close it in this case.
	kr_cache_gc_free_state(state);

	return ret;
}
