#include "db.h"

#include <lib/cache/impl.h>
//#include <lib/defines.h>

#include <time.h>
#include <sys/stat.h>

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

int kr_gc_cache_open(const char *cache_path, struct kr_cache *kres_db, knot_db_t **libknot_db, double *usage)
{
	char cache_data[strlen(cache_path) + 10];
	snprintf(cache_data, sizeof(cache_data), "%s/data.mdb", cache_path);

	struct stat st = { 0 };
	if (stat(cache_path, &st) || !(st.st_mode & S_IFDIR) || stat(cache_data, &st)) {
		printf("Error: %s does not exist or is not a LMDB.\n", cache_path);
		return -ENOENT;
	}

	size_t cache_size = st.st_size;

	struct kr_cdb_opts opts = { cache_path, cache_size };

open_kr_cache:
	;
	int ret = kr_cache_open(kres_db, NULL, &opts, NULL);
	if (ret || kres_db->db == NULL) {
		printf("Error opening Resolver cache (%s).\n", kr_strerror(ret));
		return -EINVAL;
	}

	*libknot_db = knot_db_t_kres2libknot(kres_db->db);
	if (*libknot_db == NULL) {
		printf("Out of memory.\n");
		return -ENOMEM;
	}

	size_t real_size = knot_db_lmdb_get_mapsize(*libknot_db), usageb = knot_db_lmdb_get_usage(*libknot_db);
	*usage = (double)usageb / real_size * 100.0;
	printf("Cache size: %zu, Usage: %zu (%.2lf%%)\n", real_size, usageb, *usage);

#if 1
	if (*usage > 90.0) {
		free(*libknot_db);
		kr_cache_close(kres_db);
		cache_size += cache_size / 10;
		opts.maxsize = cache_size;
		goto open_kr_cache;
	}
# endif
	return 0;
}

void kr_gc_cache_close(struct kr_cache *kres_db, knot_db_t *knot_db)
{
	free(knot_db);
	kr_cache_close(kres_db);
}

const uint16_t *kr_gc_key_consistent(knot_db_val_t key)
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

// expects that key is consistent!
static uint8_t entry_labels(knot_db_val_t *key)
{
	uint8_t lab = 0, *p = key->data;
	while (*p != 0) {
		while (*p++ != 0) {
			if (p - (uint8_t *)key->data >= key->len) {
				return 0;
			}
		}
		lab++;
	}
	return lab;
}

int kr_gc_cache_iter(knot_db_t *knot_db, kr_gc_iter_callback callback, void *ctx)
{
	knot_db_txn_t txn = { 0 };
	knot_db_iter_t *it = NULL;
	const knot_db_api_t *api = knot_db_lmdb_api();
	gc_record_info_t info = { 0 };
	int64_t now = time(NULL);

	int ret = api->txn_begin(knot_db, &txn, KNOT_DB_RDONLY);
	if (ret != KNOT_EOK) {
		printf("Error starting DB transaction (%s).\n", knot_strerror(ret));
		return ret;
	}

	it = api->iter_begin(&txn, KNOT_DB_FIRST);
	if (it == NULL) {
		printf("Error iterationg database.\n");
		api->txn_abort(&txn);
		return KNOT_ERROR;
	}

	while (it != NULL) {
		knot_db_val_t key = { 0 }, val = { 0 };
		ret = api->iter_key(it, &key);
		if (ret == KNOT_EOK) {
			ret = api->iter_val(it, &val);
		}

		const uint16_t *entry_type = ret == KNOT_EOK ? kr_gc_key_consistent(key) : NULL;
		if (entry_type != NULL) {
			struct entry_h *entry = entry_h_consistent(val, *entry_type);

			info.rrtype = *entry_type;
			info.entry_size = key.len + val.len;
			info.expires_in = entry->time + entry->ttl - now;
			info.no_labels = entry_labels(&key);

			ret = callback(&key, &info, ctx);
		}

		if (ret != KNOT_EOK) {
			printf("Error iterating database (%s).\n", knot_strerror(ret));
			api->iter_finish(it);
			api->txn_abort(&txn);
			return ret;
		}

		it = api->iter_next(it);
	}

	api->txn_abort(&txn);
	return KNOT_EOK;
}
