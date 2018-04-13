// standard includes
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

int64_t now = 1523701784;

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

dynarray_declare(entry, knot_db_val_t, static, 256);
dynarray_define(entry, knot_db_val_t, static);

int main(int argc, char *argv[])
{
	if (argc < 2 || argv[1][0] == '-') {
		printf("Usage: %s <path/to/kres/cache>\n", argv[0]);
		return 0;
	}

	const char *cache = argv[1];
	char cache_data[strlen(cache) + 10];
	snprintf(cache_data, sizeof(cache_data), "%s/data.mdb", cache);

	struct stat st = { 0 };
	if (stat(cache, &st) || !(st.st_mode & S_IFDIR) || stat(cache_data, &st)) {
		printf("Error: %s does not exist or is not a LMDB.\n", cache);
		return 1;
	}

	size_t cache_size = st.st_size;

	struct kr_cdb_opts opts = { cache, cache_size };
	struct kr_cache krc = { 0 };

	int ret = kr_cache_open(&krc, NULL, &opts, NULL);
	if (ret || krc.db == NULL) {
		printf("Error opening Resolver cache (%s).\n", kr_strerror(ret));
		return 2;
	}

	const knot_db_api_t *api = knot_db_lmdb_api();
	knot_db_txn_t txn = { 0 };
	knot_db_t *db = knot_db_t_kres2libknot(krc.db);
	if (db == NULL) {
		printf("Out of memory.\n");
		ret = KNOT_ENOMEM;
		goto fail;
	}

	ret = api->txn_begin(db, &txn, 0);
	if (ret != KNOT_EOK) {
		printf("Error starting DB transaction (%s).\n", knot_strerror(ret));
		goto fail;
	}

	knot_db_iter_t *it = NULL;
	it = api->iter_begin(&txn, KNOT_DB_FIRST);
	if (it == NULL) {
		printf("Error iterating DB.\n");
		ret = KNOT_ERROR;
		goto fail;
	}

	entry_dynarray_t to_del = { 0 };

	while (it != NULL) {
		knot_db_val_t key = { 0 }, val = { 0 };
		if ((ret = api->iter_key(it, &key)) != KNOT_EOK ||
		    (ret = api->iter_val(it, &val)) != KNOT_EOK) {
			printf("Warning: skipping a key due to error (%s).\n", knot_strerror(ret));
		}
		const uint16_t *entry_type = ret == KNOT_EOK ? key_consistent(key) : NULL;
		if (entry_type == NULL) {
			printf("Inconsistent entry.\n");
		} else {
			char type_s[32] = { 0 };
			knot_rrtype_to_string(*entry_type, type_s, sizeof(type_s));
			struct entry_h *entry = entry_h_consistent(val, *entry_type);
			int64_t over = entry->time + entry->ttl;
			over -= now;
			printf("%s time=%u ttl=%u rel=%ld\n", type_s, entry->time, entry->ttl, over);
			if (over < 0) {
				entry_dynarray_add(&to_del, &key);
			}
		}

		it = api->iter_next(it);
	}

	dynarray_foreach(entry, knot_db_val_t, i, to_del) {
		ret = api->del(&txn, i);
		if (ret != KNOT_EOK) {
			printf("Warning: skipping deleting because of error (%s)\n", knot_strerror(ret));
		}
	}

	entry_dynarray_free(&to_del);

	//api->iter_finish(it);
	//it = NULL;
	ret = api->txn_commit(&txn);
	txn.txn = NULL;

fail:
	api->iter_finish(it);
	if (txn.txn) {
		api->txn_abort(&txn);
	}

	free(db);
	kr_cache_close(&krc);

	return (ret ? 10 : 0);
}


