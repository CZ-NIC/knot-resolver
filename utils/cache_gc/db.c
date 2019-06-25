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

int kr_gc_cache_open(const char *cache_path, struct kr_cache *kres_db, knot_db_t **libknot_db)
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
	const static uint16_t NSEC3 = KNOT_RRTYPE_NSEC3;
	const uint8_t *kd = key.data;
	ssize_t i;
	/* CACHE_KEY_DEF */
	if (key.len >= 2 && kd[0] == '\0') {
                /* Beware: root zone is special and starts with
		 *         a single \0 followed by type sign */
                i = 1;
	} else {
		/* find the first double zero in the key */
                for (i = 2; !kd[i - 1] == 0 || !kd[i - 2] == 0; ++i) {
                    if (i >= key.len)
			    return NULL;
                }
	}
	// the next character can be used for classification
	switch (kd[i]) {
	case 'E':
		if (i + 1 + sizeof(uint16_t) > key.len) {
			assert(!EINVAL);
			return NULL;
		}
		return (uint16_t *)&kd[i + 1];
	case '1':
		return &NSEC1;
	case '3':
		return &NSEC3;
	default:
		return NULL;
	}
}

/// expects that key is consistent! CACHE_KEY_DEF
static uint8_t entry_labels(knot_db_val_t *key, uint16_t rrtype)
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
	if (rrtype == KNOT_RRTYPE_NSEC3) {
		// We don't know the number of labels so easily,
		// but let's classify everything as directly
		// below the zone apex (that's most common).
		++lab;
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

			if (entry != NULL) {
				info.rrtype = *entry_type;
				info.entry_size = key.len + val.len;
				info.expires_in = entry->time + entry->ttl - now;
				info.no_labels = entry_labels(&key, *entry_type);

				ret = callback(&key, &info, ctx);
			}
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
