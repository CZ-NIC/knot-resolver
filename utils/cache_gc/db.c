/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "db.h"

#include "lib/cache/cdb_lmdb.h"
#include "lib/cache/impl.h"

#include <ctype.h>
#include <time.h>
#include <sys/stat.h>

int kr_gc_cache_open(const char *cache_path, struct kr_cache *kres_db,
		     knot_db_t ** libknot_db)
{
	char cache_data[strlen(cache_path) + 10];
	snprintf(cache_data, sizeof(cache_data), "%s/data.mdb", cache_path);

	struct stat st = { 0 };
	if (stat(cache_path, &st) || !(st.st_mode & S_IFDIR)
	    || stat(cache_data, &st)) {
		printf("Error: %s does not exist or is not a LMDB.\n", cache_path);
		return -ENOENT;
	}

	struct kr_cdb_opts opts = { .path = cache_path, .maxsize = 0/*don't resize*/ };

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

int kr_gc_cache_check_health(struct kr_cache *kres_db, knot_db_t ** libknot_db)
{
	int ret = kr_cache_check_health(kres_db, 0);
	if (ret == 0) {
		return 0;
	} else if (ret != 1) {
		kr_gc_cache_close(kres_db, *libknot_db);
		return ret;
	}
	/* Cache was reopen. */
	free(*libknot_db);
	*libknot_db = knot_db_t_kres2libknot(kres_db->db);
	if (*libknot_db == NULL) {
		printf("Out of memory.\n");
		return -ENOMEM;
	}
	return 0;
}

void kr_gc_cache_close(struct kr_cache *kres_db, knot_db_t * knot_db)
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
		for (i = 2; kd[i - 1] || kd[i - 2]; ++i) {
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
		return (uint16_t *) & kd[i + 1];
	case '1':
		return &NSEC1;
	case '3':
		return &NSEC3;
	default:
		return NULL;
	}
}

/// expects that key is consistent! CACHE_KEY_DEF
static uint8_t entry_labels(knot_db_val_t * key, uint16_t rrtype)
{
	uint8_t lab = 0, *p = key->data;
	while (*p != 0) {
		while (*p++ != 0) {
			if (p - (uint8_t *) key->data >= key->len) {
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

void debug_printbin(const char *str, unsigned int len)
{
	putchar('"');
	for (int idx = 0; idx < len; idx++) {
		char c = str[idx];
		if (isprint(c))
			putchar(c);
		else
			printf("`%02x`", c);
	}
	putchar('"');
}

/** Return one entry_h reference from a cache DB value.  NULL if not consistent/suitable. */
static const struct entry_h *val2entry(const knot_db_val_t val, uint16_t ktype)
{
	if (ktype != KNOT_RRTYPE_NS)
		return entry_h_consistent(val, ktype);
	/* Otherwise we have a multi-purpose entry.
	 * Well, for now we simply choose the most suitable entry;
	 * the only realistic collision is DNAME in apex where we'll prefer NS. */
	entry_list_t el;
	if (entry_list_parse(val, el))
		return NULL;
	for (int i = ENTRY_APEX_NSECS_CNT; i < EL_LENGTH; ++i) {
		if (el[i].len)
			return entry_h_consistent(el[i], EL2RRTYPE(i));
	}
	/* Only NSEC* meta-data inside. */
	return NULL;
}

int kr_gc_cache_iter(knot_db_t * knot_db, const  kr_cache_gc_cfg_t *cfg,
			kr_gc_iter_callback callback, void *ctx)
{
	unsigned int counter_iter = 0;
	unsigned int counter_gc_consistent = 0;
	unsigned int counter_kr_consistent = 0;

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

	it = api->iter_begin(&txn, KNOT_DB_NOOP); // _FIRST is split for easier debugging
	if (it == NULL) {
		printf("Error: failed to create an iterator.\n");
		api->txn_abort(&txn);
		return KNOT_ERROR;
	}
	it = api->iter_seek(it, NULL, KNOT_DB_FIRST);
	if (it == NULL)
		printf("Suspicious: completely empty LMDB at this moment?\n");

	int txn_steps = 0;
	while (it != NULL) {
		knot_db_val_t key = { 0 }, val = { 0 };
		ret = api->iter_key(it, &key);
		if (ret == KNOT_EOK && key.len == 4 && memcmp("VERS", key.data, 4) == 0) {
			/* skip DB metadata */
			goto skip;
		}
		if (ret == KNOT_EOK) {
			ret = api->iter_val(it, &val);
		}
		if (ret != KNOT_EOK) {
			goto error;
		}

		info.entry_size = key.len + val.len;
		info.valid = false;
		const uint16_t *entry_type =
		    ret == KNOT_EOK ? kr_gc_key_consistent(key) : NULL;
		const struct entry_h *entry = NULL;
		if (entry_type != NULL) {
			counter_gc_consistent++;
			entry = val2entry(val, *entry_type);
		}
		/* TODO: perhaps improve some details around here:
		 *  - xNAME have .rrtype NS
		 *  - DNAME hidden on NS name will not be considered here
		 *  - if zone has NSEC* meta-data but no NS, it will be seen
		 *    here as kr_inconsistent */
		if (entry != NULL) {
			info.valid = true;
			info.rrtype = *entry_type;
			info.expires_in = entry->time + entry->ttl - now;
			info.no_labels = entry_labels(&key, *entry_type);
		}
		counter_iter++;
		counter_kr_consistent += info.valid;
		if (VERBOSE_STATUS) {
			if (!entry_type || !entry) {	// don't log fully consistent entries
				printf
				    ("GC %sconsistent, KR %sconsistent, size %zu, key len %zu: ",
				     entry_type ? "" : "in", entry ? "" : "IN",
				     (key.len + val.len), key.len);
				debug_printbin(key.data, key.len);
				printf("\n");
			}
		}
		ret = callback(&key, &info, ctx);

		if (ret != KNOT_EOK) {
		error:
			printf("Error iterating database (%s).\n",
			       knot_strerror(ret));
			api->iter_finish(it);
			api->txn_abort(&txn);
			return ret;
		}

	skip:	// Advance to the next GC item.
		if (++txn_steps < cfg->ro_txn_items || !cfg->ro_txn_items/*unlimited*/) {
			it = api->iter_next(it);
		} else {
			/* The transaction has been too long; let's reopen it. */
			txn_steps = 0;
			uint8_t key_storage[key.len];
			memcpy(key_storage, key.data, key.len);
			key.data = key_storage;

			api->iter_finish(it);
			api->txn_abort(&txn);

			ret = api->txn_begin(knot_db, &txn, KNOT_DB_RDONLY);
			if (ret != KNOT_EOK) {
				printf("Error restarting DB transaction (%s).\n",
					knot_strerror(ret));
				return ret;
			}
			it = api->iter_begin(&txn, KNOT_DB_NOOP);
			if (it == NULL) {
				printf("Error: failed to create an iterator.\n");
				api->txn_abort(&txn);
				return KNOT_ERROR;
			}
			it = api->iter_seek(it, &key, KNOT_DB_GEQ);
			// NULL here means we'we reached the end
		}
	}

	api->txn_abort(&txn);

	kr_log_verbose("DEBUG: iterated %u items, gc consistent %u, kr consistent %u\n",
		counter_iter, counter_gc_consistent, counter_kr_consistent);
	return KNOT_EOK;
}
