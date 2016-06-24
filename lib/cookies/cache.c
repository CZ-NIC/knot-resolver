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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include <libknot/db/db_lmdb.h>
#include <libknot/cookies/client.h>

#include "contrib/cleanup.h"
#include "lib/cdb_lmdb.h"
#include "lib/cookies/cache.h"
#include "lib/cookies/control.h"
#include "lib/utils.h"

/* Key size */
#define KEY_HSIZE (sizeof(uint8_t))
#define KEY_SIZE (KEY_HSIZE + 16)
/* Shorthand for operations on cache backend */
#define cache_isvalid(cache) ((cache) && (cache)->api && (cache)->db)
#define cache_op(cache, op, ...) (cache)->api->op((cache)->db, ## __VA_ARGS__)

/**
 * @internal Composed key as { u8 tag, u8[4,16] IP address }
 */
static size_t cache_key(uint8_t *buf, uint8_t tag, const struct sockaddr *sa)
{
	assert(buf && sa);

	const char *addr = kr_inaddr(sa);
	int addr_len = kr_inaddr_len(sa);

	if (!addr || (addr_len <= 0)) {
		return 0;
	}

	buf[0] = tag;
	memcpy(buf + sizeof(uint8_t), addr, addr_len);

	return addr_len + KEY_HSIZE;
}

static struct kr_cache_entry *lookup(struct kr_cache *cache, uint8_t tag,
                                     const struct sockaddr *sa)
{
	if (!cache || !sa) {
		return NULL;
	}

	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, sa);

	/* Look up and return value */
	knot_db_val_t key = { keybuf, key_len };
	knot_db_val_t val = { NULL, 0 };
	int ret = cache_op(cache, read, &key, &val, 1);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	return (struct kr_cache_entry *)val.data;
}

static int check_lifetime(struct kr_cache_entry *found, uint32_t *timestamp)
{
	/* No time constraint */
	if (!timestamp) {
		return kr_ok();
	} else if (*timestamp <= found->timestamp) {
		/* John Connor record cached in the future. */
		*timestamp = 0;
		return kr_ok();
	} else {
		/* Check if the record is still valid. */
		uint32_t drift = *timestamp - found->timestamp;
		if (drift <= found->ttl) {
			*timestamp = drift;
			return kr_ok();
		}
	}
	return kr_error(ESTALE);
}

int kr_cookie_cache_peek(struct kr_cache *cache, uint8_t tag,
                         const struct sockaddr *sa, struct kr_cache_entry **entry,
                         uint32_t *timestamp)
{
	if (!cache_isvalid(cache) || !sa || !entry) {
		return kr_error(EINVAL);
	}

	struct kr_cache_entry *found = lookup(cache, tag, sa);
	if (!found) {
		cache->stats.miss += 1;
		return kr_error(ENOENT);
	}

	/* Check entry lifetime */
	*entry = found;
	int ret = check_lifetime(found, timestamp);
	if (ret == 0) {
		cache->stats.hit += 1;
	} else {
		cache->stats.miss += 1;
	}
	return ret;
}

static void entry_write(struct kr_cache_entry *dst, struct kr_cache_entry *header, knot_db_val_t data)
{
	assert(dst && header);
	memcpy(dst, header, sizeof(*header));
	if (data.data) {
		memcpy(dst->data, data.data, data.len);
	}
}

int kr_cookie_cache_insert(struct kr_cache *cache,
                           uint8_t tag, const struct sockaddr *sa,
                           struct kr_cache_entry *header, knot_db_val_t data)
{
	if (!cache_isvalid(cache) || !sa || !header) {
		return kr_error(EINVAL);
	}

	/* Insert key */
	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, sa);
	if (key_len == 0) {
		return kr_error(EILSEQ);
	}
	assert(data.len != 0);
	knot_db_val_t key = { keybuf, key_len };
	knot_db_val_t entry = { NULL, sizeof(*header) + data.len };

	/* LMDB can do late write and avoid copy */
	int ret = 0;
	cache->stats.insert += 1;
	if (cache->api == kr_cdb_lmdb()) {
		ret = cache_op(cache, write, &key, &entry, 1);
		if (ret != 0) {
			return ret;
		}
		entry_write(entry.data, header, data);
		ret = cache_op(cache, sync); /* Make sure the entry is comitted. */
	} else {
		/* Other backends must prepare contiguous data first */
		auto_free char *buffer = malloc(entry.len);
		entry.data = buffer;
		entry_write(entry.data, header, data);
		ret = cache_op(cache, write, &key, &entry, 1);
	}

	return ret;
}

int kr_cookie_cache_remove(struct kr_cache *cache,
                           uint8_t tag, const struct sockaddr *sa)
{
	if (!cache_isvalid(cache) || !sa) {
		return kr_error(EINVAL);
	}

	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, sa);
	if (key_len == 0) {
		return kr_error(EILSEQ);
	}
	knot_db_val_t key = { keybuf, key_len };
	cache->stats.delete += 1;
	return cache_op(cache, remove, &key, 1);
}

int kr_cookie_cache_peek_cookie(struct kr_cache *cache, const struct sockaddr *sa,
                                struct timed_cookie *cookie, uint32_t *timestamp)
{
	if (!cache_isvalid(cache) || !sa || !cookie || !timestamp) {
		return kr_error(EINVAL);
	}

	/* Check if the RRSet is in the cache. */
	struct kr_cache_entry *entry = NULL;
	int ret = kr_cookie_cache_peek(cache, KR_CACHE_COOKIE, sa,
	                               &entry, timestamp);
	if (ret != 0) {
		return ret;
	}
	cookie->ttl = entry->ttl;
	cookie->cookie_opt = entry->data;
	return kr_ok();
}

int kr_cookie_cache_insert_cookie(struct kr_cache *cache, const struct sockaddr *sa,
                                  const struct timed_cookie *cookie,
                                  uint32_t timestamp)
{
	if (!cache_isvalid(cache) || !sa) {
		return kr_error(EINVAL);
	}

	/* Ignore empty cookie data. */
	if (!cookie || !cookie->cookie_opt) {
		return kr_ok();
	}

	/* Prepare header to write. */
	struct kr_cache_entry header = {
		.timestamp = timestamp,
		.ttl = cookie->ttl,
		.rank = KR_RANK_BAD,
		.flags = KR_CACHE_FLAG_NONE,
		.count = 1 /* Only one entry. */
	};

	size_t cookie_opt_size = KNOT_EDNS_OPTION_HDRLEN +
	                         knot_edns_opt_get_length(cookie->cookie_opt);

	knot_db_val_t data = { (uint8_t *) cookie->cookie_opt, cookie_opt_size };
	return kr_cookie_cache_insert(cache, KR_CACHE_COOKIE, sa,
	                              &header, data);
}
