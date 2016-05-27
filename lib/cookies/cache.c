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
#include <libknot/db/db_lmdb.h>

#include "lib/cookies/cache.h"
#include "lib/cookies/control.h"

/* Key size */
#define KEY_HSIZE (sizeof(uint8_t))
#define KEY_SIZE (KEY_HSIZE + 16)
#define txn_api(txn) ((txn)->owner->api)
#define txn_is_valid(txn) ((txn) && (txn)->owner && txn_api(txn))

/**
 * @internal Composed key as { u8 tag, u8[4,16] IP address }
 */
static size_t cache_key(uint8_t *buf, uint8_t tag, const void *sockaddr)
{
	assert(buf && sockaddr);

	const uint8_t *addr = NULL;
	size_t addr_len = 0;

	if (kr_ok() != kr_address_bytes(sockaddr, &addr, &addr_len)) {
		return 0;
	}
	assert(addr_len > 0);

	buf[0] = tag;
	memcpy(buf + sizeof(uint8_t), addr, addr_len);

	return addr_len + KEY_HSIZE;
}

static struct kr_cache_entry *lookup(struct kr_cache_txn *txn, uint8_t tag,
                                     const void *sockaddr)
{
	if (!txn_is_valid(txn) || !sockaddr) {
		return NULL;
	}

	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, sockaddr);

	/* Look up and return value */
	knot_db_val_t key = { keybuf, key_len };
	knot_db_val_t val = { NULL, 0 };
	int ret = txn_api(txn)->find(&txn->t, &key, &val, 0);
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

int kr_cookie_cache_peek(struct kr_cache_txn *txn, uint8_t tag, const void *sockaddr,
                         struct kr_cache_entry **entry, uint32_t *timestamp)
{
	if (!txn_is_valid(txn) || !sockaddr || !entry) {
		return kr_error(EINVAL);
	}

	struct kr_cache_entry *found = lookup(txn, tag, sockaddr);
	if (!found) {
		txn->owner->stats.miss += 1;
		return kr_error(ENOENT);
	}

	/* Check entry lifetime */
	*entry = found;
	int ret = check_lifetime(found, timestamp);
	if (ret == 0) {
		txn->owner->stats.hit += 1;
	} else {
		txn->owner->stats.miss += 1;
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

int kr_cookie_cache_insert(struct kr_cache_txn *txn,
                           uint8_t tag, const void *sockaddr,
                           struct kr_cache_entry *header, knot_db_val_t data)
{
	if (!txn_is_valid(txn) || !sockaddr || !header) {
		return kr_error(EINVAL);
	}

	/* Insert key */
	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, sockaddr);
	if (key_len == 0) {
		return kr_error(EILSEQ);
	}
	knot_db_val_t key = { keybuf, key_len };
	knot_db_val_t entry = { NULL, sizeof(*header) + data.len };
	const knot_db_api_t *db_api = txn_api(txn);

	/* LMDB can do late write and avoid copy */
	txn->owner->stats.insert += 1;
	if (db_api == knot_db_lmdb_api()) {
		int ret = db_api->insert(&txn->t, &key, &entry, 0);
		if (ret != 0) {
			return ret;
		}
		entry_write(entry.data, header, data);
	} else {
		/* Other backends must prepare contiguous data first */
		entry.data = malloc(entry.len);
		if (!entry.data) {
			return kr_error(ENOMEM);
		}
		entry_write(entry.data, header, data);
		int ret = db_api->insert(&txn->t, &key, &entry, 0);
		free(entry.data);
		if (ret != 0) {
			return ret;
		}
	}

	return kr_ok();
}

int kr_cookie_cache_peek_cookie(struct kr_cache_txn *txn, const void *sockaddr,
                                struct timed_cookie *cookie, uint32_t *timestamp)
{
	if (!txn_is_valid(txn) || !sockaddr || !cookie || !timestamp) {
		return kr_error(EINVAL);
	}

	/* Check if the RRSet is in the cache. */
	struct kr_cache_entry *entry = NULL;
	int ret = kr_cookie_cache_peek(txn, KR_CACHE_COOKIE, sockaddr, &entry, timestamp);
	if (ret != 0) {
		return ret;
	}
	cookie->ttl = entry->ttl;
	cookie->cookie_opt = entry->data;
	return kr_ok();
}

int kr_cookie_cache_insert_cookie(struct kr_cache_txn *txn, const void *sockaddr,
                                  const struct timed_cookie *cookie,
                                  uint32_t timestamp)
{
	if (!txn_is_valid(txn) || !sockaddr) {
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

	size_t cookie_opt_size = knot_edns_opt_get_length(cookie->cookie_opt) + KNOT_EDNS_OPTION_HDRLEN;

	knot_db_val_t data = { (uint8_t *) cookie->cookie_opt, cookie_opt_size };
	return kr_cookie_cache_insert(txn, KR_CACHE_COOKIE, sockaddr, &header,
	                              data);
}
