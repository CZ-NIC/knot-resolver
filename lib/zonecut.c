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

#include <libknot/descriptor.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/packet/wire.h>
#include <libknot/descriptor.h>
#include <libknot/rrtype/aaaa.h>

#include "lib/zonecut.h"
#include "lib/rplan.h"
#include "lib/defines.h"
#include "lib/layer.h"
#include "lib/generic/pack.h"

/* Root hint descriptor. */
struct hint_info {
	const knot_dname_t *name;
	const uint8_t *addr;
};

/* Initialize with SBELT name servers. */
#define U8(x) (const uint8_t *)(x)
#define HINT_COUNT 13
#define HINT_ADDRLEN sizeof(struct in_addr)
static const struct hint_info SBELT[HINT_COUNT] = {
        { U8("\x01""a""\x0c""root-servers""\x03""net"), U8("\xc6)\x00\x04")    }, /* 198.41.0.4 */
        { U8("\x01""b""\x0c""root-servers""\x03""net"), U8("\xc0\xe4O\xc9")    }, /* 192.228.79.201 */
        { U8("\x01""c""\x0c""root-servers""\x03""net"), U8("\xc6)\x00\x04")    }, /* 192.33.4.12 */
        { U8("\x01""d""\x0c""root-servers""\x03""net"), U8("\xc7\x07[\r")      }, /* 199.7.91.13 */
        { U8("\x01""e""\x0c""root-servers""\x03""net"), U8("\xc0\xcb\xe6\n")   }, /* 192.203.230.10 */
        { U8("\x01""f""\x0c""root-servers""\x03""net"), U8("\xc0\x05\x05\xf1") }, /* 192.5.5.241 */
        { U8("\x01""g""\x0c""root-servers""\x03""net"), U8("\xc0p$\x04")       }, /* 192.112.36.4 */
        { U8("\x01""h""\x0c""root-servers""\x03""net"), U8("\x80?\x025")       }, /* 128.63.2.53 */
        { U8("\x01""i""\x0c""root-servers""\x03""net"), U8("\xc0$\x94\x11")    }, /* 192.36.148.17 */
        { U8("\x01""j""\x0c""root-servers""\x03""net"), U8("\xc0:\x80\x1e")    }, /* 192.58.128.30 */
        { U8("\x01""k""\x0c""root-servers""\x03""net"), U8("\xc1\x00\x0e\x81") }, /* 193.0.14.129 */
        { U8("\x01""l""\x0c""root-servers""\x03""net"), U8("\xc7\x07S*")       }, /* 199.7.83.42 */
        { U8("\x01""m""\x0c""root-servers""\x03""net"), U8("\xca\x0c\x1b!")    }, /* 202.12.27.33 */
};

static inline int nsset_reserve(void *baton, char **mem, size_t elm_size, size_t want, size_t *have)
{
	if (*have >= want) {
		return 0;
	} else {
		mm_ctx_t *pool = baton;
		size_t next_size = (want + 3);
		void *mem_new = mm_alloc(pool, next_size * elm_size);
		if (mem_new != NULL) {
			memcpy(mem_new, *mem, (*have)*(elm_size));
			mm_free(pool, *mem);
			*mem = mem_new;
			*have = next_size;
			return 0;
		}
	}
	return -1;
}

static void update_cut_name(struct kr_zonecut *cut, const knot_dname_t *name)
{
	if (knot_dname_is_equal(name, cut->name)) {
		return;
	}
	knot_dname_t *next_name = knot_dname_copy(name, cut->pool);
	mm_free(cut->pool, cut->name);
	cut->name = next_name;
}

int kr_zonecut_init(struct kr_zonecut *cut, const knot_dname_t *name, mm_ctx_t *pool)
{
	if (cut == NULL || name == NULL) {
		return kr_error(EINVAL);
	}

	cut->name = knot_dname_copy(name, pool);
	cut->pool = pool;
	cut->nsset = map_make();
	cut->nsset.malloc = (map_alloc_f) mm_alloc;
	cut->nsset.free = (map_free_f) mm_free;
	cut->nsset.baton = pool;
	return kr_ok();
}

static int free_addr_set(const char *k, void *v, void *baton)
{
	pack_t *pack = v;
	pack_clear_mm(*pack, mm_free, baton);
	mm_free(baton, pack);
	return kr_ok();
}

void kr_zonecut_deinit(struct kr_zonecut *cut)
{
	if (cut == NULL) {
		return;
	}
	mm_free(cut->pool, cut->name);
	map_walk(&cut->nsset, free_addr_set, cut->pool);
	map_clear(&cut->nsset);
}

void kr_zonecut_set(struct kr_zonecut *cut, const knot_dname_t *name)
{
	if (cut == NULL || name == NULL) {
		return;
	}
	kr_zonecut_deinit(cut);
	kr_zonecut_init(cut, name, cut->pool);
}

int kr_zonecut_add(struct kr_zonecut *cut, const knot_dname_t *ns, const knot_rdata_t *rdata)
{
	if (cut == NULL || ns == NULL) {
		return kr_error(EINVAL);
	}

	/* Fetch/insert nameserver. */
	pack_t *pack = kr_zonecut_find(cut, ns);
	if (pack == NULL) {
		pack = mm_alloc(cut->pool, sizeof(*pack));
		if (!pack || (map_set(&cut->nsset, (const char *)ns, pack) != 0)) {
			mm_free(cut->pool, pack);
			return kr_error(ENOMEM);
		}
		pack_init(*pack);
	}

	/* Insert data (if has any) */
	if (rdata == NULL) {
		return kr_ok();
	}
	uint16_t rdlen = knot_rdata_rdlen(rdata);
	int ret = pack_reserve_mm(*pack, 1, rdlen, nsset_reserve, cut->pool);
	if (ret != 0) {
		return kr_error(ENOMEM);
	}

	return pack_obj_push(pack, knot_rdata_data(rdata), rdlen);
}

int kr_zonecut_del(struct kr_zonecut *cut, const knot_dname_t *ns, const knot_rdata_t *rdata)
{
	if (cut == NULL || ns == NULL) {
		return kr_error(EINVAL);
	}

	/* Find the address list. */
	pack_t *pack = kr_zonecut_find(cut, ns);
	if (pack == NULL) {
		return kr_error(ENOENT);
	}

	/* Remove address from the pack. */
	int ret = pack_obj_del(pack, knot_rdata_data(rdata), knot_rdata_rdlen(rdata));
	if (pack->len == 0) {
		/* No servers left, remove NS from the set. */
		free_addr_set((const char *)ns, pack, cut->pool);
		return map_del(&cut->nsset, (const char *)ns);
	}

	return ret;
}

pack_t *kr_zonecut_find(struct kr_zonecut *cut, const knot_dname_t *ns)
{
	if (cut == NULL || ns == NULL) {
		return NULL;
	}

	const char *key = (const char *)ns;
	map_t *nsset = &cut->nsset;
	return map_get(nsset, key);
}

int kr_zonecut_set_sbelt(struct kr_zonecut *cut)
{
	if (cut == NULL) {
		return kr_error(EINVAL);
	}

	update_cut_name(cut, U8(""));
	for (unsigned i = 0; i < HINT_COUNT; ++i) {
		const struct hint_info *hint = &SBELT[i];
		knot_rdata_t rdata[knot_rdata_array_size(HINT_ADDRLEN)];
		knot_rdata_init(rdata, HINT_ADDRLEN, hint->addr, 0);
		int ret = kr_zonecut_add(cut, hint->name, rdata);
		if (ret != 0) {
			return ret;
		}
	}

	return kr_ok();
}

/** Fetch address for zone cut. */
static void fetch_addr(struct kr_zonecut *cut, const knot_dname_t *ns, uint16_t rrtype, namedb_txn_t *txn, uint32_t timestamp)
{
	knot_rrset_t cached_rr;
	knot_rrset_init(&cached_rr, (knot_dname_t *)ns, rrtype, KNOT_CLASS_IN);
	if (kr_cache_peek_rr(txn, &cached_rr, &timestamp) != 0) {
		return;
	}

	for (uint16_t i = 0; i < cached_rr.rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&cached_rr.rrs, i);
		if (knot_rdata_ttl(rd) > timestamp) {
			(void) kr_zonecut_add(cut, ns, rd);
		}
	}
}

/** Fetch best NS for zone cut. */
static int fetch_ns(struct kr_zonecut *cut, const knot_dname_t *name, namedb_txn_t *txn, uint32_t timestamp)
{
	uint32_t drift = timestamp;
	knot_rrset_t cached_rr;
	knot_rrset_init(&cached_rr, (knot_dname_t *)name, KNOT_RRTYPE_NS, KNOT_CLASS_IN);
	int ret = kr_cache_peek_rr(txn, &cached_rr, &drift);
	if (ret != 0) {
		return ret;
	}

	/* Fetch address records for this nameserver */
	for (unsigned i = 0; i < cached_rr.rrs.rr_count; ++i) {
		const knot_dname_t *ns_name = knot_ns_name(&cached_rr.rrs, i);
		kr_zonecut_add(cut, ns_name, NULL);
		fetch_addr(cut, ns_name, KNOT_RRTYPE_A, txn, timestamp);
		fetch_addr(cut, ns_name, KNOT_RRTYPE_AAAA, txn, timestamp);
	}

	return kr_ok();
}

int kr_zonecut_find_cached(struct kr_zonecut *cut, namedb_txn_t *txn, uint32_t timestamp)
{
	if (cut == NULL) {
		return kr_error(EINVAL);
	}

	/* Start at QNAME. */
	const knot_dname_t *name = cut->name;
	while (txn) {
		if (fetch_ns(cut, name, txn, timestamp) == 0) {
			update_cut_name(cut, name);
			return kr_ok();
		}
		/* Subtract label from QNAME. */
		if (name[0] == '\0') {
			break;
		}
		name = knot_wire_next_label(name, NULL);
	}

	/* Name server not found, start with SBELT. */
	return kr_zonecut_set_sbelt(cut);
}
