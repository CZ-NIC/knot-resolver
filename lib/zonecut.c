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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
#include "lib/resolve.h"
#include "lib/generic/pack.h"

/* Root hint descriptor. */
struct hint_info {
	const knot_dname_t *name;
	size_t len;
	const uint8_t *addr;
};

#define U8(x) (const uint8_t *)(x)

/* Initialize with SBELT name servers. */
#include "lib/root-hints.inc"
#define HINT_LEN_A sizeof(struct in_addr)
#define HINT_LEN_AAAA sizeof(struct in6_addr)
#define SBELT_LEN (sizeof(SBELT) / sizeof(SBELT[0]))
static const struct hint_info SBELT[] = {
	#define HINT(name,type) { \
		U8("\x01" #name "\x0c""root-servers""\x03""net"), \
		HINT_LEN_##type, \
		U8(HINT_##name##_##type), \
      	}
	HINT(j, A),
	HINT(k, A),
	HINT(d, A),
	HINT(e, A),
	HINT(f, A),
	HINT(g, A),
	HINT(h, A),
	HINT(i, A),
	HINT(l, A),
	HINT(m, A),
	HINT(b, A),
	HINT(c, A),
	HINT(a, A),
	HINT(a, AAAA),
	HINT(b, AAAA),
	HINT(c, AAAA),
	HINT(d, AAAA),
	HINT(e, AAAA),
	HINT(f, AAAA),
	HINT(g, AAAA),
	HINT(h, AAAA),
	HINT(i, AAAA),
	HINT(j, AAAA),
	HINT(k, AAAA),
	HINT(l, AAAA),
	HINT(m, AAAA),
	#undef HINT
};
#undef HINT_LEN_A
#undef HINT_LEN_AAAA


static void update_cut_name(struct kr_zonecut *cut, const knot_dname_t *name)
{
	if (knot_dname_is_equal(name, cut->name)) {
		return;
	}
	knot_dname_t *next_name = knot_dname_copy(name, cut->pool);
	mm_free(cut->pool, cut->name);
	cut->name = next_name;
}

int kr_zonecut_init(struct kr_zonecut *cut, const knot_dname_t *name, knot_mm_t *pool)
{
	if (!cut || !name) {
		return kr_error(EINVAL);
	}

	cut->name = knot_dname_copy(name, pool);
	cut->pool = pool;
	cut->key  = NULL;
	cut->trust_anchor = NULL;
	cut->parent = NULL;
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
	if (!cut) {
		return;
	}
	mm_free(cut->pool, cut->name);
	map_walk(&cut->nsset, free_addr_set, cut->pool);
	map_clear(&cut->nsset);
	knot_rrset_free(&cut->key, cut->pool);
	knot_rrset_free(&cut->trust_anchor, cut->pool);
	cut->name = NULL;
}

void kr_zonecut_set(struct kr_zonecut *cut, const knot_dname_t *name)
{
	if (!cut || !name) {
		return;
	}
	knot_rrset_t *key, *ta;
	key = cut->key; cut->key = NULL;
	ta = cut->trust_anchor; cut->trust_anchor = NULL;
	kr_zonecut_deinit(cut);
	kr_zonecut_init(cut, name, cut->pool);
	cut->key = key;
	cut->trust_anchor = ta;
}

static int copy_addr_set(const char *k, void *v, void *baton)
{
	pack_t *addr_set = v;
	struct kr_zonecut *dst = baton;
	/* Clone addr_set pack */
	pack_t *new_set = mm_alloc(dst->pool, sizeof(*new_set));
	if (!new_set) {
		return kr_error(ENOMEM);
	}
	pack_init(*new_set);
	/* Clone data only if needed */
	if (addr_set->len > 0) {
		new_set->at = mm_alloc(dst->pool, addr_set->len);
		if (!new_set->at) {
			mm_free(dst->pool, new_set);
			return kr_error(ENOMEM);
		}
		memcpy(new_set->at, addr_set->at, addr_set->len);
		new_set->len = addr_set->len;
		new_set->cap = addr_set->len;
	}
	/* Reinsert */
	if (map_set(&dst->nsset, k, new_set) != 0) {
		pack_clear_mm(*new_set, mm_free, dst->pool);
		mm_free(dst->pool, new_set);
		return kr_error(ENOMEM);
	}
	return kr_ok();
}

int kr_zonecut_copy(struct kr_zonecut *dst, const struct kr_zonecut *src)
{
	if (!dst || !src) {
		return kr_error(EINVAL);
	}
	/* We're not touching src nsset, I promise */
	return map_walk((map_t *)&src->nsset, copy_addr_set, dst);
}

int kr_zonecut_copy_trust(struct kr_zonecut *dst, const struct kr_zonecut *src)
{
	knot_rrset_t *key_copy = NULL;
	knot_rrset_t *ta_copy = NULL;

	if (src->key) {
		key_copy = knot_rrset_copy(src->key, dst->pool);
		if (!key_copy) {
			return kr_error(ENOMEM);
		}
	}

	if (src->trust_anchor) {
		ta_copy = knot_rrset_copy(src->trust_anchor, dst->pool);
		if (!ta_copy) {
			knot_rrset_free(&key_copy, dst->pool);
			return kr_error(ENOMEM);
		}
	}

	knot_rrset_free(&dst->key, dst->pool);
	dst->key = key_copy;
	knot_rrset_free(&dst->trust_anchor, dst->pool);
	dst->trust_anchor = ta_copy;

	return kr_ok();
}

int kr_zonecut_add(struct kr_zonecut *cut, const knot_dname_t *ns, const knot_rdata_t *rdata)
{
	if (!cut || !ns) {
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
	/* Check for duplicates */
	uint16_t rdlen = knot_rdata_rdlen(rdata);
	uint8_t *raw_addr = knot_rdata_data(rdata);
	if (pack_obj_find(pack, raw_addr, rdlen)) {
		return kr_ok();
	}
	/* Push new address */
	int ret = pack_reserve_mm(*pack, 1, rdlen, kr_memreserve, cut->pool);
	if (ret != 0) {
		return kr_error(ENOMEM);
	}
	return pack_obj_push(pack, raw_addr, rdlen);
}

int kr_zonecut_del(struct kr_zonecut *cut, const knot_dname_t *ns, const knot_rdata_t *rdata)
{
	if (!cut || !ns) {
		return kr_error(EINVAL);
	}

	/* Find the address list. */
	int ret = kr_ok();
	pack_t *pack = kr_zonecut_find(cut, ns);
	if (pack == NULL) {
		return kr_error(ENOENT);
	}
	/* Remove address from the pack. */
	if (rdata) {
		ret = pack_obj_del(pack, knot_rdata_data(rdata), knot_rdata_rdlen(rdata));
	}
	/* No servers left, remove NS from the set. */
	if (pack->len == 0) {
		free_addr_set((const char *)ns, pack, cut->pool);
		return map_del(&cut->nsset, (const char *)ns);
	}

	return ret;
}

pack_t *kr_zonecut_find(struct kr_zonecut *cut, const knot_dname_t *ns)
{
	if (!cut || !ns) {
		return NULL;
	}

	const char *key = (const char *)ns;
	map_t *nsset = &cut->nsset;
	return map_get(nsset, key);
}

int kr_zonecut_set_sbelt(struct kr_context *ctx, struct kr_zonecut *cut)
{
	if (!ctx || !cut) {
		return kr_error(EINVAL);
	}
	/* @warning _NOT_ thread-safe */
	static knot_rdata_t rdata_arr[RDATA_ARR_MAX];

	update_cut_name(cut, U8(""));
	map_walk(&cut->nsset, free_addr_set, cut->pool);
	map_clear(&cut->nsset);

	/* Copy root hints from resolution context. */
	int ret = 0;
	if (ctx->root_hints.nsset.root) {
		ret = kr_zonecut_copy(cut, &ctx->root_hints);
	} else {
		/* Copy compiled-in root hints */
		for (unsigned i = 0; i < SBELT_LEN; ++i) {
			const struct hint_info *hint = &SBELT[i];
			knot_rdata_init(rdata_arr, hint->len, hint->addr, 0);
			ret = kr_zonecut_add(cut, hint->name, rdata_arr);
			if (ret != 0) {
				break;
			}
		}
	}
	return ret;
}

/** Fetch address for zone cut. */
static void fetch_addr(struct kr_zonecut *cut, struct kr_cache *cache, const knot_dname_t *ns, uint16_t rrtype, uint32_t timestamp)
{
	uint8_t rank = 0;
	knot_rrset_t cached_rr;
	knot_rrset_init(&cached_rr, (knot_dname_t *)ns, rrtype, KNOT_CLASS_IN);
	if (kr_cache_peek_rr(cache, &cached_rr, &rank, NULL, &timestamp) != 0) {
		return;
	}

	knot_rdata_t *rd = cached_rr.rrs.data;
	for (uint16_t i = 0; i < cached_rr.rrs.rr_count; ++i) {
		if (knot_rdata_ttl(rd) > timestamp) {
			(void) kr_zonecut_add(cut, ns, rd);
		}
		rd = kr_rdataset_next(rd);
	}
}

/** Fetch best NS for zone cut. */
static int fetch_ns(struct kr_context *ctx, struct kr_zonecut *cut, const knot_dname_t *name, uint32_t timestamp, uint8_t * restrict rank)
{
	uint32_t drift = timestamp;
	knot_rrset_t cached_rr;
	knot_rrset_init(&cached_rr, (knot_dname_t *)name, KNOT_RRTYPE_NS, KNOT_CLASS_IN);
	int ret = kr_cache_peek_rr(&ctx->cache, &cached_rr, rank, NULL, &drift);
	if (ret != 0) {
		return ret;
	}

	/* Materialize as we'll going to do more cache lookups. */
	knot_rrset_t rr_copy;
	ret = kr_cache_materialize(&rr_copy, &cached_rr, drift, 0, cut->pool);
	if (ret != 0) {
		return ret;
	}

	/* Insert name servers for this zone cut, addresses will be looked up
	 * on-demand (either from cache or iteratively) */
	for (unsigned i = 0; i < rr_copy.rrs.rr_count; ++i) {
		const knot_dname_t *ns_name = knot_ns_name(&rr_copy.rrs, i);
		kr_zonecut_add(cut, ns_name, NULL);
		/* Fetch NS reputation and decide whether to prefetch A/AAAA records. */
		unsigned *cached = lru_get_try(ctx->cache_rep,
				(const char *)ns_name, knot_dname_size(ns_name));
		unsigned reputation = (cached) ? *cached : 0;
		if (!(reputation & KR_NS_NOIP4) && !(ctx->options & QUERY_NO_IPV4)) {
			fetch_addr(cut, &ctx->cache, ns_name, KNOT_RRTYPE_A, timestamp);
		}
		if (!(reputation & KR_NS_NOIP6) && !(ctx->options & QUERY_NO_IPV6)) {
			fetch_addr(cut,  &ctx->cache, ns_name, KNOT_RRTYPE_AAAA, timestamp);
		}
	}

	knot_rrset_clear(&rr_copy, cut->pool);
	return kr_ok();
}

/**
 * Fetch RRSet of given type.
 */
static int fetch_rrset(knot_rrset_t **rr, struct kr_cache *cache,
                       const knot_dname_t *owner, uint16_t type, knot_mm_t *pool, uint32_t timestamp)
{
	if (!rr) {
		return kr_error(ENOENT);
	}

	uint8_t rank = 0;
	uint32_t drift = timestamp;
	knot_rrset_t cached_rr;
	knot_rrset_init(&cached_rr, (knot_dname_t *)owner, type, KNOT_CLASS_IN);
	int ret = kr_cache_peek_rr(cache, &cached_rr, &rank, NULL, &drift);
	if (ret != 0) {
		return ret;
	}

	knot_rrset_free(rr, pool);
	*rr = mm_alloc(pool, sizeof(knot_rrset_t));
	if (*rr == NULL) {
		return kr_error(ENOMEM);
	}

	ret = kr_cache_materialize(*rr, &cached_rr, drift, 0, pool);
	if (ret != 0) {
		knot_rrset_free(rr, pool);
		return ret;
	}

	return kr_ok();
}

/**
 * Fetch trust anchors for zone cut.
 * @note The trust anchor can theoretically be a DNSKEY but for now lets use only DS.
 */
static int fetch_ta(struct kr_zonecut *cut, struct kr_cache *cache, const knot_dname_t *name, uint32_t timestamp)
{
	return fetch_rrset(&cut->trust_anchor, cache, name, KNOT_RRTYPE_DS, cut->pool, timestamp);
}

/** Fetch DNSKEY for zone cut. */
static int fetch_dnskey(struct kr_zonecut *cut, struct kr_cache *cache, const knot_dname_t *name, uint32_t timestamp)
{
	return fetch_rrset(&cut->key, cache, name, KNOT_RRTYPE_DNSKEY, cut->pool, timestamp);
}

int kr_zonecut_find_cached(struct kr_context *ctx, struct kr_zonecut *cut, const knot_dname_t *name,
                           uint32_t timestamp, bool * restrict secured)
{
	if (!ctx || !cut || !name) {
		return kr_error(EINVAL);
	}
	/* Copy name as it may overlap with cut name that is to be replaced. */
	knot_dname_t *qname = knot_dname_copy(name, cut->pool);
	if (!qname) {
		return kr_error(ENOMEM);
	}
	/* Start at QNAME parent. */
	const knot_dname_t *label = qname;
	while (true) {
		/* Fetch NS first and see if it's insecure. */
		uint8_t rank = 0;
		const bool is_root = (label[0] == '\0');
		if (fetch_ns(ctx, cut, label, timestamp, &rank) == 0) {
			/* Flag as insecure if cached as this */
			if (rank & KR_RANK_INSECURE)
				*secured = false;
			/* Fetch DS if caller wants secure zone cut */
			if (*secured || is_root) {
				fetch_ta(cut, &ctx->cache, label, timestamp);
				fetch_dnskey(cut, &ctx->cache, label, timestamp);
			}
			update_cut_name(cut, label);
			mm_free(cut->pool, qname);
			return kr_ok();
		}
		/* Subtract label from QNAME. */
		if (!is_root) {
			label = knot_wire_next_label(label, NULL);
		} else {
			break;
		}
	}
	mm_free(cut->pool, qname);
	return kr_error(ENOENT);
}
