/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "contrib/cleanup.h"
#include "lib/defines.h"
#include "lib/layer.h"
#include "lib/resolve.h"
#include "lib/generic/pack.h"

#define VERBOSE_MSG(qry, fmt...) QRVERBOSE(qry, "zcut", fmt)

/* Root hint descriptor. */
struct hint_info {
	const knot_dname_t *name;
	size_t len;
	const uint8_t *addr;
};

#define U8(x) (const uint8_t *)(x)

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
	cut->nsset = map_make(pool);
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

int kr_zonecut_del_all(struct kr_zonecut *cut, const knot_dname_t *ns)
{
	if (!cut || !ns) {
		return kr_error(EINVAL);
	}

	/* Find the address list; then free and remove it. */
	pack_t *pack = kr_zonecut_find(cut, ns);
	if (pack == NULL) {
		return kr_error(ENOENT);
	}
	free_addr_set((const char *)ns, pack, cut->pool);
	return map_del(&cut->nsset, (const char *)ns);
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

	update_cut_name(cut, U8(""));
	map_walk(&cut->nsset, free_addr_set, cut->pool);
	map_clear(&cut->nsset);

	/* Copy root hints from resolution context. */
	int ret = 0;
	if (ctx->root_hints.nsset.root) {
		ret = kr_zonecut_copy(cut, &ctx->root_hints);
	}
	return ret;
}

/** Fetch address for zone cut.  Any rank is accepted (i.e. glue as well). */
static void fetch_addr(struct kr_zonecut *cut, struct kr_cache *cache,
			const knot_dname_t *ns, uint16_t rrtype,
			const struct kr_query *qry)
// LATER(optim.): excessive data copying
{
	struct kr_cache_p peek;
	if (kr_cache_peek_exact(cache, ns, rrtype, &peek) != 0) {
		return;
	}
	int32_t new_ttl = kr_cache_ttl(&peek, qry, ns, rrtype);
	if (new_ttl < 0) {
		return;
	}

	knot_rrset_t cached_rr;
	knot_rrset_init(&cached_rr, /*const-cast*/(knot_dname_t *)ns, rrtype, KNOT_CLASS_IN);
	if (kr_cache_materialize(&cached_rr.rrs, &peek, new_ttl, cut->pool) < 0) {
		return;
	}
	knot_rdata_t *rd = cached_rr.rrs.data;
	for (uint16_t i = 0; i < cached_rr.rrs.rr_count; ++i) {
		(void) kr_zonecut_add(cut, ns, rd);
		rd = kr_rdataset_next(rd);
	}
}

/** Fetch best NS for zone cut. */
static int fetch_ns(struct kr_context *ctx, struct kr_zonecut *cut,
		    const knot_dname_t *name, const struct kr_query *qry,
		    uint8_t * restrict rank)
{
	struct kr_cache_p peek;
	int ret = kr_cache_peek_exact(&ctx->cache, name, KNOT_RRTYPE_NS, &peek);
	if (ret != 0) {
		return ret;
	}
	/* Note: we accept *any* rank from the cache.  We assume that nothing
	 * completely untrustworthy could get into the cache, e.g out-of-bailiwick
	 * records that weren't validated.
	 */
	*rank = peek.rank;

	int32_t new_ttl = kr_cache_ttl(&peek, qry, name, KNOT_RRTYPE_NS);
	if (new_ttl < 0) {
		return kr_error(ESTALE);
	}
	/* Materialize the rdataset temporarily, for simplicity. */
	knot_rdataset_t ns_rds = { 0, NULL };
	ret = kr_cache_materialize(&ns_rds, &peek, new_ttl, cut->pool);
	if (ret < 0) {
		return ret;
	}

	/* Insert name servers for this zone cut, addresses will be looked up
	 * on-demand (either from cache or iteratively) */
	for (unsigned i = 0; i < ns_rds.rr_count; ++i) {
		const knot_dname_t *ns_name = knot_ns_name(&ns_rds, i);
		(void) kr_zonecut_add(cut, ns_name, NULL);
		/* Fetch NS reputation and decide whether to prefetch A/AAAA records. */
		unsigned *cached = lru_get_try(ctx->cache_rep,
				(const char *)ns_name, knot_dname_size(ns_name));
		unsigned reputation = (cached) ? *cached : 0;
		if (!(reputation & KR_NS_NOIP4) && !(ctx->options.NO_IPV4)) {
			fetch_addr(cut, &ctx->cache, ns_name, KNOT_RRTYPE_A, qry);
		}
		if (!(reputation & KR_NS_NOIP6) && !(ctx->options.NO_IPV6)) {
			fetch_addr(cut,  &ctx->cache, ns_name, KNOT_RRTYPE_AAAA, qry);
		}
	}

	knot_rdataset_clear(&ns_rds, cut->pool);
	return kr_ok();
}

/**
 * Fetch secure RRSet of given type.
 */
static int fetch_secure_rrset(knot_rrset_t **rr, struct kr_cache *cache,
	const knot_dname_t *owner, uint16_t type, knot_mm_t *pool,
	const struct kr_query *qry)
{
	if (!rr) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
	/* peek, check rank and TTL */
	struct kr_cache_p peek;
	int ret = kr_cache_peek_exact(cache, owner, type, &peek);
	if (ret != 0) {
		return ret;
	}
	if (!kr_rank_test(peek.rank, KR_RANK_SECURE)) {
		return kr_error(ENOENT);
	}
	int32_t new_ttl = kr_cache_ttl(&peek, qry, owner, type);
	if (new_ttl < 0) {
		return kr_error(ESTALE);
	}
	/* materialize a new RRset */
	knot_rrset_free(rr, pool);
	*rr = mm_alloc(pool, sizeof(knot_rrset_t));
	if (*rr == NULL) {
		return kr_error(ENOMEM);
	}
	owner = knot_dname_copy(/*const-cast*/(knot_dname_t *)owner, pool);
	if (!owner) {
		mm_free(pool, *rr);
		*rr = NULL;
		return kr_error(ENOMEM);
	}
	knot_rrset_init(*rr, /*const-cast*/(knot_dname_t *)owner, type, KNOT_CLASS_IN);
	ret = kr_cache_materialize(&(*rr)->rrs, &peek, new_ttl, pool);
	if (ret < 0) {
		knot_rrset_free(rr, pool);
		return ret;
	}

	return kr_ok();
}

int kr_zonecut_find_cached(struct kr_context *ctx, struct kr_zonecut *cut,
			   const knot_dname_t *name, const struct kr_query *qry,
			   bool * restrict secured)
{
	//VERBOSE_MSG(qry, "_find_cached\n");
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
		if (fetch_ns(ctx, cut, label, qry, &rank) == 0) {
			/* Flag as insecure if cached as this */
			if (kr_rank_test(rank, KR_RANK_INSECURE)) {
				*secured = false;
			}
			/* Fetch DS and DNSKEY if caller wants secure zone cut */
			int ret_ds = 1, ret_dnskey = 1;
			if (*secured || is_root) {
				ret_ds = fetch_secure_rrset(&cut->trust_anchor, &ctx->cache,
						label, KNOT_RRTYPE_DS, cut->pool, qry);
				ret_dnskey = fetch_secure_rrset(&cut->key, &ctx->cache,
						label, KNOT_RRTYPE_DNSKEY, cut->pool, qry);
			}
			update_cut_name(cut, label);
			mm_free(cut->pool, qname);
			kr_cache_sync(&ctx->cache);
			WITH_VERBOSE(qry) {
				auto_free char *label_str = kr_dname_text(label);
				VERBOSE_MSG(qry,
					"found cut: %s (return codes: DS %d, DNSKEY %d)\n",
					label_str, ret_ds, ret_dnskey);
			}
			return kr_ok();
		}
		/* Subtract label from QNAME. */
		if (!is_root) {
			label = knot_wire_next_label(label, NULL);
		} else {
			break;
		}
	}
	kr_cache_sync(&ctx->cache);
	mm_free(cut->pool, qname);
	return kr_error(ENOENT);
}
