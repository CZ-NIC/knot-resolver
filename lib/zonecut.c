/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/zonecut.h"

#include "contrib/cleanup.h"
#include "lib/defines.h"
#include "lib/generic/pack.h"
#include "lib/layer.h"
#include "lib/resolve.h"
#include "lib/rplan.h"

#include <libknot/descriptor.h>
#include <libknot/packet/wire.h>
#include <libknot/rrtype/rdname.h>

#define VERBOSE_MSG(qry, ...) QRVERBOSE(qry, ZCUT, __VA_ARGS__)

/** Information for one NS name + address type. */
typedef enum {
	AI_UNINITED = 0,
	AI_REPUT,	/**< Don't use this addrset, due to: cache_rep, NO_IPV6, ...
			 * cache_rep approximates various problems when fetching the RRset. */
	AI_CYCLED,	/**< Skipped due to cycle detection; see implementation for details. */
	AI_LAST_BAD = AI_CYCLED, /** bad states: <= AI_LAST_BAD */
	AI_UNKNOWN,	/**< Don't know status of this RRset; various reasons. */
	AI_EMPTY,	/**< No usable address (may mean e.g. just NODATA). */
	AI_OK,		/**< At least one usable address.
			 * LATER: we might be interested whether it's only glue. */
} addrset_info_t;


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

	memset(cut, 0, sizeof(*cut));
	cut->name = knot_dname_copy(name, pool);
	cut->pool = pool;
	cut->nsset = trie_create(pool);
	return cut->name && cut->nsset ? kr_ok() : kr_error(ENOMEM);
}

/** Completely free a pack_t. */
static inline void free_addr_set(pack_t *pack, knot_mm_t *pool)
{
	if (kr_fails_assert(pack)) {
		/* promised we don't store NULL packs */
		return;
	}
	pack_clear_mm(*pack, mm_free, pool);
	mm_free(pool, pack);
}
/** Trivial wrapper for use in trie_apply, due to ugly casting. */
static int free_addr_set_cb(trie_val_t *v, void *pool)
{
	free_addr_set(*v, pool);
	return kr_ok();
}

void kr_zonecut_deinit(struct kr_zonecut *cut)
{
	if (!cut) {
		return;
	}
	mm_free(cut->pool, cut->name);
	if (cut->nsset) {
		trie_apply(cut->nsset, free_addr_set_cb, cut->pool);
		trie_free(cut->nsset);
	}
	knot_rrset_free(cut->key, cut->pool);
	knot_rrset_free(cut->trust_anchor, cut->pool);
}

void kr_zonecut_move(struct kr_zonecut *to, const struct kr_zonecut *from)
{
	if (!to || !from) abort();
	kr_zonecut_deinit(to);
	memcpy(to, from, sizeof(*to));
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

int kr_zonecut_copy(struct kr_zonecut *dst, const struct kr_zonecut *src)
{
	if (!dst || !src) {
		return kr_error(EINVAL);
	}
	if (!dst->nsset) {
		dst->nsset = trie_create(dst->pool);
	}
	/* Copy the contents, one by one. */
	int ret = kr_ok();
	trie_it_t *it;
	for (it = trie_it_begin(src->nsset); !trie_it_finished(it); trie_it_next(it)) {
		size_t klen;
		const char * const k = trie_it_key(it, &klen);
		pack_t **new_pack = (pack_t **)trie_get_ins(dst->nsset, k, klen);
		if (!new_pack) {
			ret = kr_error(ENOMEM);
			break;
		}
		const pack_t *old_pack = *trie_it_val(it);
		ret = pack_clone(new_pack, old_pack, dst->pool);
		if (ret) break;
	}
	trie_it_free(it);
	return ret;
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
			knot_rrset_free(key_copy, dst->pool);
			return kr_error(ENOMEM);
		}
	}

	knot_rrset_free(dst->key, dst->pool);
	dst->key = key_copy;
	knot_rrset_free(dst->trust_anchor, dst->pool);
	dst->trust_anchor = ta_copy;

	return kr_ok();
}

int kr_zonecut_add(struct kr_zonecut *cut, const knot_dname_t *ns, const void *data, int len)
{
	if (kr_fails_assert(cut && ns && cut->nsset && (!data || len > 0)))
		return kr_error(EINVAL);
	/* Disabled; add_reverse_pair() misuses this for domain name in rdata. */
	if (false && data && len != sizeof(struct in_addr)
		  && len != sizeof(struct in6_addr)) {
		kr_assert(!EINVAL);
		return kr_error(EINVAL);
	}

	/* Get a pack_t for the ns. */
	pack_t **pack = (pack_t **)trie_get_ins(cut->nsset, (const char *)ns, knot_dname_size(ns));
	if (!pack) return kr_error(ENOMEM);
	if (*pack == NULL) {
		*pack = mm_alloc(cut->pool, sizeof(pack_t));
		if (*pack == NULL) return kr_error(ENOMEM);
		pack_init(**pack);
	}
	/* Insert data (if has any) */
	if (data == NULL) {
		return kr_ok();
	}
	/* Check for duplicates */
	if (pack_obj_find(*pack, data, len)) {
		return kr_ok();
	}
	/* Push new address */
	int ret = pack_reserve_mm(**pack, 1, len, kr_memreserve, cut->pool);
	if (ret != 0) {
		return kr_error(ENOMEM);
	}
	return pack_obj_push(*pack, data, len);
}

int kr_zonecut_del(struct kr_zonecut *cut, const knot_dname_t *ns, const void *data, int len)
{
	if (!cut || !ns || (data && len <= 0)) {
		return kr_error(EINVAL);
	}

	/* Find the address list. */
	int ret = kr_ok();
	pack_t *pack = kr_zonecut_find(cut, ns);
	if (pack == NULL) {
		return kr_error(ENOENT);
	}
	/* Remove address from the pack. */
	if (data) {
		ret = pack_obj_del(pack, data, len);
	}
	/* No servers left, remove NS from the set. */
	if (pack->len == 0) {
		free_addr_set(pack, cut->pool);
		ret = trie_del(cut->nsset, (const char *)ns, knot_dname_size(ns), NULL);
		if (kr_fails_assert(ret == 0)) /* only KNOT_ENOENT and that *can't* happen */
			return kr_error(ret);
		return kr_ok();
	}

	return ret;
}

int kr_zonecut_del_all(struct kr_zonecut *cut, const knot_dname_t *ns)
{
	if (!cut || !ns) {
		return kr_error(EINVAL);
	}

	/* Find the address list; then free and remove it. */
	pack_t *pack;
	int ret = trie_del(cut->nsset, (const char *)ns, knot_dname_size(ns),
			   (trie_val_t *)&pack);
	if (ret) { /* deletion failed */
		kr_assert(ret == KNOT_ENOENT);
		return kr_error(ENOENT);
	}
	free_addr_set(pack, cut->pool);
	return kr_ok();
}

pack_t *kr_zonecut_find(struct kr_zonecut *cut, const knot_dname_t *ns)
{
	if (!cut || !ns) {
		return NULL;
	}
	trie_val_t *val = trie_get_try(cut->nsset, (const char *)ns, knot_dname_size(ns));
	/* we get pointer to the pack_t pointer */
	return val ? (pack_t *)*val : NULL;
}

static int has_address(trie_val_t *v, void *baton_)
{
	const pack_t *pack = *v;
	const bool found = pack != NULL && pack->len != 0;
	return found;
}

bool kr_zonecut_is_empty(struct kr_zonecut *cut)
{
	if (kr_fails_assert(cut && cut->nsset))
		return true;
	return !trie_apply(cut->nsset, has_address, NULL);
}

int kr_zonecut_set_sbelt(struct kr_context *ctx, struct kr_zonecut *cut)
{
	if (!ctx || !cut || !ctx->root_hints.nsset) {
		return kr_error(EINVAL);
	}

	trie_apply(cut->nsset, free_addr_set_cb, cut->pool);
	trie_clear(cut->nsset);

	const uint8_t *const dname_root = (const uint8_t *)/*sign-cast*/("");
	update_cut_name(cut, dname_root);
	/* Copy root hints from resolution context. */
	return kr_zonecut_copy(cut, &ctx->root_hints);
}

/** Fetch address for zone cut.  Any rank is accepted (i.e. glue as well). */
static addrset_info_t fetch_addr(pack_t *addrs, const knot_dname_t *ns, uint16_t rrtype,
				 knot_mm_t *mm_pool, const struct kr_query *qry)
// LATER(optim.): excessive data copying
{
	int rdlen;
	switch (rrtype) {
	case KNOT_RRTYPE_A:
		rdlen = 4;
		break;
	case KNOT_RRTYPE_AAAA:
		rdlen = 16;
		break;
	default:
		kr_assert(!EINVAL);
		return AI_UNKNOWN;
	}

	struct kr_context *ctx = qry->request->ctx;
	struct kr_cache_p peek;
	if (kr_cache_peek_exact(&ctx->cache, ns, rrtype, &peek) != 0) {
		return AI_UNKNOWN;
	}
	int32_t new_ttl = kr_cache_ttl(&peek, qry, ns, rrtype);
	if (new_ttl < 0) {
		return AI_UNKNOWN;
	}

	knot_rrset_t cached_rr;
	knot_rrset_init(&cached_rr, /*const-cast*/(knot_dname_t *)ns, rrtype,
			KNOT_CLASS_IN, new_ttl);
	if (kr_cache_materialize(&cached_rr.rrs, &peek, mm_pool) < 0) {
		return AI_UNKNOWN;
	}

	/* Reserve memory in *addrs.  Implementation detail:
	 * pack_t cares for lengths, so we don't store those in the data. */
	const size_t pack_extra_size = cached_rr.rrs.size
		- cached_rr.rrs.count * offsetof(knot_rdata_t, len);
	int ret = pack_reserve_mm(*addrs, cached_rr.rrs.count, pack_extra_size,
				  kr_memreserve, mm_pool);
	if (ret) abort(); /* ENOMEM "probably" */

	int usable_cnt = 0;
	addrset_info_t result = AI_EMPTY;
	knot_rdata_t *rd = cached_rr.rrs.rdata;
	for (uint16_t i = 0; i < cached_rr.rrs.count; ++i, rd = knot_rdataset_next(rd)) {
		if (unlikely(rd->len != rdlen)) {
			VERBOSE_MSG(qry, "bad NS address length %d for rrtype %d, skipping\n",
					(int)rd->len, (int)rrtype);
			continue;
		}
		result = AI_OK;
		++usable_cnt;

		ret = pack_obj_push(addrs, rd->data, rd->len);
		kr_assert(!ret); /* didn't fit because of incorrectly reserved memory */
		/* LATER: for now we lose quite some information here,
		 * as keeping it would need substantial changes on other places,
		 * and it turned out to be premature optimization (most likely).
		 * We might e.g. skip adding unusable addresses,
		 * and either keep some rtt information associated
		 * or even finish up choosing the set to send packets to.
		 * Overall there's some overlap with nsrep.c functionality.
		 */
	}
	if (usable_cnt != cached_rr.rrs.count) {
		VERBOSE_MSG(qry, "usable NS addresses: %d/%d\n",
				usable_cnt, cached_rr.rrs.count);
	}
	return result;
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
	knot_rdataset_t ns_rds = { 0 };
	ret = kr_cache_materialize(&ns_rds, &peek, cut->pool);
	if (ret < 0) {
		return ret;
	}

	/* Insert name servers for this zone cut, addresses will be looked up
	 * on-demand (either from cache or iteratively) */
	bool all_bad = true; /**< All NSs (seen so far) are in a bad state. */
	knot_rdata_t *rdata_i = ns_rds.rdata;
	for (unsigned i = 0; i < ns_rds.count;
			++i, rdata_i = knot_rdataset_next(rdata_i)) {
		const knot_dname_t *ns_name = knot_ns_name(rdata_i);
		const size_t ns_size = knot_dname_size(ns_name);

		/* Get a new pack within the nsset. */
		pack_t **pack = (pack_t **)trie_get_ins(cut->nsset,
					(const char *)ns_name, ns_size);
		if (!pack) return kr_error(ENOMEM);
		kr_assert(!*pack); /* not critical, really */
		*pack = mm_alloc(cut->pool, sizeof(pack_t));
		if (!*pack) return kr_error(ENOMEM);
		pack_init(**pack);

		addrset_info_t infos[2];

		/* Fetch NS reputation and decide whether to prefetch A/AAAA records. */
		infos[0] = fetch_addr(*pack, ns_name, KNOT_RRTYPE_A, cut->pool, qry);
		infos[1] = fetch_addr(*pack, ns_name, KNOT_RRTYPE_AAAA, cut->pool, qry);

		#if 0 /* rather unlikely to be useful unless changing some zcut code */
		if (kr_log_is_debug_qry(ZCUT, qry)) {
			auto_free char *ns_name_txt = kr_dname_text(ns_name);
			VERBOSE_MSG(qry, "NS %s infos: %d, %d\n",
					ns_name_txt, (int)infos[0], (int)infos[1]);
		}
		#endif

		/* AI_CYCLED checks.
		 * If an ancestor query has its zone cut in the state that
		 * it's looking for name or address(es) of some NS(s),
		 * we want to avoid doing so with a NS that lies under its cut.
		 * Instead we need to consider such names unusable in the cut (for now). */
		if (infos[0] != AI_UNKNOWN && infos[1] != AI_UNKNOWN) {
			/* Optimization: the following loop would be pointless. */
			all_bad = false;
			continue;
		}
		for (const struct kr_query *aq = qry; aq->parent; aq = aq->parent) {
			const struct kr_qflags *aqpf = &aq->parent->flags;
			if (   (aqpf->AWAIT_CUT  && aq->stype == KNOT_RRTYPE_NS)
			    || (aqpf->AWAIT_IPV4 && aq->stype == KNOT_RRTYPE_A)
			    || (aqpf->AWAIT_IPV6 && aq->stype == KNOT_RRTYPE_AAAA)) {
				if (knot_dname_in_bailiwick(ns_name,
							aq->parent->zone_cut.name)) {
					for (int j = 0; j < 2; ++j)
						if (infos[j] == AI_UNKNOWN)
							infos[j] = AI_CYCLED;
					break;
				}
			} else {
				/* This ancestor waits for other reason that
				 * NS name or address, so we're out of a direct cycle. */
				break;
			}
		}
		all_bad = all_bad && infos[0] <= AI_LAST_BAD && infos[1] <= AI_LAST_BAD;
	}

	if (all_bad && kr_log_is_debug_qry(ZCUT, qry)) {
		auto_free char *name_txt = kr_dname_text(name);
		VERBOSE_MSG(qry, "cut %s: all NSs bad, count = %d\n",
				name_txt, (int)ns_rds.count);
	}
	knot_rdataset_clear(&ns_rds, cut->pool);
	return all_bad ? ELOOP : kr_ok();
}

/**
 * Fetch secure RRSet of given type.
 */
static int fetch_secure_rrset(knot_rrset_t **rr, struct kr_cache *cache,
	const knot_dname_t *owner, uint16_t type, knot_mm_t *pool,
	const struct kr_query *qry)
{
	if (kr_fails_assert(rr))
		return kr_error(EINVAL);
	/* peek, check rank and TTL */
	struct kr_cache_p peek;
	int ret = kr_cache_peek_exact(cache, owner, type, &peek);
	if (ret != 0)
		return ret;
	if (!kr_rank_test(peek.rank, KR_RANK_SECURE))
		return kr_error(ENOENT);
	int32_t new_ttl = kr_cache_ttl(&peek, qry, owner, type);
	if (new_ttl < 0)
		return kr_error(ESTALE);
	/* materialize a new RRset */
	knot_rrset_free(*rr, pool);
	*rr = mm_alloc(pool, sizeof(knot_rrset_t));
	if (*rr == NULL)
		return kr_error(ENOMEM);
	owner = knot_dname_copy(/*const-cast*/(knot_dname_t *)owner, pool);
	if (!owner) {
		mm_free(pool, *rr);
		*rr = NULL;
		return kr_error(ENOMEM);
	}
	knot_rrset_init(*rr, /*const-cast*/(knot_dname_t *)owner, type,
			KNOT_CLASS_IN, new_ttl);
	ret = kr_cache_materialize(&(*rr)->rrs, &peek, pool);
	if (ret < 0) {
		knot_rrset_free(*rr, pool);
		*rr = NULL;
		return ret;
	}

	return kr_ok();
}

int kr_zonecut_find_cached(struct kr_context *ctx, struct kr_zonecut *cut,
			   const knot_dname_t *name, const struct kr_query *qry,
			   bool * restrict secured)
{
	if (!ctx || !cut || !name)
		return kr_error(EINVAL);
	/* I'm not sure whether the caller always passes a clean state;
	 * mixing doesn't seem to make sense in any case, so let's clear it.
	 * We don't bother freeing the packs, as they're on mempool. */
	trie_clear(cut->nsset);
	/* Copy name as it may overlap with cut name that is to be replaced. */
	knot_dname_t *qname = knot_dname_copy(name, cut->pool);
	if (!qname) {
		return kr_error(ENOMEM);
	}
	/* Start at QNAME. */
	int ret;
	const knot_dname_t *label = qname;
	while (true) {
		/* Fetch NS first and see if it's insecure. */
		uint8_t rank = 0;
		const bool is_root = (label[0] == '\0');
		ret = fetch_ns(ctx, cut, label, qry, &rank);
		if (ret == 0) {
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
			if (kr_log_is_debug_qry(ZCUT, qry)) {
				auto_free char *label_str = kr_dname_text(label);
				VERBOSE_MSG(qry,
					"found cut: %s (rank 0%.2o return codes: DS %d, DNSKEY %d)\n",
					label_str, rank, ret_ds, ret_dnskey);
			}
			ret = kr_ok();
			break;
		} /* else */

		trie_clear(cut->nsset);
		/* Subtract label from QNAME. */
		if (!is_root) {
			label = knot_wire_next_label(label, NULL);
		} else {
			ret = kr_error(ENOENT);
			break;
		}
	}

	kr_cache_commit(&ctx->cache);
	mm_free(cut->pool, qname);
	return ret;
}
