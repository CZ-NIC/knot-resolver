/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "lib/generic/lru.h"
#include "contrib/murmurhash3/murmurhash3.h"

typedef struct lru_group lru_group_t;

struct lru_item {
	uint16_t key_len, val_len; /**< Two bytes should be enough for our purposes. */
	char data[];               /**< Place for both key and value. */
};

/** @internal Compute offset of value in struct lru_item. */
static uint val_offset(uint key_len)
{
	uint key_end = offsetof(struct lru_item, data) + key_len;
	// align it to the closest multiple of four
	return round_power(key_end, 2);
}

/** @internal Return pointer to value in an item. */
static void * item_val(struct lru_item *it)
{
	return it->data + val_offset(it->key_len) - offsetof(struct lru_item, data);
}

/** @internal Compute the size of an item. ATM we don't align/pad the end of it. */
static uint item_size(uint key_len, uint val_len)
{
	return val_offset(key_len) + val_len;
}

/** @internal Free each item. */
KR_EXPORT void lru_free_items_impl(struct lru *lru)
{
	assert(lru);
	for (size_t i = 0; i < (1 << (size_t)lru->log_groups); ++i) {
		lru_group_t *g = &lru->groups[i];
		for (int j = 0; j < LRU_ASSOC; ++j)
			mm_free(lru->mm, g->items[j]);
	}
}

/** @internal See lru_apply. */
KR_EXPORT void lru_apply_impl(struct lru *lru, lru_apply_fun f, void *baton)
{
	bool ok = lru && f;
	if (!ok) {
		assert(false);
		return;
	}
	for (size_t i = 0; i < (1 << (size_t)lru->log_groups); ++i) {
		lru_group_t *g = &lru->groups[i];
		for (uint j = 0; j < LRU_ASSOC; ++j) {
			struct lru_item *it = g->items[j];
			if (!it)
				continue;
			enum lru_apply_do ret =
				f(it->data, it->key_len, item_val(it), baton);
			switch(ret) {
			case LRU_APPLY_DO_EVICT: // evict
				mm_free(lru->mm, it);
				g->items[j] = NULL;
				g->counts[j] = 0;
				g->hashes[j] = 0;
				break;
			default:
				assert(ret == LRU_APPLY_DO_NOTHING);
			}
		}
	}
}

/** @internal See lru_create. */
KR_EXPORT struct lru * lru_create_impl(uint max_slots, knot_mm_t *mm_array, knot_mm_t *mm)
{
	assert(max_slots);
	if (!max_slots)
		return NULL;
	// let lru->log_groups = ceil(log2(max_slots / (float) assoc))
	//   without trying for efficiency
	uint group_count = (max_slots - 1) / LRU_ASSOC + 1;
	uint log_groups = 0;
	for (uint s = group_count - 1; s; s /= 2)
		++log_groups;
	group_count = 1 << log_groups;
	assert(max_slots <= group_count * LRU_ASSOC && group_count * LRU_ASSOC < 2 * max_slots);

	size_t size = offsetof(struct lru, groups[group_count]);
	struct lru *lru = mm_alloc(mm_array, size);
	if (unlikely(lru == NULL))
		return NULL;
	*lru = (struct lru){
		.mm = mm,
		.mm_array = mm_array,
		.log_groups = log_groups,
	};
	// zeros are a good init
	memset(lru->groups, 0, size - offsetof(struct lru, groups));
	return lru;
}

/** @internal Decrement all counters within a group. */
static void group_dec_counts(lru_group_t *g) {
	g->counts[LRU_TRACKED] = LRU_TRACKED;
	for (uint i = 0; i < LRU_TRACKED + 1; ++i)
		if (likely(g->counts[i]))
			--g->counts[i];
}

/** @internal Increment a counter within a group. */
static void group_inc_count(lru_group_t *g, int i) {
	if (likely(++(g->counts[i])))
       		return;
	g->counts[i] = -1;
	// We could've decreased or halved all of them, but let's keep the max.
}

/** @internal Implementation of both getting and insertion.
 * Note: val_len is only meaningful if do_insert. */
KR_EXPORT void * lru_get_impl(struct lru *lru, const char *key, uint key_len,
				uint val_len, bool do_insert)
{
	bool ok = lru && (key || !key_len) && key_len <= UINT16_MAX
		   && (!do_insert || val_len <= UINT16_MAX);
	if (!ok) {
		assert(false);
		return NULL; // reasonable fallback when not debugging
	}
	// find the right group
	uint32_t khash = hash(key, key_len);
	uint16_t khash_top = khash >> 16;
	lru_group_t *g = &lru->groups[khash & ((1 << lru->log_groups) - 1)];
	struct lru_item *it = NULL;
	uint i;
	// scan the *stored* elements in the group
	for (i = 0; i < LRU_ASSOC; ++i) {
		if (g->hashes[i] == khash_top) {
			it = g->items[i];
			if (likely(it && it->key_len == key_len
					&& (key_len == 0 || memcmp(it->data, key, key_len) == 0)))
				goto found; // to reduce huge nesting depth
		}
	}
	// key not found; first try an empty/counted-out place to insert
	if (do_insert)
		for (i = 0; i < LRU_ASSOC; ++i)
			if (g->items[i] == NULL || g->counts[i] == 0)
				goto insert;
	// check if we track key's count at least
	for (i = LRU_ASSOC; i < LRU_TRACKED; ++i) {
		if (g->hashes[i] == khash_top) {
			group_inc_count(g, i);
			if (!do_insert)
				return NULL;
			// check if we trumped some stored key
			for (uint j = 0; j < LRU_ASSOC; ++j)
				if (unlikely(g->counts[i] > g->counts[j])) {
					// evict key j, i.e. swap with i
					--g->counts[i]; // we increment it below
					SWAP(g->counts[i], g->counts[j]);
					SWAP(g->hashes[i], g->hashes[j]);
					i = j;
					goto insert;
				}
			return NULL;
		}
	}
	// not found at all: decrement all counts but only on every LRU_TRACKED occasion
	if (g->counts[LRU_TRACKED])
		--g->counts[LRU_TRACKED];
	else
		group_dec_counts(g);
	return NULL;
insert: // insert into position i (incl. key)
	assert(i < LRU_ASSOC);
	g->hashes[i] = khash_top;
	it = g->items[i];
	uint new_size = item_size(key_len, val_len);
	if (it == NULL || new_size != item_size(it->key_len, it->val_len)) {
		// (re)allocate
		mm_free(lru->mm, it);
		it = g->items[i] = mm_alloc(lru->mm, new_size);
		if (it == NULL)
			return NULL;
	}
	it->key_len = key_len;
	it->val_len = val_len;
	if (key_len > 0) {
		memcpy(it->data, key, key_len);
	}
	memset(item_val(it), 0, val_len); // clear the value
found: // key and hash OK on g->items[i]; now update stamps
	assert(i < LRU_ASSOC);
	group_inc_count(g, i);
	return item_val(g->items[i]);
}

