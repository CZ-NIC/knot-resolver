#include "lib/zonecut.h"
#include "lib/defines.h"
#include <libknot/internal/mempool.h>

static void ns_free(struct kr_ns *ns, mm_ctx_t *mm)
{
	mm_free(mm, ns->name);
	mm_free(mm, ns);
}

static void nslist_free(list_t *list, mm_ctx_t *mm)
{
	struct kr_ns *ns = NULL, *next = NULL;
	WALK_LIST_DELSAFE(ns, next, *list) {
		ns_free(ns, mm);
	}
	mm_free(mm, list);
}

static void zonecut_clear(struct kr_zonecut_map *map)
{
	hattrie_iter_t *i = hattrie_iter_begin(map->trie, false);
	while(!hattrie_iter_finished(i)) {
		struct kr_zonecut *zonecut = *hattrie_iter_val(i);
		nslist_free(&zonecut->nslist, map->pool);
		mm_free(map->pool, zonecut->name);
		hattrie_iter_next(i);
	}
	hattrie_iter_free(i);
	hattrie_clear(map->trie);
}


int kr_zonecut_init(struct kr_zonecut_map *map, mm_ctx_t *mm)
{
	map->pool = mm;
	map->trie = hattrie_create_n(TRIE_BUCKET_SIZE, mm);
	if (map->trie == NULL) {
		return KNOT_ENOMEM;
	}

	/* Initialize root entry. */
	struct kr_zonecut *root = kr_zonecut_get(map, (const knot_dname_t*)"\0");
	if (root == NULL) {
		hattrie_free(map->trie);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

void kr_zonecut_deinit(struct kr_zonecut_map *map)
{
	zonecut_clear(map);
	hattrie_free(map->trie);
}

struct kr_zonecut *kr_zonecut_get(struct kr_zonecut_map *map, const knot_dname_t *name)
{
	value_t *val = hattrie_get(map->trie, (const char *)name, knot_dname_size(name));
	if (*val == NULL) {
		struct kr_zonecut *cut = mm_alloc(map->pool, sizeof(struct kr_zonecut));
		if (cut == NULL) {
			return NULL;
		}

		cut->name = knot_dname_copy(name, map->pool);
		if (cut->name == NULL) {
			mm_free(map->pool, cut);
			return NULL;
		}

		init_list(&cut->nslist);
		*val = cut;
	}

	return *val;
}

struct kr_zonecut *kr_zonecut_find(struct kr_zonecut_map *map, const knot_dname_t *name)
{
	value_t *val = NULL;
	while(val == NULL) {
		val = hattrie_tryget(map->trie, (const char *)name, knot_dname_size(name));
		if (val == NULL || EMPTY_LIST(*((list_t *)*val))) {
			/* Root delegation, may be empty. */
			if (*name == '\0') {
				return *val;
			}
			/* Look up parent. */
			name = knot_wire_next_label(name, NULL);
			val = NULL;
		}
	}

	return *val;
}

struct kr_ns *kr_ns_first(list_t *list)
{
	if (EMPTY_LIST(*list)) {
		return NULL;
	}

	return HEAD(*list);
}

struct kr_ns *kr_ns_get(list_t *list, const knot_dname_t *name, mm_ctx_t *mm)
{
	/* Check for duplicates. */
	struct kr_ns *ns = kr_ns_find(list, name);
	if (ns != NULL) {
		return ns;
	}

	ns = mm_alloc(mm, sizeof(struct kr_ns));
	if (ns == NULL) {
		return NULL;
	}

	memset(ns, 0, sizeof(struct kr_ns));
	ns->name = knot_dname_copy(name, mm);

	add_tail(list, (node_t *)ns);

	return ns;
}

struct kr_ns *kr_ns_find(list_t *list, const knot_dname_t *name)
{
	struct kr_ns *ns = NULL;
	WALK_LIST(ns, *list) {
		if (knot_dname_is_equal(ns->name, name)) {
			return ns;
		}
	}

	return NULL;
}

void kr_ns_del(list_t *list, struct kr_ns *ns, mm_ctx_t *mm)
{
	rem_node(&ns->node);
	ns_free(ns, mm);
}
