#include "lib/delegpt.h"
#include <common/mempool.h>

static void delegpt_free(struct kr_ns *dp, mm_ctx_t *mm)
{
	mm_free(mm, dp->name);
	mm_free(mm, dp);
}

static void delegmap_clear(struct kr_delegmap *map)
{
	hattrie_iter_t *i = hattrie_iter_begin(map->trie, false);
	while(!hattrie_iter_finished(i)) {
		delegpt_free(*hattrie_iter_val(i), map->pool);
		hattrie_iter_next(i);
	}
	hattrie_iter_free(i);
	hattrie_clear(map->trie);
}


int kr_delegmap_init(struct kr_delegmap *map, mm_ctx_t *mm)
{
	map->pool = mm;
	map->trie = hattrie_create_n(TRIE_BUCKET_SIZE, mm);
	if (map->trie == NULL) {
		return -1;
	}

	return 0;
}

void kr_delegmap_deinit(struct kr_delegmap *map)
{
	delegmap_clear(map);
	hattrie_free(map->trie);
}

list_t *kr_delegmap_get(struct kr_delegmap *map, const knot_dname_t *name)
{
	value_t *val = hattrie_get(map->trie, (const char *)name, knot_dname_size(name));
	if (*val == NULL) {
		*val = mm_alloc(map->pool, sizeof(list_t));
		if (*val == NULL) {
			return NULL;
		}
		init_list((list_t *)*val);
	}

	return *val;
}

list_t *kr_delegmap_find(struct kr_delegmap *map, const knot_dname_t *name)
{
	value_t *val = NULL;
	while(val == NULL) {
		val = hattrie_tryget(map->trie, (const char *)name, knot_dname_size(name));
		if (val == NULL || EMPTY_LIST(*((list_t *)*val))) {
			/* No root delegation, failure. */
			if (*name == '\0') {
				assert(0);
				return NULL;
			}
			/* Look up parent. */
			name = knot_wire_next_label(name, NULL);
			val = NULL;
		}
	}

	return *val;
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
	ns->flags = DP_LAME;

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

void kr_ns_remove(struct kr_ns *ns, mm_ctx_t *mm)
{
	rem_node((node_t *)ns);
	delegpt_free(ns, mm);
}