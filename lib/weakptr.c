/*  Copyright (C) 2015-2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "contrib/mempattern.h"
#include "lib/generic/trie.h"

#include "lib/weakptr.h"

struct weakptr_manager {
	trie_t *weak_to_mem; /**< Key: weakptr_t;
	                      *   Value: Pointer to managed memory */
	weakptr_t next_val;  /**< Value of the next created weakptr_t */
};

static struct weakptr_manager the_manager_val = {0};
static struct weakptr_manager *the_manager = NULL;

static inline weakptr_t weakptr_next()
{
	weakptr_t ptr = the_manager->next_val++;
	if (the_manager->next_val == WEAKPTR_NULL)
		the_manager->next_val++;
	return ptr;
}

int weakptr_manager_init()
{
	kr_assert(!the_manager);
	the_manager = &the_manager_val;

	the_manager->next_val = 1;
	the_manager->weak_to_mem = trie_create(NULL);
	kr_require(the_manager->weak_to_mem);

	return kr_ok();
}

void weakptr_manager_deinit()
{
	kr_assert(the_manager);
	size_t leaked = trie_weight(the_manager->weak_to_mem);
	if (leaked) {
		kr_log_debug(WEAKPTR, "Leaked %zu weak pointers!\n", leaked);
		/* TODO: Add an assertion here when proper session cleanup
		 *       is implemented. Without it, these messages are pretty
		 *       much useless false-positives. */
	}
	trie_free(the_manager->weak_to_mem);
	the_manager = NULL;
}

weakptr_t weakptr_mm_alloc(knot_mm_t *mm, size_t size, void **naked_ptr)
{
	bool rolled_over = false;
	weakptr_t initial_ptr = weakptr_next();
	weakptr_t ptr = initial_ptr;
	trie_val_t *val = NULL;

	do {
		/* Create reference to managed memory */
		val = trie_get_ins(the_manager->weak_to_mem,
				(const char *)&ptr, sizeof(weakptr_t));
		if (!val)
			goto exit_err;

		if (*val) {
			/* The pointer already exists, find a new one */

			if (ptr == initial_ptr && rolled_over) {
				/* Ran out of weak-pointer space */
				return WEAKPTR_NULL;
			}

			rolled_over = true;
			ptr = weakptr_next();
			continue;
		}

		/* Allocate the managed memory */
		*val = mm_alloc(mm, size);
		if (!*val)
			goto exit_err;

		*naked_ptr = *val;
		return ptr;
	} while (true);

exit_err:
	if (val) {
		trie_del(the_manager->weak_to_mem,
				(const char *)&ptr, sizeof(weakptr_t), NULL);
	}
	return WEAKPTR_NULL;
}

void weakptr_mm_free(knot_mm_t *mm, weakptr_t ptr)
{
	if (!ptr)
		return;

	/* Delete reference to managed memory */
	trie_val_t val;
	int ret = trie_del(the_manager->weak_to_mem,
			(const char *)&ptr, sizeof(weakptr_t), &val);
	if (kr_fails_assert(ret == KNOT_EOK))
		return;

	mm_free(mm, val);
}

void *weakptr_get(weakptr_t ptr)
{
	if (ptr == WEAKPTR_NULL)
		return NULL;

	trie_val_t *val = trie_get_try(the_manager->weak_to_mem,
			(const char *)&ptr, sizeof(weakptr_t));
	return (val) ? *val : NULL;
}
