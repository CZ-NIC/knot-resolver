/*
 * critbit89 - A crit-bit tree implementation for strings in C89
 * Written by Jonas Gehring <jonas@jgehring.net>
 */

/*
 * The code makes the assumption that malloc returns pointers aligned at at
 * least a two-byte boundary. Since the C standard requires that malloc return
 * pointers that can store any type, there are no commonly-used toolchains for
 * which this assumption is false.
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "critbit.h"

#ifdef _MSC_VER /* MSVC */
 typedef unsigned __int8 uint8_t;
 typedef unsigned __int32 uint32_t;
 #ifdef _WIN64
  typedef signed __int64 intptr_t;
 #else
  typedef _W64 signed int intptr_t;
 #endif
#else /* Not MSVC */
 #include <stdint.h>
#endif


typedef struct {
	void *child[2];
	uint32_t byte;
	uint8_t otherbits;
} cb_node_t;

/* Standard memory allocation functions */
static void *malloc_std(size_t size, void *baton) {
	(void)baton; /* Prevent compiler warnings */
	return malloc(size);
}

static void free_std(void *ptr, void *baton) {
	(void)baton; /* Prevent compiler warnings */
	free(ptr);
}

/* Static helper functions */
static void cbt_traverse_delete(cb_tree_t *tree, void *top)
{
	uint8_t *p = top;
	if (1 & (intptr_t)p) {
		cb_node_t *q = (void *)(p - 1);
		cbt_traverse_delete(tree, q->child[0]);
		cbt_traverse_delete(tree, q->child[1]);
		tree->free(q, tree->baton);
	} else {
		tree->free(p, tree->baton);
	}
}

static int cbt_traverse_prefixed(uint8_t *top,
	int (*callback)(const char *, void *), void *baton)
{
	if (1 & (intptr_t)top) {
		cb_node_t *q = (void *)(top - 1);
		int ret = 0;

		ret = cbt_traverse_prefixed(q->child[0], callback, baton);
		if (ret != 0) {
			return ret;
		}
		ret = cbt_traverse_prefixed(q->child[1], callback, baton);
		if (ret != 0) {
			return ret;
		}
		return 0;
	}

	return (callback)((const char *)top, baton);
}


/*! Creates a new, empty critbit tree */
cb_tree_t cb_tree_make()
{
	cb_tree_t tree;
	tree.root = NULL;
	tree.malloc = &malloc_std;
	tree.free = &free_std;
	tree.baton = NULL;
	return tree;
}

/*! Returns non-zero if tree contains str */
int cb_tree_contains(cb_tree_t *tree, const char *str)
{
	const uint8_t *ubytes = (void *)str;
	const size_t ulen = strlen(str);
	uint8_t *p = tree->root;

	if (p == NULL) {
		return 0;
	}

	while (1 & (intptr_t)p) {
		cb_node_t *q = (void *)(p - 1);
		uint8_t c = 0;
		int direction;

		if (q->byte < ulen) {
			c = ubytes[q->byte];
		}
		direction = (1 + (q->otherbits | c)) >> 8;

		p = q->child[direction];
	}

	return (strcmp(str, (const char *)p) == 0);
}

/*! Inserts str into tree, returns 0 on success */
int cb_tree_insert(cb_tree_t *tree, const char *str)
{
	const uint8_t *const ubytes = (void *)str;
	const size_t ulen = strlen(str);
	uint8_t *p = tree->root;
	uint8_t c, *x;
	uint32_t newbyte;
	uint32_t newotherbits;
	int direction, newdirection;
	cb_node_t *newnode;
	void **wherep;

	if (p == NULL) {
		x = tree->malloc(ulen + 1, tree->baton);
		if (x == NULL) {
			return ENOMEM;
		}
		memcpy(x, str, ulen + 1);
		tree->root = x;
		return 0;
	}

	while (1 & (intptr_t)p) {
		cb_node_t *q = (void *)(p - 1);
		c = 0;
		if (q->byte < ulen) {
			c = ubytes[q->byte];
		}
		direction = (1 + (q->otherbits | c)) >> 8;

		p = q->child[direction];
	}

	for (newbyte = 0; newbyte < ulen; ++newbyte) {
		if (p[newbyte] != ubytes[newbyte]) {
			newotherbits = p[newbyte] ^ ubytes[newbyte];
			goto different_byte_found;
		}
	}

	if (p[newbyte] != 0) {
		newotherbits = p[newbyte];
		goto different_byte_found;
	}
	return 1;

different_byte_found:
	newotherbits |= newotherbits >> 1;
	newotherbits |= newotherbits >> 2;
	newotherbits |= newotherbits >> 4;
	newotherbits = (newotherbits & ~(newotherbits >> 1)) ^ 255;
	c = p[newbyte];
	newdirection = (1 + (newotherbits | c)) >> 8;

	newnode = tree->malloc(sizeof(cb_node_t), tree->baton);
	if (newnode == NULL) {
		return ENOMEM;
	}

	x = tree->malloc(ulen + 1, tree->baton);
	if (x == NULL) {
		tree->free(newnode, tree->baton);
		return ENOMEM;
	}

	memcpy(x, ubytes, ulen + 1);
	newnode->byte = newbyte;
	newnode->otherbits = newotherbits;
	newnode->child[1 - newdirection] = x;

	/* Insert into tree */
	wherep = &tree->root;
	for (;;) {
		cb_node_t *q;
		p = *wherep;
		if (!(1 & (intptr_t)p)) {
			break;
		}

		q = (void *)(p - 1);
		if (q->byte > newbyte) {
			break;
		}
		if (q->byte == newbyte && q->otherbits > newotherbits) {
			break;
		}

		c = 0;
		if (q->byte < ulen) {
			c = ubytes[q->byte];
		}
		direction = (1 + (q->otherbits | c)) >> 8;
		wherep = q->child + direction;
	}

	newnode->child[newdirection] = *wherep;
	*wherep = (void *)(1 + (char *)newnode);
	return 0;
}

/*! Deletes str from the tree, returns 0 on success */
int cb_tree_delete(cb_tree_t *tree, const char *str)
{
	const uint8_t *ubytes = (void *)str;
	const size_t ulen = strlen(str);
	uint8_t *p = tree->root;
	void **wherep = 0, **whereq = 0;
	cb_node_t *q = 0;
	int direction = 0;

	if (tree->root == NULL) {
		return 1;
	}
	wherep = &tree->root;

	while (1 & (intptr_t)p) {
		uint8_t c = 0;
		whereq = wherep;
		q = (void *)(p - 1);

		if (q->byte < ulen) {
			c = ubytes[q->byte];
		}
		direction = (1 + (q->otherbits | c)) >> 8;
		wherep = q->child + direction;
		p = *wherep;
	}

	if (strcmp(str, (const char *)p) != 0) {
		return 1;
	}
	tree->free(p, tree->baton);

	if (!whereq) {
		tree->root = NULL;
		return 0;
	}

	*whereq = q->child[1 - direction];
	tree->free(q, tree->baton);
	return 0;
}

/*! Clears the given tree */
void cb_tree_clear(cb_tree_t *tree)
{
	if (tree->root) {
		cbt_traverse_delete(tree, tree->root);
	}
	tree->root = NULL;
}

/*! Calls callback for all strings in tree with the given prefix */
int cb_tree_walk_prefixed(cb_tree_t *tree, const char *prefix,
	int (*callback)(const char *, void *), void *baton)
{
	const uint8_t *ubytes = (void *)prefix;
	const size_t ulen = strlen(prefix);
	uint8_t *p = tree->root;
	uint8_t *top = p;

	if (p == NULL) {
		return 0;
	}

	while (1 & (intptr_t)p) {
		cb_node_t *q = (void *)(p - 1);
		uint8_t c = 0;
		int direction;

		if (q->byte < ulen) {
			c = ubytes[q->byte];
		}
		direction = (1 + (q->otherbits | c)) >> 8;

		p = q->child[direction];
		if (q->byte < ulen) {
			top = p;
		}
	}

	if (strlen((const char *)p) < ulen || memcmp(p, prefix, ulen) != 0) {
		/* No strings match */
		return 0;
	}

	return cbt_traverse_prefixed(top, callback, baton);
}
