/*
 *	BIRD Library -- Linked Lists
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *	(c) 2015, 2020-2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Linked lists
 *
 * The BIRD library provides a set of functions for operating on linked
 * lists. The lists are internally represented as standard doubly linked
 * lists with synthetic head and tail which makes all the basic operations
 * run in constant time and contain no extra end-of-list checks. Each list
 * is described by a &list structure, nodes can have any format as long
 * as they start with a &node structure. If you want your nodes to belong
 * to multiple lists at once, you can embed multiple &node structures in them
 * and use the SKIP_BACK() macro to calculate a pointer to the start of the
 * structure from a &node pointer, but beware of obscurity.
 *
 * There also exist safe linked lists (&slist, &snode and all functions
 * being prefixed with |s_|) which support asynchronous walking very
 * similar to that used in the &fib structure.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/ucw/lists.h"
#include "contrib/mempattern.h"

/**
 * add_tail - append a node to a list
 * \p l: linked list
 * \p n: list node
 *
 * add_tail() takes a node \p n and appends it at the end of the list \p l.
 */
void
add_tail(list_t *l, node_t *n)
{
  node_t *z = &l->tail;

  n->next = z;
  n->prev = z->prev;
  z->prev->next = n;
  z->prev = n;
  assert(z->next == NULL);
}

/**
 * add_head - prepend a node to a list
 * \p l: linked list
 * \p n: list node
 *
 * add_head() takes a node \p n and prepends it at the start of the list \p l.
 */
void
add_head(list_t *l, node_t *n)
{
  node_t *z = &l->head;

  n->next = z->next;
  n->prev = z;
  z->next->prev = n;
  z->next = n;
  assert(z->prev == NULL);
}

/**
 * insert_node - insert a node to a list
 * \p n: a new list node
 * \p after: a node of a list
 *
 * Inserts a node \p n to a linked list after an already inserted
 * node \p after.
 */
void
insert_node(node_t *n, node_t *after)
{
  node_t *z = after->next;

  n->next = z;
  n->prev = after;
  after->next = n;
  z->prev = n;
}

/**
 * rem_node - remove a node from a list
 * \p n: node to be removed
 *
 * Removes a node \p n from the list it's linked in.
 */
void
rem_node(node_t *n)
{
  node_t *z = n->prev;
  node_t *x = n->next;

  z->next = x;
  x->prev = z;
  n->prev = 0;
  n->next = 0;
}

/**
 * init_list - create an empty list
 * \p l: list
 *
 * init_list() takes a &list structure and initializes its
 * fields, so that it represents an empty list.
 */
void
init_list(list_t *l)
{
  l->head.next = &l->tail;
  l->head.prev = NULL;
  l->tail.next = NULL;
  l->tail.prev = &l->head;
}

/**
 * add_tail_list - concatenate two lists
 * \p to: destination list
 * \p l: source list
 *
 * This function appends all elements of the list \p l to
 * the list \p to in constant time.
 */
void
add_tail_list(list_t *to, list_t *l)
{
  node_t *p = to->tail.prev;
  node_t *q = l->head.next;

  p->next = q;
  q->prev = p;
  to->tail.prev = l->tail.prev;
}

/**
 * list_dup - duplicate list
 * \p to: destination list
 * \p l: source list
 *
 * This function duplicates all elements of the list \p l to
 * the list \p to in linear time.
 *
 * This function only works with a homogenous item size.
 */
void list_dup(list_t *dst, list_t *src, size_t itemsz)
{
	node_t *n;
	WALK_LIST(n, *src) {
		node_t *i = malloc(itemsz);
		memcpy(i, n, itemsz);
		add_tail(dst, i);
	}
}

/**
 * list_size - gets number of nodes
 * \p l: list
 *
 * This function counts nodes in list \p l and returns this number.
 */
size_t list_size(const list_t *l)
{
	size_t count = 0;

	node_t *n;
	WALK_LIST(n, *l) {
		count++;
	}

	return count;
}

/**
 * fix_list - correction of head/tail pointers when list had been memmove'd
 * \p l: list
 *
 * WARNING: must not be called on empty list
 */
void fix_list(list_t *l)
{
	node_t *n = HEAD(*l);
	assert(n->next != NULL);
	n->prev = &l->head;

	n = TAIL(*l);
	assert(n->prev != NULL);
	n->next = &l->tail;
}

/**
 * ptrlist_add - add pointer to pointer list
 * \p to: destination list
 * \p val: added pointer
 * \p mm: memory context
 */
ptrnode_t *ptrlist_add(list_t *to, void *val, knot_mm_t *mm)
{
	ptrnode_t *node = mm_alloc(mm , sizeof(ptrnode_t));
	if (node == NULL) {
		return NULL;
	} else {
		node->d = val;
	}
	add_tail(to, &node->n);
	return node;
}

/**
 * ptrlist_free - free all nodes in pointer list
 * \p list: list nodes
 * \p mm: memory context
 */
void ptrlist_free(list_t *list, knot_mm_t *mm)
{
	node_t *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, *list) {
		mm_free(mm, n);
	}
	init_list(list);
}

/**
 * ptrlist_rem - remove pointer node
 * \p val: pointer to remove
 * \p mm: memory context
 */
void ptrlist_rem(ptrnode_t *node, knot_mm_t *mm)
{
	rem_node(&node->n);
	mm_free(mm, node);
}

/**
 * ptrlist_deep_free - free all nodes incl referenced data
 * \p list: list nodes
 * \p mm: memory context
 */
void ptrlist_deep_free(list_t *l, knot_mm_t *mm)
{
	ptrnode_t *n;
	WALK_LIST(n, *l) {
		mm_free(mm, n->d);
	}
	ptrlist_free(l, mm);
}

void ptrlist_free_custom(list_t *l, knot_mm_t *mm, ptrlist_free_cb free_cb)
{
	ptrnode_t *n;
	WALK_LIST(n, *l) {
		free_cb(n->d);
	}
	ptrlist_free(l, mm);
}
