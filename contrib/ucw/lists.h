/*
 *	BIRD Library -- Linked Lists
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *	(c) 2015, 2020-2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#pragma once

#include <string.h>
#include "libknot/mm_ctx.h"

typedef struct node {
  struct node *next, *prev;
} node_t;

typedef struct list {
  node_t head, tail;
} list_t;

#define NODE (node_t *)
#define HEAD(list) ((void *)((list).head.next))
#define TAIL(list) ((void *)((list).tail.prev))
#define WALK_LIST(n,list) for(n=HEAD(list);(NODE (n))->next; \
				n=(void *)((NODE (n))->next))
#define WALK_LIST_DELSAFE(n,nxt,list) \
     for(n=HEAD(list); (nxt=(void *)((NODE (n))->next)); n=(void *) nxt)
/* WALK_LIST_FIRST supposes that called code removes each processed node */
#define WALK_LIST_FIRST(n,list) \
     while(n=HEAD(list), (NODE (n))->next)
#define WALK_LIST_BACKWARDS(n,list) for(n=TAIL(list);(NODE (n))->prev; \
				n=(void *)((NODE (n))->prev))
#define WALK_LIST_BACKWARDS_DELSAFE(n,prv,list) \
     for(n=TAIL(list); prv=(void *)((NODE (n))->prev); n=(void *) prv)

#define EMPTY_LIST(list) (!(NODE HEAD(list))->next)

/*! \brief Free every node in the list. */
#define WALK_LIST_FREE(list) \
	do { \
	node_t *n=0,*nxt=0;  \
	WALK_LIST_DELSAFE(n,nxt,list) { \
	    free(n); \
	} \
	init_list(&list); \
	} while(0)

void add_tail(list_t *, node_t *);
void add_head(list_t *, node_t *);
void rem_node(node_t *);
void add_tail_list(list_t *, list_t *);
void init_list(list_t *);
void insert_node(node_t *, node_t *);
void list_dup(list_t *dst, list_t *src, size_t itemsz);
size_t list_size(const list_t *);
void fix_list(list_t *);

/*!
 * \brief Generic pointer list implementation.
 */
typedef struct ptrnode {
	node_t n;
	void *d;
} ptrnode_t;

ptrnode_t *ptrlist_add(list_t *, void *, knot_mm_t *);
void ptrlist_free(list_t *, knot_mm_t *);
void ptrlist_rem(ptrnode_t *node, knot_mm_t *mm);
void ptrlist_deep_free(list_t *, knot_mm_t *);

typedef void (*ptrlist_free_cb)(void *);
void ptrlist_free_custom(list_t *l, knot_mm_t *mm, ptrlist_free_cb free_cb);
