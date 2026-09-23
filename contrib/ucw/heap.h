/*
 *	Binary heap
 *
 *	Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

#pragma once

struct heap_val {
	int pos;
};

typedef struct heap_val heap_val_t;

struct heap {
   int num;		/* Number of elements */
   int max_size;	/* Size of allocated memory */
   int (*cmp)(void *, void *);
   heap_val_t **data;
};		/* Array follows */

#define INITIAL_HEAP_SIZE	512 /* initial heap size */
#define HEAP_INCREASE_STEP	2 /* multiplier for each inflation, keep conservative */
#define HEAP_DECREASE_THRESHOLD	2 /* threshold for deflation, keep conservative */
#define HELEMENT(h,num) 	((h)->data + (num))
#define HHEAD(h) 		HELEMENT((h), 1)
#define EMPTY_HEAP(h) 		((h)->num == 0)

int heap_init(struct heap *h, int (*cmp)(void *, void *), int init_size);
void heap_deinit(struct heap *h);

void heap_delmin(struct heap *h);
int heap_insert(struct heap *h, heap_val_t *e);
int heap_find(struct heap *h, heap_val_t *elm);
void heap_delete(struct heap *h, int e);
void heap_replace(struct heap *h, int pos, heap_val_t *e);
