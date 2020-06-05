/*
 *	Binary heap
 *
 *	(c) 2012 Ondrej Filip <feela@network.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

/***
 * Introduction
 * ------------
 *
 * Binary heap is a simple data structure, which for example supports efficient insertions, deletions
 * and access to the minimal inserted item. We define several macros for such operations.
 * Note that because of simplicity of heaps, we have decided to define direct macros instead
 * of a <<generic:,macro generator>> as for several other data structures in the Libucw.
 *
 * A heap is represented by a number of elements and by an array of values. Beware that we
 * index this array from one, not from zero as do the standard C arrays.
 *
 * Most macros use these parameters:
 *
 * - @num - a variable (signed or unsigned integer) with the number of elements
 * - @heap - a C array of type @type; the heap is stored in `heap[1] .. heap[num]`; `heap[0]` is unused
 *
 * A valid heap must follow these rules:
 *
 * - `num >= 0`
 * - `heap[i] >= heap[i / 2]` for each `i` in `[2, num]`
 *
 * The first element `heap[1]` is always lower or equal to all other elements.
 ***/

#include <string.h>
#include <stdlib.h>
#include "contrib/ucw/heap.h"

static inline void heap_swap(heap_val_t **e1, heap_val_t **e2)
{
	if (e1 == e2) return; /* Stack tmp should be faster than tmpelem. */
	heap_val_t *tmp = *e1; /* Even faster than 2-XOR nowadays. */
	*e1 = *e2;
	*e2 = tmp;
	int pos = (*e1)->pos;
	(*e1)->pos = (*e2)->pos;
	(*e2)->pos = pos;
}

int heap_init(struct heap *h, int (*cmp)(void *, void *), int init_size)
{
	int isize = init_size ? init_size : INITIAL_HEAP_SIZE;

	h->num = 0;
	h->max_size = isize;
	h->cmp = cmp;
	h->data = malloc((isize + 1) * sizeof(heap_val_t*)); /* Temp element unused. */

	return h->data ? 1 : 0;
}

void heap_deinit(struct heap *h)
{
	free(h->data);
	memset(h, 0, sizeof(*h));
}

static inline void _heap_bubble_down(struct heap *h, int e)
{
	int e1;
	for (;;)
	{
		e1 = 2*e;
		if(e1 > h->num) break;
		if((h->cmp(*HELEMENT(h, e),*HELEMENT(h,e1)) < 0) && (e1 == h->num || (h->cmp(*HELEMENT(h, e),*HELEMENT(h,e1+1)) < 0))) break;
		if((e1 != h->num) && (h->cmp(*HELEMENT(h, e1+1), *HELEMENT(h,e1)) < 0)) e1++;
		heap_swap(HELEMENT(h,e),HELEMENT(h,e1));
		e = e1;
	}
}

static inline void _heap_bubble_up(struct heap *h, int e)
{
	int e1;
	while (e > 1)
	{
		e1 = e/2;
		if(h->cmp(*HELEMENT(h, e1),*HELEMENT(h,e)) < 0) break;
		heap_swap(HELEMENT(h,e),HELEMENT(h,e1));
		e = e1;
	}

}

static void heap_increase(struct heap *h, int pos, heap_val_t *e)
{
	*HELEMENT(h, pos) = e;
	e->pos = pos;
	_heap_bubble_down(h, pos);
}

static void heap_decrease(struct heap *h, int pos, heap_val_t *e)
{
	*HELEMENT(h, pos) = e;
	e->pos = pos;
	_heap_bubble_up(h, pos);
}

void heap_replace(struct heap *h, int pos, heap_val_t *e)
{
	if (h->cmp(*HELEMENT(h, pos),e) < 0) {
		heap_increase(h, pos, e);
	} else {
		heap_decrease(h, pos, e);
	}
}

void heap_delmin(struct heap *h)
{
	if(h->num == 0) return;
	if(h->num > 1)
	{
		heap_swap(HHEAD(h),HELEMENT(h,h->num));
	}
	(*HELEMENT(h, h->num))->pos = 0;
	--h->num;
	_heap_bubble_down(h, 1);
}

int heap_insert(struct heap *h, heap_val_t *e)
{
	if(h->num == h->max_size)
	{
		h->max_size = h->max_size * HEAP_INCREASE_STEP;
		h->data = realloc(h->data, (h->max_size + 1) * sizeof(heap_val_t*));
		if (!h->data) {
			return 0;
		}
	}

	h->num++;
	*HELEMENT(h,h->num) = e;
	e->pos = h->num;
	_heap_bubble_up(h,h->num);
	return 1;
}

int heap_find(struct heap *h, heap_val_t *elm)
{
	return ((struct heap_val *) elm)->pos;
}

void heap_delete(struct heap *h, int e)
{
	heap_swap(HELEMENT(h, e), HELEMENT(h, h->num));
	(*HELEMENT(h, h->num))->pos = 0;
	h->num--;
	if(h->cmp(*HELEMENT(h, e), *HELEMENT(h, h->num + 1)) < 0) _heap_bubble_up(h, e);
	else _heap_bubble_down(h, e);

	if ((h->num > INITIAL_HEAP_SIZE) && (h->num < h->max_size / HEAP_DECREASE_THRESHOLD))
	{
		h->max_size = h->max_size / HEAP_INCREASE_STEP;
		h->data = realloc(h->data, (h->max_size + 1) * sizeof(heap_val_t*));
	}
}
