/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#define EMPTY_HEAP(h) 		((h)->num == 0) /* h->num == 0 */

int heap_init(struct heap *, int (*cmp)(void *, void *), int);
void heap_deinit(struct heap *);

void heap_delmin(struct heap *);
int heap_insert(struct heap *, heap_val_t *);
int heap_find(struct heap *, heap_val_t *);
void heap_delete(struct heap *, int);
void heap_replace(struct heap *h, int pos, heap_val_t *);
