/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "lib/generic/queue.h"
#include <string.h>

KR_EXPORT void queue_init_impl(struct queue *q, size_t item_size)
{
	q->len = 0;
	q->item_size = item_size;
	q->head = q->tail = NULL;
	/* Take 128 B (two x86 cache lines), except a small margin
	 * that the allocator can use for its overhead.
	 * Normally (64-bit pointers) this means 16 B header + 13*8 B data. */
	q->chunk_cap = ( ((ssize_t)128) - offsetof(struct queue_chunk, data)
			- sizeof(size_t)
			) / item_size;
	if (!q->chunk_cap) q->chunk_cap = 1; /* item_size big enough by itself */
}

KR_EXPORT void queue_deinit_impl(struct queue *q)
{
	assert(q);
	for (struct queue_chunk *p = q->head; p != NULL; p = p->next)
		free(p);
#ifndef NDEBUG
	memset(q, 0, sizeof(*q));
#endif
}

static struct queue_chunk * queue_chunk_new(const struct queue *q)
{
	struct queue_chunk *c = malloc(offsetof(struct queue_chunk, data)
					+ q->chunk_cap * q->item_size);
	if (unlikely(!c)) abort(); // simplify stuff
	memset(c, 0, offsetof(struct queue_chunk, data));
	c->cap = q->chunk_cap;
	/* ->begin and ->end are zero, i.e. we optimize for _push
	 * and not _push_head, by default. */
	return c;
}

/* Return pointer to the space for the new element. */
KR_EXPORT void * queue_push_impl(struct queue *q)
{
	assert(q);
	struct queue_chunk *t = q->tail; // shorthand
	if (unlikely(!t)) {
		assert(!q->head && !q->len);
		q->head = q->tail = t = queue_chunk_new(q);
	} else
	if (t->end == t->cap) {
		if (t->begin * 2 >= t->cap) {
			/* Utilization is below 50%, so let's shift (no overlap). */
			memcpy(t->data, t->data + t->begin * q->item_size,
				(t->end - t->begin) * q->item_size);
			t->end -= t->begin;
			t->begin = 0;
		} else {
			/* Let's grow the tail by another chunk. */
			assert(!t->next);
			t->next = queue_chunk_new(q);
			t = q->tail = t->next;
		}
	}
	assert(t->end < t->cap);
	++(q->len);
	++(t->end);
	return t->data + q->item_size * (t->end - 1);
}

/* Return pointer to the space for the new element. */
KR_EXPORT void * queue_push_head_impl(struct queue *q)
{
	/* When we have choice, we optimize for further _push_head,
	 * i.e. when shifting or allocating a chunk,
	 * we store items on the tail-end of the chunk. */
	assert(q);
	struct queue_chunk *h = q->head; // shorthand
	if (unlikely(!h)) {
		assert(!q->tail && !q->len);
		h = q->head = q->tail = queue_chunk_new(q);
		h->begin = h->end = h->cap;
	} else
	if (h->begin == 0) {
		if (h->end * 2 >= h->cap) {
			/* Utilization is below 50%, so let's shift (no overlap).
			 * Computations here are simplified due to h->begin == 0. */
			const int cnt = h->end;
			memcpy(h->data + (h->cap - cnt) * q->item_size, h->data,
				cnt * q->item_size);
			h->begin = h->cap - cnt;
			h->end = h->cap;
		} else {
			/* Let's grow the head by another chunk. */
			h = queue_chunk_new(q);
			h->next = q->head;
			q->head = h;
			h->begin = h->end = h->cap;
		}
	}
	assert(h->begin > 0);
	--(h->begin);
	++(q->len);
	return h->data + q->item_size * h->begin;
}

