/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/generic/queue.h"
#include <string.h>

void queue_init_impl(struct queue *q, size_t item_size)
{
	q->len = 0;
	q->item_size = item_size;
	q->head = q->tail = NULL;
	/* Take 128 B (two x86 cache lines), except a small margin
	 * that the allocator can use for its overhead.
	 * Normally (64-bit pointers) this means 16 B header + 13*8 B data. */
	q->chunk_cap = (128 - offsetof(struct queue_chunk, data)
			- sizeof(size_t)
			) / item_size;
	if (!q->chunk_cap) q->chunk_cap = 1; /* item_size big enough by itself */
}

void queue_deinit_impl(struct queue *q)
{
	if (kr_fails_assert(q))
		return;
	struct queue_chunk *p = q->head;
	while (p != NULL) {
		struct queue_chunk *pf = p;
		p = p->next;
		free(pf);
	}
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
void * queue_push_impl(struct queue *q)
{
	kr_require(q);
	struct queue_chunk *t = q->tail; // shorthand
	if (unlikely(!t)) {
		kr_require(!q->head && !q->len);
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
			kr_require(!t->next);
			t->next = queue_chunk_new(q);
			t = q->tail = t->next;
		}
	}
	kr_require(t->end < t->cap);
	++(q->len);
	++(t->end);
	return t->data + q->item_size * (t->end - 1);
}

/* Return pointer to the space for the new element. */
void * queue_push_head_impl(struct queue *q)
{
	/* When we have choice, we optimize for further _push_head,
	 * i.e. when shifting or allocating a chunk,
	 * we store items on the tail-end of the chunk. */
	kr_require(q);
	struct queue_chunk *h = q->head; // shorthand
	if (unlikely(!h)) {
		kr_require(!q->tail && !q->len);
		h = q->head = q->tail = queue_chunk_new(q);
		h->begin = h->end = h->cap;
	} else
	if (h->begin == 0) {
		if (h->end * 2 <= h->cap) {
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
	kr_require(h->begin > 0);
	--(h->begin);
	++(q->len);
	return h->data + q->item_size * h->begin;
}

