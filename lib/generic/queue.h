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
/**
 * @file queue.h
 * @brief A queue, usable for FIFO and LIFO simultaneously.
 *
 * FIXME: unit tests
 *
 * Both the head and tail of the queue can be accessed and pushed to,
 * but only the head can be popped from.
 *
 * @note The implementation uses a singly linked list of blocks
 * where each block stores an array of values (for better efficiency).
 *
 * Example usage:
 * @code{.c}
	// define new queue type, and init a new queue instance
	typedef queue_t(int) queue_int_t;
	queue_int_t q;
	queue_init(q);
	// do some operations
	queue_push(q, 1);
	queue_push(q, 2);
	queue_push(q, 3);
	queue_push(q, 4);
	queue_pop(q);
	assert(queue_head(q) == 2);
	assert(queue_tail(q) == 4);
	queue_push_head(q, 0);
	++queue_tail(q);
	assert(queue_tail(q) == 5);
	// free it up
	queue_deinit(q);

	// you may use dynamic allocation for the type itself
	queue_int_t *qm = malloc(sizeof(queue_int_t));
	queue_init(*qm);
	queue_deinit(*qm);
	free(qm);
 * @endcode
 *
 * \addtogroup generics
 * @{
 */

#pragma once

#include "lib/defines.h"
#include "contrib/ucw/lib.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/** @brief The type for queue, parametrized by value type. */
#define queue_t(type) \
	union { \
		type *pdata_t; /* only the *type* information is used */ \
		struct queue queue; \
	}

/** @brief Initialize a queue.  You can malloc() it the usual way. */
#define queue_init(q) do { \
	(void)(((__typeof__(((q).pdata_t)))0) == (void *)0); /* typecheck queue_t */ \
	queue_init_impl(&(q).queue, sizeof(*(q).pdata_t)); \
	} while (false)

/** @brief De-initialize a queue: make it invalid and free any inner allocations. */
#define queue_deinit(q) \
	queue_deinit_impl(&(q).queue)

/** @brief Push data to queue's tail.  (Type-safe version; use _impl() otherwise.) */
#define queue_push(q, data) \
	*((__typeof__((q).pdata_t)) queue_push_impl(&(q).queue)) = data

/** @brief Push data to queue's head.  (Type-safe version; use _impl() otherwise.) */
#define queue_push_head(q, data) \
	*((__typeof__((q).pdata_t)) queue_push_head_impl(&(q).queue)) = data

/** @brief Remove the element at the head. */
#define queue_pop(q) \
	queue_pop_impl(&(q).queue)

/** @brief Return a "reference" to the element at the head (it's an L-value) . */
#define queue_head(q) \
	( *(__typeof__((q).pdata_t)) queue_head_impl(&(q).queue) )

/** @brief Return a "reference" to the element at the tail (it's an L-value) . */
#define queue_tail(q) \
	( *(__typeof__((q).pdata_t)) queue_tail_impl(&(q).queue) )

/** @brief Return the number of elements in the queue. */
#define queue_len(q) \
	((const size_t)(q).queue.len)



/* ====================== Internal for the implementation ================== */
/** @cond internal */

struct queue;
/* Non-inline functions are exported to be usable from daemon. */
void queue_init_impl(struct queue *q, size_t item_size);
void queue_deinit_impl(struct queue *q);
void * queue_push_impl(struct queue *q);
void * queue_push_head_impl(struct queue *q);

struct queue_chunk;
struct queue {
	size_t len;
	uint16_t chunk_cap, item_size;
	struct queue_chunk *head, *tail;
};

struct queue_chunk {
	struct queue_chunk *next; /*< head -> ... -> tail */
	int16_t begin, end, cap, pad_; /*< indices: zero is closest to head */
	/*< We could fit into uint8_t for example, but the choice of (3+1)*2 bytes
	 * is a compromise between wasting space and getting a good alignment.
	 * In particular, queue_t(type*) will store the pointers on addresses
	 * aligned to the pointer size, in both 64-bit and 32-bit platforms.
	 */
	char data[];
	/**< The item data.  We use "char" to satisfy the C99+ aliasing rules.
	 * See C99 section 6.5 Expressions, paragraph 7.
	 * Any type can be accessed through char-pointer,
	 * so we can use a common struct definition
	 * for all types being held.
	 */
};

static inline void * queue_head_impl(const struct queue *q)
{
	assert(q);
	struct queue_chunk *h = q->head;
	if (unlikely(!h))
		return NULL;
	assert(h->end > h->begin);
	return h->data + h->begin * q->item_size;
}

static inline void * queue_tail_impl(const struct queue *q)
{
	assert(q);
	struct queue_chunk *t = q->tail;
	if (unlikely(!t))
		return NULL;
	assert(t->end > t->begin);
	return t->data + (t->end - 1) * q->item_size;
}

static inline void queue_pop_impl(struct queue *q)
{
	assert(q);
	struct queue_chunk *h = q->head;
	assert(h && h->end > h->begin);
	if (h->end - h->begin == 1) {
		/* removing the last element in the chunk */
		q->head = h->next;
		free(h);
	} else {
		++(h->begin);
	}
	--(q->len);
}

/** @endcond (internal) */
/** @} (addtogroup generics) */

