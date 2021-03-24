/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
/**
 * @file queue.h
 * @brief A queue, usable for FIFO and LIFO simultaneously.
 *
 * Both the head and tail of the queue can be accessed and pushed to,
 * but only the head can be popped from.
 *
 * @note The implementation uses a singly linked list of blocks ("chunks")
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
	kr_require(queue_head(q) == 2);
	kr_require(queue_tail(q) == 4);

	// you may iterate
	typedef queue_it_t(int) queue_it_int_t;
	for (queue_it_int_t it = queue_it_begin(q); !queue_it_finished(it);
	     queue_it_next(it)) {
		++queue_it_val(it);
	}
	kr_require(queue_tail(q) == 5);

	queue_push_head(q, 0);
	++queue_tail(q);
	kr_require(queue_tail(q) == 6);
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
#include "lib/utils.h"
#include "contrib/ucw/lib.h"
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

/** @brief Remove the element at the head.
 * The queue must not be empty. */
#define queue_pop(q) \
	queue_pop_impl(&(q).queue)

/** @brief Return a "reference" to the element at the head (it's an L-value).
 * The queue must not be empty. */
#define queue_head(q) \
	( *(__typeof__((q).pdata_t)) queue_head_impl(&(q).queue) )

/** @brief Return a "reference" to the element at the tail (it's an L-value).
 * The queue must not be empty. */
#define queue_tail(q) \
	( *(__typeof__((q).pdata_t)) queue_tail_impl(&(q).queue) )

/** @brief Return the number of elements in the queue (very efficient). */
#define queue_len(q) \
	((const size_t)(q).queue.len)


/** @brief Type for queue iterator, parametrized by value type.
 * It's a simple structure that owns no other resources.
 * You may NOT use it after doing any push or pop (without _begin again). */
#define queue_it_t(type) \
	union { \
		type *pdata_t; /* only the *type* information is used */ \
		struct queue_it iter; \
	}

/** @brief Initialize a queue iterator at the head of the queue.
 * If you use this in assignment (instead of initialization),
 * you will unfortunately need to add corresponding type-cast in front.
 * Beware: there's no type-check between queue and iterator! */
#define queue_it_begin(q) \
	{ .iter = queue_it_begin_impl(&(q).queue) }

/** @brief Return a "reference" to the current element (it's an L-value) . */
#define queue_it_val(it) \
	( *(__typeof__((it).pdata_t)) queue_it_val_impl(&(it).iter) )

/** @brief Test if the iterator has gone past the last element.
 * If it has, you may not use _val or _next. */
#define queue_it_finished(it) \
	queue_it_finished_impl(&(it).iter)

/** @brief Advance the iterator to the next element. */
#define queue_it_next(it) \
	queue_it_next_impl(&(it).iter)



/* ====================== Internal for the implementation ================== */
/** @cond internal */

struct queue;
/* Non-inline functions are exported to be usable from daemon. */
KR_EXPORT void queue_init_impl(struct queue *q, size_t item_size);
KR_EXPORT void queue_deinit_impl(struct queue *q);
KR_EXPORT void * queue_push_impl(struct queue *q);
KR_EXPORT void * queue_push_head_impl(struct queue *q);

struct queue_chunk;
struct queue {
	size_t len; /**< the current number of items in queue */
	uint16_t chunk_cap; /**< max. number of items in each chunk */
	uint16_t item_size; /**< sizeof() each item */
	struct queue_chunk *head, *tail; /*< first and last chunk (or NULLs) */
};

struct queue_chunk {
	struct queue_chunk *next; /*< *head -> ... -> *tail; each is non-empty */
	int16_t begin, end, cap, pad_; /*< indices: zero is closest to head */
	/*< We could fit into uint8_t for example, but the choice of (3+1)*2 bytes
	 * is a compromise between wasting space and getting a good alignment.
	 * In particular, queue_t(type*) will store the pointers on addresses
	 * aligned to the pointer size, on both 64-bit and 32-bit platforms.
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
	kr_require(q);
	struct queue_chunk *h = q->head;
	kr_require(h && h->end > h->begin);
	return h->data + h->begin * q->item_size;
}

static inline void * queue_tail_impl(const struct queue *q)
{
	kr_require(q);
	struct queue_chunk *t = q->tail;
	kr_require(t && t->end > t->begin);
	return t->data + (t->end - 1) * q->item_size;
}

static inline void queue_pop_impl(struct queue *q)
{
	kr_require(q);
	struct queue_chunk *h = q->head;
	kr_require(h && h->end > h->begin);
	if (h->end - h->begin == 1) {
		/* removing the last element in the chunk */
		kr_require((q->len == 1) == (q->head == q->tail));
		if (q->len == 1) {
			q->tail = NULL;
			kr_require(!h->next);
		} else {
			kr_require(h->next);
		}
		q->head = h->next;
		free(h);
	} else {
		++(h->begin);
	}
	--(q->len);
}


struct queue_it {
	struct queue_chunk *chunk;
	int16_t pos, item_size;
};

static inline struct queue_it queue_it_begin_impl(struct queue *q)
{
	kr_require(q);
	return (struct queue_it){
		.chunk = q->head,
		.pos = q->head ? q->head->begin : -1,
		.item_size = q->item_size,
	};
}

static inline bool queue_it_finished_impl(struct queue_it *it)
{
	return it->chunk == NULL || it->pos >= it->chunk->end;
}

static inline void * queue_it_val_impl(struct queue_it *it)
{
	kr_require(!queue_it_finished_impl(it));
	return it->chunk->data + it->pos * it->item_size;
}

static inline void queue_it_next_impl(struct queue_it *it)
{
	kr_require(!queue_it_finished_impl(it));
	++(it->pos);
	if (it->pos < it->chunk->end)
		return;
	it->chunk = it->chunk->next;
	it->pos = it->chunk ? it->chunk->begin : -1;
}

/** @endcond (internal) */
/** @} (addtogroup generics) */

