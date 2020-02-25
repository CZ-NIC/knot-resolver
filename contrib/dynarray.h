/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*!
 * \brief Simple write-once allocation-optimal dynamic array.
 *
 * Include it into your .c file
 *
 * prefix - identifier prefix, e.g. ptr -> struct ptr_dynarray, ptr_dynarray_add(), ...
 * ntype - data type to be stored. Let it be a number, pointer or small struct
 * initial_capacity - how many data items will be allocated on stac and copied with assignment
 *
 * prefix_dynarray_add() - add a data item
 * prefix_dynarray_fix() - call EVERYTIME the array is copied from some already invalid stack
 * prefix_dynarray_free() - call EVERYTIME you dismiss all copies of the array
 *
 */

#include <stdlib.h>
#include <assert.h>

#pragma once

#define DYNARRAY_VISIBILITY_STATIC static
#define DYNARRAY_VISIBILITY_PUBLIC
#define DYNARRAY_VISIBILITY_LIBRARY __public__

#define dynarray_declare(prefix, ntype, visibility, initial_capacity) \
	typedef struct prefix ## _dynarray { \
		ssize_t capacity; \
		ssize_t size; \
		ntype *(*arr)(struct prefix ## _dynarray *dynarray); \
		ntype init[initial_capacity]; \
		ntype *_arr; \
	} prefix ## _dynarray_t; \
	\
	visibility ntype *prefix ## _dynarray_arr(prefix ## _dynarray_t *dynarray); \
	visibility void prefix ## _dynarray_add(prefix ## _dynarray_t *dynarray, \
	                                        ntype const *to_add); \
	visibility void prefix ## _dynarray_free(prefix ## _dynarray_t *dynarray);

#define dynarray_foreach(prefix, ntype, ptr, array) \
	for (ntype *ptr = prefix ## _dynarray_arr(&(array)); \
	     ptr < prefix ## _dynarray_arr(&(array)) + (array).size; ptr++)

#define dynarray_define(prefix, ntype, visibility) \
	\
	static void prefix ## _dynarray_free__(struct prefix ## _dynarray *dynarray) \
	{ \
		if (dynarray->capacity > sizeof(dynarray->init) / sizeof(*dynarray->init)) { \
			free(dynarray->_arr); \
		} \
	} \
	\
	__attribute__((unused)) \
	visibility ntype *prefix ## _dynarray_arr(struct prefix ## _dynarray *dynarray) \
	{ \
		assert(dynarray->size <= dynarray->capacity); \
		return (dynarray->capacity <= sizeof(dynarray->init) / sizeof(*dynarray->init) ? \
			dynarray->init : dynarray->_arr); \
	} \
	\
	static ntype *prefix ## _dynarray_arr_init__(struct prefix ## _dynarray *dynarray) \
	{ \
		assert(dynarray->capacity == sizeof(dynarray->init) / sizeof(*dynarray->init)); \
		return dynarray->init; \
	} \
	\
	static ntype *prefix ## _dynarray_arr_arr__(struct prefix ## _dynarray *dynarray) \
	{ \
		assert(dynarray->capacity > sizeof(dynarray->init) / sizeof(*dynarray->init)); \
		return dynarray->_arr; \
	} \
	\
	__attribute__((unused)) \
	visibility void prefix ## _dynarray_add(struct prefix ## _dynarray *dynarray, \
	                                        ntype const *to_add) \
	{ \
		if (dynarray->capacity < 0) { \
			return; \
		} \
		if (dynarray->capacity == 0) { \
			dynarray->capacity = sizeof(dynarray->init) / sizeof(*dynarray->init); \
			dynarray->arr = prefix ## _dynarray_arr_init__; \
		} \
		if (dynarray->size >= dynarray->capacity) { \
			ssize_t new_capacity = dynarray->capacity * 2 + 1; \
			ntype *new_arr = calloc(new_capacity, sizeof(ntype)); \
			if (new_arr == NULL) { \
				prefix ## _dynarray_free__(dynarray); \
				dynarray->capacity = dynarray->size = -1; \
				return; \
			} \
			if (dynarray->capacity > 0) { \
				memcpy(new_arr, prefix ## _dynarray_arr(dynarray), \
				       dynarray->capacity * sizeof(ntype)); \
			} \
			prefix ## _dynarray_free__(dynarray); \
			dynarray->_arr = new_arr; \
			dynarray->capacity = new_capacity; \
			dynarray->arr = prefix ## _dynarray_arr_arr__; \
		} \
		prefix ## _dynarray_arr(dynarray)[dynarray->size++] = *to_add; \
	} \
	\
	__attribute__((unused)) \
	visibility void prefix ## _dynarray_free(struct prefix ## _dynarray *dynarray) \
	{ \
		prefix ## _dynarray_free__(dynarray); \
		memset(dynarray, 0, sizeof(*dynarray)); \
	}
