/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/* Idle timer may be used for periodic cleanup/prefetch/... actions
 * which can be arbitrarily delayed due to being busy.
 * If defer is active, callbacks calls require one libuv cycle without processing any requests
 * to make sure no work is pending;
 * if defer is disabled, it just uses libuv timers without checking for idle.
 */

#pragma once
#include <uv.h>
#include <stdbool.h>

/* Callback function doing the periodic work.
 * It is expected to return time delay in msec after which it may be called again.
 * You can yield earlier returning zero not to block for too long.
 * At least one libuv cycle is always processed before next execution.
 */
typedef uint64_t (*idletimer_callback_t)(void);

// An opaque handle.
typedef struct idletimer {
	uv_timer_t timer;
	idletimer_callback_t callback;
	struct idletimer *next;
} idletimer_t;


// Initialize idle timer.
void idletimer_init(idletimer_t *handle, idletimer_callback_t cb, uint64_t initial_timeout);

// Announce idle state from defer.
void idletimer_defer_busy(bool busy);
