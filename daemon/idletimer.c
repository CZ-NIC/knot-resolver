/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/idletimer.h"

bool defer_busy = false;
struct idletimer *skipped = NULL;

void idletimer_cb(uv_timer_t *timer);
void idletimer_init(idletimer_t *handle, idletimer_callback_t cb, uint64_t initial_timeout)
{
	*handle = (idletimer_t){
		.callback = cb
	};
	uv_timer_init(uv_default_loop(), &handle->timer);
	uv_timer_start(&handle->timer, idletimer_cb, initial_timeout, 0);
}

void idletimer_cb(uv_timer_t *timer)
{
	idletimer_t *handle = (idletimer_t *)timer;
	if (defer_busy) {
		handle->next = skipped;
		skipped = handle;
		return;
	}
	uint64_t next_timeout = handle->callback();
	uv_timer_start(timer, idletimer_cb, next_timeout, 0);
}

void idletimer_defer_busy(bool busy) {
	defer_busy = busy;
	if (!busy) {
		while (skipped) {
			uv_timer_start(&skipped->timer, idletimer_cb, 0, 0);
			skipped = skipped->next;
		}
	}
}
