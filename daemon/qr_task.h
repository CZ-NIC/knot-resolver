
#pragma once

#include "lib/generic/array.h"

#include <uv.h>

#include <stdbool.h>

struct qr_task;
struct request_ctx;

/** List of query resolution tasks. */
typedef array_t(struct qr_task *) qr_tasklist_t;

void qr_task_free(struct qr_task *task);

bool qr_task_is_full(const struct qr_task *task);

struct request_ctx *qr_task_get_request(struct qr_task *task);

/* Connect or issue query datagram */
void qr_task_append(struct qr_task *task, uv_handle_t *handle);

static inline void qr_task_ref(struct qr_task *task)
{
	uint32_t *refs = (uint32_t *)task;
	++*refs;
}
static inline void qr_task_unref(struct qr_task *task)
{
	if (!task) return;
	uint32_t *refs = (uint32_t *)task;
	if (--*refs == 0) {
		qr_task_free(task);
	}
}


