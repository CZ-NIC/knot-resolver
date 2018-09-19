
#pragma once

#include "lib/generic/array.h"

struct qr_task;
/** List of query resolution tasks. */
typedef array_t(struct qr_task *) qr_tasklist_t;

bool qr_task_is_full(const struct qr_task *task);

/* Connect or issue query datagram */
void qr_task_append(struct qr_task *task, uv_handle_t *handle);

