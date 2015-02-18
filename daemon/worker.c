/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <uv.h>

#include <libknot/packet/pkt.h>
#include <libknot/internal/net.h>
#include <libknot/errcode.h>

#include "daemon/worker.h"
#include "daemon/layer/query.h"

/* Defines */
#define CACHE_DEFAULT_SIZE 10*1024*1024

int worker_init(struct worker_ctx *worker, mm_ctx_t *mm)
{
	if (worker == NULL) {
		return KNOT_EINVAL;
	}

	memset(worker, 0, sizeof(struct worker_ctx));
	worker->pool = mm;

	/* Open resolution context */
	int ret = kr_context_init(&worker->resolve, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Open resolution context cache */
	worker->resolve.cache = kr_cache_open("/tmp/kresolved", mm, CACHE_DEFAULT_SIZE);
	if (worker->resolve.cache == NULL) {
		fprintf(stderr, "Cache directory '/tmp/kresolved' not exists, exitting.\n");
		kr_context_deinit(&worker->resolve);
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

void worker_deinit(struct worker_ctx *worker)
{
	if (worker == NULL) {
		return;
	}

	kr_context_deinit(&worker->resolve);
}

int worker_exec(struct worker_ctx *worker, knot_pkt_t *answer, knot_pkt_t *query)
{
	if (worker == NULL) {
		return KNOT_EINVAL;
	}

	/* Parse query packet. */
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK) {
		return ret; /* Ignore malformed query. */
	}

	/* Process query packet. */
	knot_layer_t proc;
	memset(&proc, 0, sizeof(knot_layer_t));
	proc.mm = worker->pool;
	knot_layer_begin(&proc, LAYER_QUERY, &worker->resolve);
	int state = knot_layer_in(&proc, query);

	/* Build an answer. */
	if (state & (KNOT_NS_PROC_FULL|KNOT_NS_PROC_FAIL)) {
		knot_pkt_init_response(answer, query);
		state = knot_layer_out(&proc, answer);
	}

	/* Cleanup. */
	knot_layer_finish(&proc);

	return KNOT_EOK;
}
