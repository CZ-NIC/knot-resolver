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

#include "daemon/worker.h"
#include "daemon/engine.h"
#include "daemon/layer/query.h"

int worker_exec(struct worker_ctx *worker, knot_pkt_t *answer, knot_pkt_t *query)
{
	if (worker == NULL) {
		return kr_error(EINVAL);
	}

	/* Parse query packet. */
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK) {
		return kr_error(EPROTO); /* Ignore malformed query. */
	}

	/* Process query packet. */
	knot_layer_t proc;
	memset(&proc, 0, sizeof(knot_layer_t));
	proc.mm = worker->mm;
	knot_layer_begin(&proc, LAYER_QUERY, &worker->engine->resolver);
	int state = knot_layer_consume(&proc, query);

	/* Build an answer. */
	if (state & (KNOT_STATE_PRODUCE|KNOT_STATE_FAIL)) {
		knot_pkt_init_response(answer, query);
		state = knot_layer_produce(&proc, answer);
	}

	/* Cleanup. */
	knot_layer_finish(&proc);

	return kr_ok();
}
