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

#pragma once

#include <netinet/in.h>
#include <libknot/processing/overlay.h>
#include <libknot/packet/pkt.h>

#include "lib/generic/array.h"
#include "lib/nsrep.h"
#include "lib/rplan.h"
#include "lib/module.h"
#include "lib/cache.h"

/**
 * @file resolve.h
 * @brief The API provides a high-level API for simple name resolution,
 * and an API providing a "consumer-producer"-like interface to enable
 * you write custom I/O or special iterative resolution driver.
 *
 * # Example usage of the high-level API:
 *
 * @code{.c}
 *
 * struct kr_context ctx = {
 *     .pool = NULL, // for persistent data
 *     .cache = ..., // open cache instance (or NULL)
 *     .layers = {}  // loaded layers
 * };
 *
 * // Push basic layers
 * array_push(ctx.layers, iterate_layer);
 * array_push(ctx.layers, rrcache_layer);
 *
 * // Resolve "IN A cz."
 * knot_pkt_t *answer = knot_pkt_new(NULL, 65535, ctx.pool);
 * int ret = kr_resolve(&ctx, answer, (uint8_t*)"\x02cz", 1, 1);
 * printf("rcode: %d, ancount: %u\n",
 *        knot_wire_get_rcode(answer->wire),
 *        knot_wire_get_ancount(answer->wire));
 * @endcode
 *
 * # Example usage of the iterative API:
 *
 * @code{.c}
 *
 * // Create request and its memory pool
 * struct kr_request req = {
 * 	.pool = {
 * 		.ctx = mp_new (4096),
 * 		.alloc = (mm_alloc_t) mp_alloc
 * 	}
 * };
 * kr_resolve_begin(&req, ctx, answer);
 * int state = kr_resolve_query(&req, qname, qclass, qtype);
 *
 * // Generate answer
 * while (state == KNOT_STATE_PRODUCE) {
 *
 *     // Additional query generate, do the I/O and pass back answer
 *     state = kr_resolve_produce(&req, &addr, &type, query);
 *     while (state == KNOT_STATE_CONSUME) {
 *         int ret = sendrecv(addr, proto, query, resp);
 *
 *         // If I/O fails, make "resp" empty
 *         state = kr_resolve_consume(&request, resp);
 *         knot_pkt_clear(resp);
 *     }
 *     knot_pkt_clear(query);
 * }
 *
 * // "state" is either DONE or FAIL
 * kr_resolve_finish(&request, state);
 *
 * @endcode
 */

/* @cond internal Array of modules. */
typedef array_t(struct kr_module *) module_array_t;
/* @endcond */

/**
 * Name resolution context.
 *
 * Resolution context provides basic services like cache, configuration and options.
 *
 * @note This structure is persistent between name resolutions and may
 *       be shared between threads.
 */
struct kr_context
{
	mm_ctx_t *pool;
	struct kr_zonecut root_hints;
	struct kr_cache cache;
	kr_nsrep_lru_t *cache_rtt;
	kr_nsrep_lru_t *cache_rep;
	module_array_t *modules;
	uint32_t options;
};

/**
 * Name resolution request.
 *
 * Keeps information about current query processing between calls to
 * processing APIs, i.e. current resolved query, resolution plan, ...
 * Use this instead of the simple interface if you want to implement
 * multiplexing or custom I/O.
 *
 * @note All data for this request must be allocated from the given pool.
 */
struct kr_request {
    struct kr_context *ctx;
    struct kr_rplan rplan;
    struct knot_overlay overlay;
    knot_pkt_t *answer;
    mm_ctx_t pool;
    uint32_t options;
};

/**
 * Resolve an input query and produce a packet with an answer.
 *
 * @note The function doesn't change the packet question or message ID.
 *
 * @param ctx    resolution context
 * @param answer answer packet to be written
 * @param qname  resolved query name
 * @param qclass resolved query class
 * @param qtype  resolved query type
 * @return       0 or an error code
 */
int kr_resolve(struct kr_context* ctx, knot_pkt_t *answer,
               const knot_dname_t *qname, uint16_t qclass, uint16_t qtype);

/**
 * Begin name resolution.
 *
 * @note Expects a request to have an initialized mempool, the "answer" packet will
 *       be kept during the resolution and will contain the final answer at the end.
 *
 * @param request request state with initialized mempool
 * @param ctx     resolution context
 * @param answer  allocated packet for final answer
 * @return        CONSUME (expecting query)
 */
int kr_resolve_begin(struct kr_request *request, struct kr_context *ctx, knot_pkt_t *answer);

/**
 * Push new query for resolution to the state.
 * @param  request request state (if already has a question, this will be resolved first)
 * @param  qname
 * @param  qclass
 * @param  qtype
 * @return         PRODUCE|FAIL
 */
int kr_resolve_query(struct kr_request *request, const knot_dname_t *qname, uint16_t qclass, uint16_t qtype);

/**
 * Consume input packet (may be either first query or answer to query originated from kr_resolve_produce())
 *
 * @note If the I/O fails, provide an empty or NULL packet, this will make iterator recognize nameserver failure.
 * 
 * @param  request request state (awaiting input)
 * @param  packet  [in] input packet
 * @return         any state
 */
int kr_resolve_consume(struct kr_request *request, knot_pkt_t *packet);

/**
 * Produce either next additional query or finish.
 *
 * If the CONSUME is returned then dst, type and packet will be filled with
 * appropriate values and caller is responsible to send them and receive answer.
 * If it returns any other state, then content of the variables is undefined.
 * 
 * @param  request request state (in PRODUCE state)
 * @param  dst     [out] possible address of the next nameserver
 * @param  type    [out] possible used socket type (SOCK_STREAM, SOCK_DGRAM)
 * @param  packet  [out] packet to be filled with additional query
 * @return         any state
 */
int kr_resolve_produce(struct kr_request *request, struct sockaddr **dst, int *type, knot_pkt_t *packet);

/**
 * Finish resolution and commit results if the state is DONE.
 *
 * @note The structures will be deinitialized, but the assigned memory pool is not going to
 *       be destroyed, as it's owned by caller.
 *
 * @param  request request state
 * @param  state   either DONE or FAIL state
 * @return         DONE
 */
int kr_resolve_finish(struct kr_request *request, int state);
