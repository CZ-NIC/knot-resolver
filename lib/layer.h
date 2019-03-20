/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "kresconfig.h"
#include "lib/defines.h"
#include "lib/utils.h"

#ifdef NOVERBOSELOG
	#define QRVERBOSE(query, cls, ...)
#else
	/** Print a debug message related to resolution.
	 * \param _query	associated kr_query, may be NULL
	 * \param _cls	identifying string, typically of length exactly four (padded)
	 * \param ...	printf-compatible list of parameters
	 */
	#define QRVERBOSE(_query, _cls, ...) do { \
		const struct kr_query *_qry = (_query); \
		if (kr_log_trace_enabled(_qry)) { \
			kr_log_trace(_qry, (_cls), __VA_ARGS__); \
		} else if (VERBOSE_STATUS) { \
			kr_log_qverbose_impl(_qry, (_cls), __VA_ARGS__); \
		}  \
	} while (false)
#endif

/** Layer processing states.  Only one value at a time (but see TODO).
 *
 *  Each state represents the state machine transition,
 *  and determines readiness for the next action.
 *  See struct kr_layer_api for the actions.
 *
 *  TODO: the cookie module sometimes sets (_FAIL | _DONE) on purpose (!)
 */
enum kr_layer_state {
	KR_STATE_CONSUME = 1 << 0, /*!< Consume data. */
	KR_STATE_PRODUCE = 1 << 1, /*!< Produce data. */
	KR_STATE_DONE    = 1 << 2, /*!< Finished successfully. */
	KR_STATE_FAIL    = 1 << 3, /*!< Error. */
	KR_STATE_YIELD   = 1 << 4, /*!< Paused, waiting for a sub-query. */
};

/* Forward declarations. */
struct kr_layer_api;

/** Packet processing context. */
typedef struct kr_layer {
	int state; /*!< The current state; bitmap of enum kr_layer_state. */
	struct kr_request *req; /*!< The corresponding request. */
	const struct kr_layer_api *api;
} kr_layer_t;

/** Packet processing module API.  All functions return the new kr_layer_state. */
struct kr_layer_api {
      	/** Start of processing the DNS request. */
	int (*begin)(kr_layer_t *ctx);

	int (*reset)(kr_layer_t *ctx);

	/** Paired to begin, called both on successes and failures. */
	int (*finish)(kr_layer_t *ctx);

	/** Processing an answer from upstream or the answer to the request. */
	int (*consume)(kr_layer_t *ctx, knot_pkt_t *pkt);

	/** Produce either an answer to the request or a query for upstream (or fail). */
	int (*produce)(kr_layer_t *ctx, knot_pkt_t *pkt);

	/** Finalises the outbound query packet with the knowledge of the IP addresses.
	 * The checkout layer doesn't persist the state, so canceled subrequests
	 * don't affect the resolution or rest of the processing. */
	/* FIXME: lua has been using boolean for `type` param (== SOCK_STREAM). */
	int (*checkout)(kr_layer_t *ctx, knot_pkt_t *packet, struct sockaddr *dst, int type);

	/** Finalises the answer.
	 * Last chance to affect what will get into the answer, including EDNS.*/
	int (*answer_finalize)(kr_layer_t *ctx);

	/** The C module can store anything in here. */
	void *data;
};

typedef struct kr_layer_api kr_layer_api_t;

/** Pickled layer state (api, input, state). */
struct kr_layer_pickle {
    struct kr_layer_pickle *next;
    const struct kr_layer_api *api;
    knot_pkt_t *pkt;
    unsigned state;
};

