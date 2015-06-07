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
#include <libknot/dname.h>
#include <limits.h>

#include "lib/defines.h"
#include "lib/generic/map.h"
#include "lib/generic/lru.h"

struct kr_query;

/** 
  * NS RTT score (special values).
  * @note RTT is measured in milliseconds.
  */
enum kr_ns_score {
	KR_NS_MAX_SCORE = KR_CONN_RTT_MAX,
	KR_NS_TIMEOUT   = (95 * KR_NS_MAX_SCORE) / 100,
	KR_NS_UNKNOWN   = KR_NS_TIMEOUT / 2,
	KR_NS_GLUED     = 10
};

/**
 * NS QoS flags.
 */
enum kr_ns_rep {
	KR_NS_NOIP4  = 1 << 0, /**< NS has no IPv4 */
	KR_NS_NOIP6  = 1 << 1, /**< NS has no IPv6 */
	KR_NS_NOEDNS = 1 << 2  /**< NS has no EDNS support */
};

/**
 * NS reputation/QoS tracking.
 */
typedef lru_hash(unsigned) kr_nsrep_lru_t;

/**
 * Name server representation.
 * Contains extra information about the name server, e.g. score
 * or other metadata.
 */
struct kr_nsrep
{
	unsigned score;                  /**< NS score */
	unsigned reputation;             /**< NS reputation */
	const knot_dname_t *name;        /**< NS name */
	struct kr_context *ctx;          /**< Resolution context */
	union {
		struct sockaddr ip;
		struct sockaddr_in ip4;
		struct sockaddr_in6 ip6;
	} addr;                          /**< NS address */
};

/** @internal Address bytes for given family. */
#define kr_nsrep_inaddr(addr) \
	((addr).ip.sa_family == AF_INET ? (void *)&((addr).ip4.sin_addr) : (void *)&((addr).ip6.sin6_addr))
/** @internal Address length for given family. */
#define kr_nsrep_inaddr_len(addr) \
	((addr).ip.sa_family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr))

/**
 * Elect best nameserver/address pair from the nsset.
 * @param  qry          updated query
 * @param  ctx          resolution context
 * @return              0 or an error code
 */
int kr_nsrep_elect(struct kr_query *qry, struct kr_context *ctx);

/**
 * Elect best nameserver/address pair from the nsset.
 * @param  qry          updated query
 * @param  ctx          resolution context
 * @return              0 or an error code
 */
int kr_nsrep_elect_addr(struct kr_query *qry, struct kr_context *ctx);

/**
 * Update NS address RTT information.
 *
 * @brief Reputation is smoothed over last N measurements.
 * 
 * @param  ns           updated NS representation
 * @param  score        new score (i.e. RTT), see enum kr_ns_score
 * @param  cache        LRU cache
 * @return              0 on success, error code on failure
 */
int kr_nsrep_update_rtt(struct kr_nsrep *ns, unsigned score, kr_nsrep_lru_t *cache);

/**
 * Update NS name quality information.
 *
 * @brief Reputation is smoothed over last N measurements.
 * 
 * @param  ns           updated NS representation
 * @param  reputation   combined reputation flags, see enum kr_ns_rep
 * @param  cache        LRU cache
 * @return              0 on success, error code on failure
 */
int kr_nsrep_update_rep(struct kr_nsrep *ns, unsigned reputation, kr_nsrep_lru_t *cache);
