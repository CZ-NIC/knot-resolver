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

#include "lib/generic/map.h"
#include "lib/generic/lru.h"

/** 
  * Special values for nameserver score (RTT in miliseconds)
  */
enum kr_ns_score {
	KR_NS_MAX_SCORE = 10 * 1000,
	KR_NS_TIMEOUT   = KR_NS_MAX_SCORE,
	KR_NS_UNKNOWN   = 10
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
	unsigned score;                  /**< Server score */
	const knot_dname_t *name;        /**< Server name */
	kr_nsrep_lru_t *repcache;        /**< Reputation cache pointer */
	union {
		struct sockaddr ip;
		struct sockaddr_in ip4;
		struct sockaddr_in6 ip6;
	} addr;                          /**< Server address */
};

/** @internal Address bytes for given family. */
#define kr_nsrep_inaddr(addr) \
	((addr).ip.sa_family == AF_INET ? (void *)&((addr).ip4.sin_addr) : (void *)&((addr).ip6.sin6_addr))
/** @internal Address length for given family. */
#define kr_nsrep_inaddr_len(addr) \
	((addr).ip.sa_family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr))

/**
 * Elect best nameserver/address pair from the nsset.
 * @param  ns           updated NS representation
 * @param  nsset        NS set to choose from
 * @param  repcache     reputation storage
 * @return              score, see enum kr_ns_score
 */
int kr_nsrep_elect(struct kr_nsrep *ns, map_t *nsset, kr_nsrep_lru_t *repcache);

/**
 * Update NS quality information.
 *
 * @brief Reputation is smoothed over last N measurements.
 * 
 * @param  ns           updated NS representation
 * @param  score        new score (i.e. RTT), see enum kr_ns_score
 * @param  reputation   reputation storage
 * @return              0 on success, error code on failure
 */
int kr_nsrep_update(struct kr_nsrep *ns, unsigned score, kr_nsrep_lru_t *repcache);
