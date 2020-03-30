/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <netinet/in.h>
#include <sys/socket.h>
#include <libknot/dname.h>
#include <limits.h>

#include "lib/defines.h"
#include "lib/generic/lru.h"

struct kr_query;

/**
  * NS RTT score (special values).
  * @note RTT is measured in milliseconds.
  */
enum kr_ns_score {
	KR_NS_MAX_SCORE     = 20 * KR_CONN_RTT_MAX, /* max possible value */
	KR_NS_FWD_TIMEOUT   = (95 * 10000) / 100, /* timeout for upstream recursor,
						   * 95 percents from max resolution time */
	KR_NS_TIMEOUT       = (95 * KR_CONN_RTT_MAX) / 100, /* timeout for upstream auth */
	KR_NS_LONG          = (3 * KR_NS_TIMEOUT) / 4,
	KR_NS_UNKNOWN       = KR_NS_TIMEOUT / 2,
	KR_NS_PENALTY       = 100,
	KR_NS_GLUED         = 10
};

/**
 *  See kr_nsrep_update_rtt()
 */
#define KR_NS_DEAD (((KR_NS_TIMEOUT * 4) + 3) / 3)
#define KR_NS_FWD_DEAD (((KR_NS_FWD_TIMEOUT * 4) + 3) / 3)

/** If once NS was marked as "timeouted", it won't participate in NS elections
 * at least KR_NS_TIMEOUT_RETRY_INTERVAL milliseconds (now: one second). */
#define KR_NS_TIMEOUT_RETRY_INTERVAL 1000

/**
 * NS QoS flags.
 */
enum kr_ns_rep {
	KR_NS_NOIP4  = 1 << 0, /**< NS has no IPv4 */
	KR_NS_NOIP6  = 1 << 1, /**< NS has no IPv6 */
	KR_NS_NOEDNS = 1 << 2  /**< NS has no EDNS support */
};

/**
 * NS RTT update modes.
 * First update is always KR_NS_RESET unless
 * KR_NS_UPDATE_NORESET mode had choosen.
 */
enum kr_ns_update_mode {
	KR_NS_UPDATE = 0,     /**< Update as smooth over last two measurements */
	KR_NS_UPDATE_NORESET, /**< Same as KR_NS_UPDATE, but disable fallback to
			       *   KR_NS_RESET on newly added entries.
			       *   Zero is used as initial value. */
	KR_NS_RESET,          /**< Set to given value */
	KR_NS_ADD,            /**< Increment current value */
	KR_NS_MAX             /**< Set to maximum of current/proposed value. */
};

struct kr_nsrep_rtt_lru_entry {
	unsigned score;	          /* combined rtt */
	uint64_t tout_timestamp;  /* The time when score became
				   * greater or equal then KR_NS_TIMEOUT.
				   * Is meaningful only when score >= KR_NS_TIMEOUT */
};

typedef struct kr_nsrep_rtt_lru_entry kr_nsrep_rtt_lru_entry_t;

/**
 * NS QoS tracking.
 */
typedef lru_t(kr_nsrep_rtt_lru_entry_t) kr_nsrep_rtt_lru_t;

/**
 * NS reputation tracking.
 */
typedef lru_t(unsigned) kr_nsrep_lru_t;

/* Maximum count of addresses probed in one go (last is left empty) */
#define KR_NSREP_MAXADDR 4

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
	union inaddr addr[KR_NSREP_MAXADDR];        /**< NS address(es) */
};

/**
 * Set given NS address.  (Very low-level access to the list.)
 * @param  qry      updated query
 * @param  index    index of the updated target
 * @param  sock     socket address to use (sockaddr_in or sockaddr_in6 or NULL)
 * @return          0 or an error code, in particular kr_error(ENOENT) for net.ipvX
 */
KR_EXPORT
int kr_nsrep_set(struct kr_query *qry, size_t index, const struct sockaddr *sock);

/**
 * Elect best nameserver/address pair from the nsset.
 * @param  qry          updated query
 * @param  ctx          resolution context
 * @return              0 or an error code
 */
KR_EXPORT
int kr_nsrep_elect(struct kr_query *qry, struct kr_context *ctx);

/**
 * Elect best nameserver/address pair from the nsset.
 * @param  qry          updated query
 * @param  ctx          resolution context
 * @return              0 or an error code
 */
KR_EXPORT
int kr_nsrep_elect_addr(struct kr_query *qry, struct kr_context *ctx);

/**
 * Update NS address RTT information.
 *
 * @brief In KR_NS_UPDATE mode reputation is smoothed over last N measurements.
 * 
 * @param  ns           updated NS representation
 * @param  addr         chosen address (NULL for first)
 * @param  score        new score (i.e. RTT), see enum kr_ns_score
 * @param  cache        RTT LRU cache
 * @param  umode        update mode (KR_NS_UPDATE or KR_NS_RESET or KR_NS_ADD)
 * @return              0 on success, error code on failure
 */
KR_EXPORT
int kr_nsrep_update_rtt(struct kr_nsrep *ns, const struct sockaddr *addr,
			unsigned score, kr_nsrep_rtt_lru_t *cache, int umode);

/**
 * Update NSSET reputation information.
 * 
 * @param  ns           updated NS representation
 * @param  reputation   combined reputation flags, see enum kr_ns_rep
 * @param  cache        LRU cache
 * @return              0 on success, error code on failure
 */
KR_EXPORT
int kr_nsrep_update_rep(struct kr_nsrep *ns, unsigned reputation, kr_nsrep_lru_t *cache);
/**
 * Copy NSSET reputation information and resets score.
 *
 * @param  dst          updated NS representation
 * @param  src          source NS representation
 * @return              0 on success, error code on failure
 */
int kr_nsrep_copy_set(struct kr_nsrep *dst, const struct kr_nsrep *src);

/**
 * Sort addresses in the query nsrep list by cached RTT.
 * if RTT is greater then KR_NS_TIMEOUT, address will placed at the beginning of the
 * nsrep list once in cache.ns_tout() milliseconds. Otherwise it will be sorted
 * as if it has cached RTT equal to KR_NS_MAX_SCORE + 1.
 * @param  ns           updated kr_nsrep
 * @param  ctx          name resolution context.
 * @return              0 or an error code
 * @note   ns reputation is zeroed and score is set to KR_NS_MAX_SCORE + 1.
 */
KR_EXPORT
int kr_nsrep_sort(struct kr_nsrep *ns,  struct kr_context *ctx);
