/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

/**
 * @file selection.h
 * Provides server selection API (see `kr_server_selection`) and functions common to both implementations.
 */

#include "lib/cache/api.h"

/**
 * These errors are to be reported as feedback to server selection.
 * See `kr_server_selection::error` for more details.
 */
enum kr_selection_error {
	KR_SELECTION_OK = 0,

	// Network errors
	KR_SELECTION_QUERY_TIMEOUT,
	KR_SELECTION_TLS_HANDSHAKE_FAILED,
	KR_SELECTION_TCP_CONNECT_FAILED,
	KR_SELECTION_TCP_CONNECT_TIMEOUT,

	// RCODEs
	KR_SELECTION_REFUSED,
	KR_SELECTION_SERVFAIL,
	KR_SELECTION_FORMERROR,
	KR_SELECTION_NOTIMPL,
	KR_SELECTION_OTHER_RCODE,

	// DNS errors
	KR_SELECTION_TRUNCATED,
	KR_SELECTION_DNSSEC_ERROR,
	KR_SELECTION_LAME_DELEGATION,
	KR_SELECTION_BAD_CNAME, /**< Too long chain, or cycle. */

	KR_SELECTION_NUMBER_OF_ERRORS /**< Leave this last, as it is used as array size. */
};

enum kr_transport_protocol {
	KR_TRANSPORT_RESOLVE_A, /**< Selected name with no IPv4 address, it has to be resolved first.*/
	KR_TRANSPORT_RESOLVE_AAAA, /**< Selected name with no IPv6 address, it has to be resolved first.*/
	KR_TRANSPORT_UDP,
	KR_TRANSPORT_TCP,
	KR_TRANSPORT_TLS,
};


/**
 * Output of the selection algorithm.
 */
struct kr_transport {
	knot_dname_t *ns_name; /**< Set to "." for forwarding targets.*/
	union inaddr address;
	size_t address_len;
	enum kr_transport_protocol protocol;
	unsigned timeout; /**< Timeout in ms to be set for UDP transmission. */
	bool deduplicated; /**< True iff transport was set in worker.c:subreq_finalize,
                                that means it may be different from the one originally chosen one.*/
	bool safe_mode; /**< Turn on SAFEMODE for this transport */
};

struct local_state {
	int timeouts; /**< Number of timeouts that occured resolving this query.*/
	bool truncated; /**< Query was truncated, switch to TCP. */
	void *private; /**< Inner state of the implementation.*/
};

/**
 * Specifies a API for selecting transports and giving feedback on the choices.
 *
 * The function pointers are to be used throughout resolver when some information about
 * the transport is obtained. E.g. RTT in `worker.c` or RCODE in `iterate.c`,…
 */
struct kr_server_selection
{
	bool initialized;
	/**
	 * Puts a pointer to next transport of @p qry to @p transport .
	 *
	 * Allocates new kr_transport in request's mempool, chooses transport to be used for this query.
	 * Selection may fail, so @p transport can be set to NULL.
	 *
	 * @param transport to be filled with pointer to the chosen transport or NULL on failure
	 */
	void (*choose_transport)(struct kr_query *qry, struct kr_transport **transport);
	/// Report back the RTT of network operation for transport in ms.
	void (*update_rtt)(struct kr_query *qry, const struct kr_transport *transport, unsigned rtt);
	/// Report back error encourtered with the chosen transport. See `enum kr_selection`
	void (*error)(struct kr_query *qry, const struct kr_transport *transport, enum kr_selection_error error);

	struct local_state *local_state;
};

/**
 * @brief Initialize the server selection API for @p qry.
 *
 * The implementation is to be chosen based on qry->flags.
 */
KR_EXPORT
void kr_server_selection_init(struct kr_query *qry);

/**
 * @brief Add forwarding target to request.
 *
 * This is exposed to Lua in order to add forwarding targets to request.
 * These are then shared by all the queries in said request.
 */
KR_EXPORT
int kr_forward_add_target(struct kr_request *req, size_t index, const struct sockaddr *sock);

/**
 * To be held per IP address in the global LMDB cache
 */
struct rtt_state {
	int32_t srtt;
	int32_t variance;
	int32_t consecutive_timeouts;
};

/**
 * @brief To be held per IP address and locally "inside" query.
 */
struct address_state {
	unsigned int generation; /**<< Used to distinguish old and valid records in local_state. */
	struct rtt_state rtt_state;
	knot_dname_t *ns_name;
	bool tls_capable : 1;
	/* TODO: uncomment these once we actually use this information in selection
	bool tcp_waiting : 1;
	bool tcp_connected : 1;
	*/
	int choice_array_index;
	int error_count;
	int unrecoverable_errors;
	int errors[KR_SELECTION_NUMBER_OF_ERRORS];
};

/**
 * @brief Array of these is one of inputs for the actual selection algorithm (`choose_transport`)
 */
struct choice {
	uint8_t *address;
	size_t address_len;
	struct address_state *address_state;
	uint16_t port; /**< used to overwrite the port number; if zero, `choose_transport` determines it*/
};

/**
 * @brief Array of these is description of names to be resolved (i.e. name without some address)
 */
struct to_resolve
{
	knot_dname_t *name;
	enum kr_transport_protocol type; /**< Either KR_TRANSPORT_RESOLVE_A or KR_TRANSPORT_RESOLVE_AAAA is valid here.*/
};


/**
 * @brief Based on passed choices, choose the next transport.
 *
 * Common function to both implementations (iteration and forwarding).
 * The `*_choose_transport` functions from `selection_*.h` preprocess the input for this one.
 *
 * @param choices Options to choose from, see struct above
 * @param unresolved Array of names that can be resolved (i.e. no A/AAAA record)
 * @param timeouts Number of timeouts that occured in this query (used for exponential backoff)
 * @param mempool Memory context of current request
 * @param tcp Force TCP as transport protocol
 * @param[out] choice_index Optinally index of the chosen transport in the @p choices array is stored here.
 * @return Chosen transport or NULL when no choice is viable
 */
struct kr_transport *choose_transport(struct choice choices[], int choices_len,
                                      struct to_resolve unresolved[], int unresolved_len,
                                      int timeouts, struct knot_mm *mempool, bool tcp,
                                      size_t *choice_index);

/**
 * Common part of RTT feedback mechanism. Notes RTT to global cache.
 */
void update_rtt(struct kr_query *qry, struct address_state *addr_state,
                const struct kr_transport *transport, unsigned rtt);

/**
 * Common part of error feedback mechanism.
 */
void error(struct kr_query *qry, struct address_state *addr_state,
           const struct kr_transport *transport, enum kr_selection_error sel_error);

/**
 * Get RTT state from cache. Returns `default_rtt_state` on unknown addresses.
 */
struct rtt_state get_rtt_state(const uint8_t *ip, size_t len, struct kr_cache *cache);

int put_rtt_state(const uint8_t *ip, size_t len, struct rtt_state state, struct kr_cache *cache);

/**
 * @internal Helper function for conversion between different IP representations.
 */
void bytes_to_ip(uint8_t *bytes, size_t len, union inaddr *dst);

/**
 * @internal Helper function for conversion between different IP representations.
 */
uint8_t* ip_to_bytes(const union inaddr *src, size_t len);

/**
 * Check if IP address is TLS capable.
 * 
 * @p req has to have the selection_context properly initiazed.
 */
void check_tls_capable(struct address_state *address_state, struct kr_request *req,
                       struct sockaddr *address);

#if 0
/* TODO: uncomment these once we actually use the information they collect. */
/**
 * Check if there is a existing TCP connection to this address.
 * 
 * @p req has to have the selection_context properly initiazed.
 */
void check_tcp_connections(struct address_state *address_state, struct kr_request *req,
                           struct sockaddr *address);
#endif

/**
 * Invalidate address if the respective IP version is disabled.
 */
void check_network_settings(struct address_state *address_state, size_t address_len,
                            bool no_ipv4, bool no_ipv6);


