/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/cache/api.h"

enum kr_selection_error {
	// Network errors
	KR_SELECTION_TIMEOUT,
	KR_SELECTION_TLS_HANDSHAKE_FAILED,
	KR_SELECTION_TCP_CONNECT_FAILED,
	KR_SELECTION_TCP_CONNECT_TIMEOUT,

	// RCODEs
	KR_SELECTION_REFUSED,
	KR_SELECTION_SERVFAIL,
	KR_SELECTION_FORMERROR,
	KR_SELECTION_NOTIMPL,
	KR_SELECTION_OTHER_RCODE,
	KR_SELECTION_TRUNCATED,

	// DNS errors
	KR_SELECTION_DNSSEC_ERROR,
	KR_SELECTION_LAME_DELEGATION,

	KR_SELECTION_NUMBER_OF_ERRORS // Leave this last as it is used as array size.
};

enum kr_transport_protocol {
	KR_TRANSPORT_NOADDR = 0,
	KR_TRANSPORT_UDP,
	KR_TRANSPORT_TCP,
	KR_TRANSPORT_TLS,
};

struct kr_transport {
	knot_dname_t *name;
	union inaddr address;
	size_t address_len;
	enum kr_transport_protocol protocol;
	unsigned timeout;
	bool deduplicated; // True iff transport was set in worker.c:subreq_finalize,
	// that means it may be different from the one originally chosen one.
};

struct kr_server_selection
{
	bool initialized;
	void (*choose_transport)(struct kr_query *qry, struct kr_transport **transport);
	void (*success)(struct kr_query *qry, const struct kr_transport *transport);
	void (*update_rtt)(struct kr_query *qry, const struct kr_transport *transport, unsigned rtt);
	void (*error)(struct kr_query *qry, const struct kr_transport *transport, enum kr_selection_error error);

	int timeouts;
	void *local_state;
};

// Initialize server selection structure inside qry.
KR_EXPORT
void kr_server_selection_init(struct kr_query *qry);

KR_EXPORT
int kr_forward_add_target(struct kr_request *req, size_t index, const struct sockaddr *sock);

// To be held per IP address in the global LMDB cache
struct rtt_state {
	int32_t srtt;
	int32_t variance;
	int32_t consecutive_timeouts;
};

// To be held per IP address and locally
struct address_state {
	unsigned int generation;
	struct rtt_state rtt_state;
	knot_dname_t *name;
	bool tls_capable : 1;
	bool tcp_waiting : 1;
	bool tcp_connected : 1;

	int forward_index;
	int error_count;
	int errors[KR_SELECTION_NUMBER_OF_ERRORS];
};

// Array of these is one of inputs for the actual selection algorithm (`iter_get_best_transport`)
struct choice {
	uint8_t *address;
	size_t address_len;
	struct address_state *address_state;
};

void error(struct kr_query *qry, struct address_state *addr_state, const struct kr_transport *transport, enum kr_selection_error sel_error);
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
 * @param out_forward_index Used to indentify the transport when forwarding
 * @return Chosen transport or NULL when no choice is viable
 */
struct kr_transport *choose_transport(struct choice choices[], int choices_len,
                                      knot_dname_t *unresolved[], int unresolved_len,
                                      int timeouts, struct knot_mm *mempool, bool tcp,
                                      size_t *out_forward_index);

/**
 * @brief Common part of RTT feedback mechanism. Notes RTT to global cache.
 */
void update_rtt(struct kr_query *qry, struct address_state *addr_state,
                const struct kr_transport *transport, unsigned rtt);

struct rtt_state get_rtt_state(const uint8_t *ip, size_t len, struct kr_cache *cache);
int put_rtt_state(const uint8_t *ip, size_t len, struct rtt_state state, struct kr_cache *cache);

void bytes_to_ip(uint8_t *bytes, size_t len, union inaddr *dst);
uint8_t* ip_to_bytes(const union inaddr *src, size_t len);

void check_tls_capable(struct address_state *address_state, struct kr_request *req, struct sockaddr *address);
void check_tcp_connections(struct address_state *address_state, struct kr_request *req, struct sockaddr *address);
void check_network_settings(struct address_state *address_state, size_t address_len, bool no_ipv4, bool no_ipv6);


