/*  Copyright (C) 2015-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "daemon/tls.h"

#include "lib/generic/array.h"
#include "lib/generic/trie.h"

#include <uv.h>
#include <stdbool.h>

#include <sys/socket.h>
#ifndef AF_XDP
#define AF_XDP 44
#endif

struct engine;
struct session;

/** Ways to listen on a socket (which may exist already). */
typedef struct {
	int sock_type;    /**< SOCK_DGRAM or SOCK_STREAM */
	bool tls;         /**< only used together with .kind == NULL and SOCK_STREAM */
	bool http;        /**< DoH2, implies .tls (in current implementation) */
	bool xdp;         /**< XDP is special (not a normal socket, in particular) */
	bool freebind;    /**< used for binding to non-local address */
	const char *kind; /**< tag for other types: "control" or module-handled kinds */
} endpoint_flags_t;

struct endpoint_key;

static inline bool endpoint_flags_eq(endpoint_flags_t f1, endpoint_flags_t f2)
{
	if (f1.sock_type != f2.sock_type)
		return false;
	if (f1.kind && f2.kind)
		return strcasecmp(f1.kind, f2.kind);
	else
		return f1.tls == f2.tls && f1.kind == f2.kind;
}

/** Wrapper for a single socket to listen on.
 * There are two types: normal have handle, special have flags.kind (and never both).
 *
 * LATER: .family might be unexpected for IPv4-in-IPv6 addresses.
 * ATM AF_UNIX is only supported with flags.kind != NULL
 */
struct endpoint {
	/** uv_{udp,tcp,poll}_t (poll for XDP);
	 * NULL in case of endpoints that are to be handled by modules. */
	uv_handle_t *handle;
	int fd;              /**< POSIX file-descriptor; always used. */
	int family;          /**< AF_INET or AF_INET6 or AF_UNIX or AF_XDP */
	uint16_t port;       /**< TCP/UDP port.  Meaningless with AF_UNIX. */
	int16_t nic_queue;   /**< -1 or queue number of the interface for AF_XDP use. */
	bool engaged;        /**< to some module or internally */
	endpoint_flags_t flags;
};

/** @cond internal Array of endpoints */
typedef array_t(struct endpoint) endpoint_array_t;
/* @endcond */

struct net_tcp_param {
	uint64_t in_idle_timeout;
	uint64_t tls_handshake_timeout;
};

/** Information about an address that is allowed to use PROXYv2. */
struct net_proxy_data {
	union kr_in_addr addr;
	uint8_t netmask;   /**< Number of bits to be matched */
};

struct network {
	uv_loop_t *loop;

	/** Map: address string -> endpoint_array_t.
	 * \note even same address-port-flags tuples may appear. */
	trie_t *endpoints;

	/** Registry of callbacks for special endpoint kinds (for opening/closing).
	 * Map: kind (lowercased) -> lua function ID converted to void *
	 * The ID is the usual: raw int index in the LUA_REGISTRYINDEX table. */
	trie_t *endpoint_kinds;
	/** See network_engage_endpoints() */
	bool missing_kind_is_error : 1;

	/** True: All IPv4 addresses are allowed to use the PROXYv2 protocol */
	bool proxy_all4 : 1;
	/** True: All IPv6 addresses are allowed to use the PROXYv2 protocol */
	bool proxy_all6 : 1;

	/** IPv4 addresses and networks allowed to use the PROXYv2 protocol */
	trie_t *proxy_addrs4;
	/** IPv6 addresses and networks allowed to use the PROXYv2 protocol */
	trie_t *proxy_addrs6;

	struct tls_credentials *tls_credentials;
	tls_client_params_t *tls_client_params; /**< Use tls_client_params_*() functions. */
	struct tls_session_ticket_ctx *tls_session_ticket_ctx;
	struct net_tcp_param tcp;
	int tcp_backlog;
};

/** Pointer to the singleton network state. NULL if not initialized. */
KR_EXPORT extern struct network *the_network;

/** Initializes the network. */
void network_init(uv_loop_t *loop, int tcp_backlog);

/** Unregisters endpoints. Should be called before `network_deinit`
 * and `engine_deinit`. */
void network_unregister(void);

/** Deinitializes the network. `network_unregister` should be called before
 * this and before `engine_deinit`. */
void network_deinit(void);

/** Start listening on addr#port with flags.
 * \note if we did listen on that combination already,
 *       nothing is done and kr_error(EADDRINUSE) is returned.
 * \note there's no short-hand to listen both on UDP and TCP.
 * \note ownership of flags.* is taken on success.  TODO: non-success?
 * \param nic_queue == -1 for auto-selection or non-XDP.
 * \note In XDP mode, addr may be also interface name, so kr_error(ENODEV)
 *       is returned if some nonsense is passed
 */
int network_listen(const char *addr, uint16_t port,
		   int16_t nic_queue, endpoint_flags_t flags);

/** Allow the specified address to send the PROXYv2 header.
 * \note the address may be specified with a netmask
 */
int network_proxy_allow(const char* addr);

/** Reset all addresses allowed to send the PROXYv2 header. No addresses will
 * be allowed to send PROXYv2 headers from the point of calling this function
 * until re-allowed via network_proxy_allow again.
 */
void network_proxy_reset(void);

/** Start listening on an open file-descriptor.
 * \note flags.sock_type isn't meaningful here.
 * \note ownership of flags.* is taken on success.  TODO: non-success?
 */
int network_listen_fd(int fd, endpoint_flags_t flags);

/** Stop listening on all endpoints with matching addr#port.
 * port < 0 serves as a wild-card.
 * \return kr_error(ENOENT) if nothing matched. */
int network_close(const char *addr, int port);

/** Close all endpoints immediately (no waiting for UV loop). */
void network_close_force(void);

/** Enforce that all endpoints are registered from now on.
 * This only does anything with struct endpoint::flags.kind != NULL. */
int network_engage_endpoints(void);

/** Returns a string representation of the specified endpoint key.
 *
 * The result points into key or is on static storage like for kr_straddr() */
const char *network_endpoint_key_str(const struct endpoint_key *key);

int network_set_tls_cert(const char *cert);
int network_set_tls_key(const char *key);
void network_new_hostname(void);
int network_set_bpf(int bpf_fd);
void network_clear_bpf(void);
