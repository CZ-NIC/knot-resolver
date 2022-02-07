/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdint.h>

#include "daemon/session.h"
#include "daemon/network.h"
#include "lib/utils.h"

extern const char PROXY2_SIGNATURE[12];

#define PROXY2_MIN_SIZE 16

enum proxy2_command {
	PROXY2_CMD_LOCAL = 0x0,
	PROXY2_CMD_PROXY = 0x1
};

/** Parsed result of the PROXY protocol */
struct proxy_result {
	enum proxy2_command command;  /**< Proxy command - PROXY or LOCAL. */
	int family;                   /**< Address family from netinet library (e.g. AF_INET6). */
	int protocol;                 /**< Protocol type from socket library (e.g. SOCK_STREAM). */
	union kr_sockaddr src_addr;   /**< Parsed source address and port. */
	union kr_sockaddr dst_addr;   /**< Parsed destination address and port. */
	bool has_tls : 1;             /**< `true` = client has used TLS with the proxy.
	                                   If TLS padding is enabled, it will be used even if
	                                   the proxy did not use TLS with kresd. */
};

/** Checks for a PROXY protocol version 2 signature in the specified buffer. */
static inline bool proxy_header_present(const void* buf, const ssize_t nread)
{
	return nread >= PROXY2_MIN_SIZE &&
		memcmp(buf, PROXY2_SIGNATURE, sizeof(PROXY2_SIGNATURE)) == 0;
}

/** Checks whether the use of PROXYv2 protocol is allowed for the specified
 * address. */
bool proxy_allowed(const struct network *net, const struct sockaddr *saddr);

/** Parses the PROXYv2 header from buf of size nread and writes the result into
 * out. The rest of the buffer is moved to free bytes of the specified session's
 * wire buffer. The function assumes that the PROXYv2 signature is present
 * and has been already checked by the caller (like `udp_recv` or `tcp_recv`). */
ssize_t proxy_process_header(struct proxy_result *out, struct session *s,
                             const void *buf, ssize_t nread);
