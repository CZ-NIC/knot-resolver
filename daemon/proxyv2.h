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
#define PROXY2_IP6_ADDR_SIZE 16
#define PROXY2_UNIX_ADDR_SIZE 108

enum proxy2_command {
	PROXY2_CMD_LOCAL = 0x0,
	PROXY2_CMD_PROXY = 0x1
};

enum proxy2_family {
	PROXY2_AF_UNSPEC = 0x0,
	PROXY2_AF_INET   = 0x1,
	PROXY2_AF_INET6  = 0x2,
	PROXY2_AF_UNIX   = 0x3
};

enum proxy2_protocol {
	PROXY2_PROTOCOL_UNSPEC = 0x0,
	PROXY2_PROTOCOL_STREAM = 0x1,
	PROXY2_PROTOCOL_DGRAM  = 0x2
};

/** PROXYv2 protocol header section */
struct proxy2_header {
	uint8_t signature[sizeof(PROXY2_SIGNATURE)];
	uint8_t version_command;
	uint8_t family_protocol;
	uint16_t length; /**< Length of the address section */
};

/** PROXYv2 protocol address section */
union proxy2_address {
	struct {
		uint32_t src_addr;
		uint32_t dst_addr;
		uint16_t src_port;
		uint16_t dst_port;
	} ipv4_addr;
	struct {
		uint8_t src_addr[PROXY2_IP6_ADDR_SIZE];
		uint8_t dst_addr[PROXY2_IP6_ADDR_SIZE];
		uint16_t src_port;
		uint16_t dst_port;
	} ipv6_addr;
	struct {
		uint8_t src_addr[PROXY2_UNIX_ADDR_SIZE];
		uint8_t dst_addr[PROXY2_UNIX_ADDR_SIZE];
	} unix_addr;
};

/** Parsed result of the PROXY protocol */
struct proxy_result {
	enum proxy2_command command;  /**< Proxy command - PROXY or LOCAL. */
	int family;                   /**< Address family from netinet library (e.g. AF_INET6). */
	int protocol;                 /**< Protocol type from socket library (e.g. SOCK_STREAM). */
	union kr_sockaddr src_addr;   /**< Parsed source address and port. */
	union kr_sockaddr dst_addr;   /**< Parsed destination address and port. */
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
