/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdint.h>

#include "lib/utils.h"

enum proxy2_command {
	PROXY2_CMD_LOCAL = 0x0,
	PROXY2_CMD_PROXY = 0x1
};

/** Parsed result of the PROXY protocol */
struct proxy_result {
	/** Proxy command - PROXY or LOCAL. */
	enum proxy2_command command;
	/** Address family from netinet library (e.g. AF_INET6). */
	int family;
	/** Protocol type from socket library (e.g. SOCK_STREAM). */
	int protocol;
	/** Parsed source address and port. */
	union kr_sockaddr src_addr;
	/** Parsed destination address and port. */
	union kr_sockaddr dst_addr;
	/** `true` = client has used TLS with the proxy. If TLS padding is
	 * enabled, it will be used even if the communication between kresd and
	 * the proxy is unencrypted. */
	bool has_tls : 1;
};

/** Initializes the protocol layers managed by the PROXYv2 "module". */
void proxy_protolayers_init(void);
