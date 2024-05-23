/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <stdint.h>

#include "lib/defines.h"

/** DNS transport protocol map
 *
 * This macro is used to generate `enum kr_proto` as well as other additional
 * data on protocols, like name string constants.
 *
 * It defines DNS transport protocols for use by `session2` (to define sequences
 * of protocol layers) and `rules` (to filter requests based on them). To find
 * out more, see the individual usages.
 *
 * Parameters for XX are:
 *   1. Constant name (for e.g. KR_PROTO_* enum value identifiers)
 *   2. Variable name (for e.g. kr_proto_* array identifiers, like those defined
 *      in `session2.c`)
 *   3. Human-readable name for logging */
#define KR_PROTO_MAP(XX) \
    XX(UDP53, udp53, "DNS UDP") \
    XX(TCP53, tcp53, "DNS TCP") \
    XX(DOT, dot, "DNS-over-TLS") \
    XX(DOH, doh, "DNS-over-HTTPS") \
    XX(DOH_INSECURE, doh_insecure, "Insecure DNS-over-HTTP") \
    XX(DOQ, doq, "DNS-over-QUIC") /* unused for now */ \
    //

/** DNS protocol set - mutually exclusive options, contrary to
 * kr_request_qsource_flags
 *
 * The XDP flag is not discerned here, as it could apply to any protocol. (Not
 * right now, but libknot does support it for TCP, so that would complete
 * everything)
 */
enum kr_proto {
	KR_PROTO_INTERNAL = 0, /// no protocol, e.g. useful to mark internal requests
#define XX(cid, vid, name) KR_PROTO_ ## cid,
	KR_PROTO_MAP(XX)
#undef XX
	KR_PROTO_COUNT,
};

/** Gets the constant string name of the specified transport protocol. */
KR_EXPORT
const char *kr_proto_name(enum kr_proto p);

/** Bitmap of enum kr_proto options. */
typedef uint8_t kr_proto_set;
static_assert(sizeof(kr_proto_set) * 8 >= KR_PROTO_COUNT, "bad combination of type sizes");
