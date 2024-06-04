/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/proto.h"

const char *kr_proto_name(enum kr_proto p)
{
	switch (p) {
	case KR_PROTO_INTERNAL:
		return "INTERNAL";
#define XX(cid, vid, name) case KR_PROTO_##cid: \
		return (name);
	KR_PROTO_MAP(XX)
#undef XX
	default:
		return "(default)";
	}
}
