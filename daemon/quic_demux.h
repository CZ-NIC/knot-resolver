/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <ngtcp2/ngtcp2.h>
#include "session2.h"

typedef struct pl_quic_demux_sess_data {
	struct protolayer_data h;
	ngtcp2_settings settings;
	struct kr_quic_table *conn_table;
	uint64_t first_stream_id;
	struct kr_request *req;
} pl_quic_demux_sess_data_t;
