/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <ngtcp2/ngtcp2.h>
#include "session2.h"

typedef enum {
	KNOT_QUIC_TABLE_CLIENT_ONLY = (1 << 0),
} kr_quic_table_flag_t;

typedef struct kr_quic_table {
	kr_quic_table_flag_t flags;
	/* general "settings" for connections */
	size_t size;
	size_t usage;
	size_t pointers;
	size_t max_conns;
	size_t udp_payload_limit;
	void (*log_cb)(const char *);
	const char *qlog_dir;
	uint64_t hash_secret[4];
	struct tls_credentials *creds;
	struct gnutls_priority_st *priority;
	struct heap *expiry_heap;
	struct kr_quic_cid *conns[];
} kr_quic_table_t;

typedef struct pl_quic_demux_sess_data {
	struct protolayer_data h;
	ngtcp2_settings settings;
	struct wire_buf outbuf;
	struct kr_quic_table *conn_table;
	uint64_t first_stream_id;
	struct kr_request *req;
} pl_quic_demux_sess_data_t;
