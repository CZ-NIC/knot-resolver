/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "quic_common.h"
#include "libdnssec/random.h"
#include "session2.h"

uint64_t quic_timestamp(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;

	return ((uint64_t)ts.tv_sec * NGTCP2_SECONDS) + (uint64_t)ts.tv_nsec;
}

bool kr_quic_conn_timeout(struct pl_quic_conn_sess_data *conn, uint64_t *now)
{
	if (!conn || !conn->conn)
		return false;

	if (*now == 0) {
		*now = quic_timestamp();
	}
	return *now > ngtcp2_conn_get_expiry(conn->conn);
}

void init_random_cid(ngtcp2_cid *cid, size_t len)
{
	if (len == 0)
		len = SERVER_DEFAULT_SCIDLEN;

	cid->datalen = dnssec_random_buffer(cid->data, len) ==
		/* DNSSEC_EOK */0 ? len : 0;
}

void quic_event_close_connection(struct pl_quic_conn_sess_data *conn,
		struct session2 *session)
{
	if (!session || !conn)
		return;

	while (session->transport.type != SESSION2_TRANSPORT_IO) {
		session = session->transport.parent;
	}

	session2_event(session, PROTOLAYER_EVENT_DISCONNECT, conn);
}

