/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "quic_common.h"
#include "libdnssec/random.h"
#include "session2.h"
#include <ngtcp2/ngtcp2.h>

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

ssize_t send_version_negotiation(struct wire_buf *dest, ngtcp2_version_cid dec_cids,
		ngtcp2_cid dcid, ngtcp2_cid scid)
{
	uint8_t rnd = 0;
	dnssec_random_buffer(&rnd, sizeof(rnd));
	uint32_t supported_quic[1] = { NGTCP2_PROTO_VER_V1 };
	int ret = ngtcp2_pkt_write_version_negotiation(
		wire_buf_free_space(dest),
		wire_buf_free_space_length(dest),
		rnd, dec_cids.scid, dec_cids.scidlen,
		dec_cids.dcid, dec_cids.dcidlen, supported_quic,
		sizeof(supported_quic) / sizeof(*supported_quic)
	);

	return ret;
}
