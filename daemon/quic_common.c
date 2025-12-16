/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <ngtcp2/ngtcp2.h>
#include "contrib/openbsd/siphash.h"
#include "libdnssec/random.h"

#include "quic_common.h"
#include "quic_conn.h"
#include "session2.h"
#include "network.h"

int quic_configuration_set(void)
{
	if (kr_fails_assert(the_network)) {
		return kr_error(EINVAL);
	}

	if (the_network->quic_params) {
		return kr_ok();
	}

	struct net_quic_params *quic_params = calloc(1, sizeof(*quic_params));
	if (quic_params == NULL) {
		return kr_error(ENOMEM);
	}

	the_network->quic_params = quic_params;
	/* Default values */
	the_network->quic_params->require_retry = false;
	the_network->quic_params->max_streams = 1024;
	the_network->quic_params->max_conns = 1024;
	return kr_ok();
}

int quic_configuration_free(struct net_quic_params *quic_params)
{
	if (quic_params == NULL){
		return kr_ok();
	}

	free(quic_params);

	return kr_ok();
}

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

uint64_t cid2hash(const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	SIPHASH_CTX ctx;
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)(table->hash_secret));
	SipHash24_Update(&ctx, cid->data, MIN(cid->datalen, 8));
	uint64_t ret = SipHash24_End(&ctx);

	return ret;
}

kr_quic_cid_t **kr_quic_table_lookup2(const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	kr_quic_cid_t **res = table->conns + (hash % table->size);
	while (*res != NULL && !ngtcp2_cid_eq(cid, (const ngtcp2_cid *)(*res)->cid_placeholder)) {
		res = &(*res)->next;
	}

	return res;
}

struct pl_quic_conn_sess_data *kr_quic_table_lookup(const ngtcp2_cid *cid, kr_quic_table_t *table)
{
	kr_quic_cid_t **pcid = kr_quic_table_lookup2(cid, table);
	return *pcid == NULL ? NULL : (*pcid)->conn_sess;
}

bool init_unique_cid(ngtcp2_cid *cid, size_t len, kr_quic_table_t *table)
{
	do {
		if (init_random_cid(cid, len), cid->datalen == 0)
			return false;

	} while (kr_quic_table_lookup(cid, table) != NULL);

	return true;
}

int write_retry_packet(struct wire_buf *dest, kr_quic_table_t *table,
		ngtcp2_version_cid *dec_cids,
		const struct sockaddr *src_addr,
		uint8_t *secret, size_t secret_len)
{
	ngtcp2_cid dcid;
	ngtcp2_cid scid;
	ngtcp2_cid new_dcid;

	ngtcp2_cid_init(&dcid, dec_cids->dcid, dec_cids->dcidlen);
	ngtcp2_cid_init(&scid, dec_cids->scid, dec_cids->scidlen);

	init_random_cid(&new_dcid, 0);
	if (!init_unique_cid(&new_dcid, 0, table)) {
		kr_log_debug(DOQ, "Failed to initialize unique cid for Retry packet\n");
		return -1;
	}

	uint8_t retry_token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2];
	uint64_t now = quic_timestamp();

	int ret = ngtcp2_crypto_generate_retry_token2(
		retry_token, (const uint8_t *)secret,
		secret_len, dec_cids->version,
		src_addr, kr_sockaddr_len(src_addr),
		&new_dcid, &dcid, now);

	if (ret < 0) {
		kr_log_debug(DOQ, "Failed to generate retry token\n");
		return ret;
	}

	ret = ngtcp2_crypto_write_retry(
		wire_buf_free_space(dest),
		wire_buf_free_space_length(dest),
		dec_cids->version, &scid,
		&new_dcid, &dcid,
		retry_token, ret
	);

	return ret;
}
