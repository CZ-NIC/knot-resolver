/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h> /* ntohl(), ... */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "contrib/fnv/fnv.h"
#include "lib/cookies/alg_clnt.h" /* kr_address_bytes() */
#include "lib/cookies/alg_srvr.h"

/**
 * @brief Server cookie contains only hash value.
 * @note DNS Cookies -- Appendix B.1
 */
static int srvr_cookie_parse_simple(const uint8_t *sc, uint16_t sc_len,
                                    struct kr_srvr_cookie_inbound *inbound)
{
	if (!sc || !sc_len || !inbound) {
		return kr_error(EINVAL);
	}

	//memset(inbound, 0, sizeof(*inbound));
	inbound->hash_data = sc; /* Entire server cookie contains data. */
	inbound->hash_len = sc_len;

	return kr_ok();
}

/**
 * @brief Server cookie contains also additional values.
 * @note DNS Cookies -- Appendix B.2
 */
static int srvr_cookie_parse(const uint8_t *sc, uint16_t sc_len,
                             struct kr_srvr_cookie_inbound *inbound)
{
	if (!sc || !sc_len || !inbound) {
		return kr_error(EINVAL);
	}

	if (sc_len <= (2 * sizeof(uint32_t))) { /* nonce + time */
		return kr_error(EINVAL);
	}

	uint32_t aux;

	memcpy(&aux, sc, sizeof(aux));
	inbound->nonce = ntohl(aux);
	memcpy(&aux, sc + sizeof(aux), sizeof(aux));
	inbound->time = ntohl(aux);
	inbound->hash_data = sc + (2 * sizeof(aux));
	inbound->hash_len = sc_len - (2 * sizeof(aux));

	return kr_ok();
}

#define SRVR_FNV64_SIMPLE_HASH_SIZE 8

/**
 * @brief Compute server cookie using FNV-64 (hash only).
 * @note Server cookie = FNV-64( client IP | client cookie | server secret )
 */
static int kr_srvr_cookie_alg_fnv64_simple(const struct kr_srvr_cookie_input *input,
                                           uint8_t sc_out[KNOT_OPT_COOKIE_SRVR_MAX],
                                           size_t *sc_size)
{
	if (!input || !sc_out ||
	    !sc_size || (*sc_size < SRVR_FNV64_SIMPLE_HASH_SIZE)) {
		return kr_error(EINVAL);
	}

	if (!input->clnt_cookie || !input->srvr_data ||
	    !input->srvr_data->secret_data || !input->srvr_data->secret_len) {
		return kr_error(EINVAL);
	}

	const uint8_t *addr = NULL;
	size_t alen = 0; /* Address length. */

	Fnv64_t hash_val = FNV1A_64_INIT;

	if (kr_ok() == kr_address_bytes(input->srvr_data->clnt_sockaddr, &addr,
	                                &alen)) {
		assert(addr && alen);
		hash_val = fnv_64a_buf((void *) addr, alen, hash_val);
	}

	hash_val = fnv_64a_buf((void *) input->clnt_cookie,
	                       KNOT_OPT_COOKIE_CLNT, hash_val);

	hash_val = fnv_64a_buf((void *) input->srvr_data->secret_data,
	                       input->srvr_data->secret_len, hash_val);

	memcpy(sc_out, &hash_val, sizeof(hash_val));
	*sc_size = sizeof(hash_val);
	assert(SRVR_FNV64_SIMPLE_HASH_SIZE == *sc_size);

	return kr_ok();
}

#define SRVR_FNV64_SIZE 16

/**
 * @brief Compute server cookie using FNV-64.
 * @note Server cookie = nonce | time | FNV-64( client IP | nonce| time | client cookie | server secret )
 */
static int kr_srvr_cookie_alg_fnv64(const struct kr_srvr_cookie_input *input,
                                    uint8_t sc_out[KNOT_OPT_COOKIE_SRVR_MAX],
                                    size_t *sc_size)
{
	if (!input || !sc_out ||
	    !sc_size || (*sc_size < SRVR_FNV64_SIMPLE_HASH_SIZE)) {
		return kr_error(EINVAL);
	}

	if (!input->clnt_cookie || !input->srvr_data ||
	    !input->srvr_data->secret_data || !input->srvr_data->secret_len) {
		return kr_error(EINVAL);
	}

	const uint8_t *addr = NULL;
	size_t alen = 0; /* Address length. */

	Fnv64_t hash_val = FNV1A_64_INIT;

	if (input->srvr_data->clnt_sockaddr) {
		if (kr_ok() == kr_address_bytes(input->srvr_data->clnt_sockaddr,
		                                &addr, &alen)) {
			assert(addr && alen);
			hash_val = fnv_64a_buf((void *) addr, alen, hash_val);
		}
	}

	hash_val = fnv_64a_buf((void *) &input->nonce, sizeof(input->nonce),
	                       hash_val);

	hash_val = fnv_64a_buf((void *) &input->time, sizeof(input->time),
	                       hash_val);

	hash_val = fnv_64a_buf((void *) input->clnt_cookie,
	                       KNOT_OPT_COOKIE_CLNT, hash_val);

	hash_val = fnv_64a_buf((void *) input->srvr_data->secret_data,
	                       input->srvr_data->secret_len, hash_val);

	uint32_t aux = htonl(input->nonce);
	memcpy(sc_out, &aux, sizeof(aux));
	aux = htonl(input->time);
	memcpy(sc_out + sizeof(aux), &aux, sizeof(aux));

	memcpy(sc_out + (2 * sizeof(aux)), &hash_val, sizeof(hash_val));
	*sc_size = (2 * sizeof(aux)) + sizeof(hash_val);
	assert(SRVR_FNV64_SIZE == *sc_size);

	return kr_ok();
}

#define SRVR_HMAC_SHA256_64_SIMPLE_HASH_SIZE 8

/**
 * @brief Compute server cookie using HMAC-SHA256-64 (hash only).
 * @note Server cookie = HMAC-SHA256-64( server secret, client cookie | client IP )
 */
static int kr_srvr_cookie_alg_hmac_sha256_64_simple(const struct kr_srvr_cookie_input *input,
                                                    uint8_t sc_out[KNOT_OPT_COOKIE_SRVR_MAX],
                                                    size_t *sc_size)
{
	if (!input || !sc_out ||
	    !sc_size || (*sc_size < SRVR_FNV64_SIMPLE_HASH_SIZE)) {
		return kr_error(EINVAL);
	}

	if (!input->clnt_cookie || !input->srvr_data ||
	    !input->srvr_data->secret_data || !input->srvr_data->secret_len) {
		return kr_error(EINVAL);
	}

	const uint8_t *addr = NULL;
	size_t alen = 0; /* Address length. */

	uint8_t digest[SHA256_DIGEST_LENGTH];
	unsigned int digest_len = SHA256_DIGEST_LENGTH;

	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);

	int ret = HMAC_Init_ex(&ctx, input->srvr_data->secret_data,
	                       input->srvr_data->secret_len,
	                       EVP_sha256(), NULL);
	if (ret != 1) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	ret = HMAC_Update(&ctx, input->clnt_cookie, KNOT_OPT_COOKIE_CLNT);
	if (ret != 1) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	if (input->srvr_data->clnt_sockaddr) {
		if (kr_ok() == kr_address_bytes(input->srvr_data->clnt_sockaddr,
		                                &addr, &alen)) {
			assert(addr && alen);
			ret = HMAC_Update(&ctx, addr, alen);
			if (ret != 1) {
				ret = kr_error(EINVAL);
				goto fail;
			}
		}
	}

	if (1 != HMAC_Final(&ctx, digest, &digest_len)) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	assert(SRVR_HMAC_SHA256_64_SIMPLE_HASH_SIZE <= SHA256_DIGEST_LENGTH);

	memcpy(sc_out, digest, SRVR_HMAC_SHA256_64_SIMPLE_HASH_SIZE);
	*sc_size = SRVR_HMAC_SHA256_64_SIMPLE_HASH_SIZE;

	ret = kr_ok();

fail:
	HMAC_CTX_cleanup(&ctx);
	return ret;
}

#define SRVR_HMAC_SHA256_64_SIZE 16

/**
 * @brief Compute server cookie using HMAC-SHA256-64).
 * @note Server cookie = nonce | time | HMAC-SHA256-64( server secret, client cookie | nonce| time | client IP )
 */
static int kr_srvr_cookie_alg_hmac_sha256_64(const struct kr_srvr_cookie_input *input,
                                             uint8_t sc_out[KNOT_OPT_COOKIE_SRVR_MAX],
                                             size_t *sc_size)
{
	if (!input || !sc_out ||
	    !sc_size || (*sc_size < SRVR_FNV64_SIMPLE_HASH_SIZE)) {
		return kr_error(EINVAL);
	}

	if (!input->clnt_cookie || !input->srvr_data ||
	    !input->srvr_data->secret_data || !input->srvr_data->secret_len) {
		return kr_error(EINVAL);
	}

	const uint8_t *addr = NULL;
	size_t alen = 0; /* Address length. */

	uint8_t digest[SHA256_DIGEST_LENGTH];
	unsigned int digest_len = SHA256_DIGEST_LENGTH;

	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);

	int ret = HMAC_Init_ex(&ctx, input->srvr_data->secret_data,
	                       input->srvr_data->secret_len,
	                       EVP_sha256(), NULL);
	if (ret != 1) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	ret = HMAC_Update(&ctx, input->clnt_cookie, KNOT_OPT_COOKIE_CLNT);
	if (ret != 1) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	ret = HMAC_Update(&ctx, (void *) &input->nonce, sizeof(input->nonce));
	if (ret != 1) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	ret = HMAC_Update(&ctx, (void *) &input->time, sizeof(input->time));
	if (ret != 1) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	if (input->srvr_data->clnt_sockaddr) {
		if (kr_ok() == kr_address_bytes(input->srvr_data->clnt_sockaddr,
		                                &addr, &alen)) {
			assert(addr && alen);
			ret = HMAC_Update(&ctx, addr, alen);
			if (ret != 1) {
				ret = kr_error(EINVAL);
				goto fail;
			}
		}
	}

	if (1 != HMAC_Final(&ctx, digest, &digest_len)) {
		ret = kr_error(EINVAL);
		goto fail;
	}

	uint32_t aux = htonl(input->nonce);
	memcpy(sc_out, &aux, sizeof(aux));
	aux = htonl(input->time);
	memcpy(sc_out + sizeof(aux), &aux, sizeof(aux));

	assert(SRVR_HMAC_SHA256_64_SIMPLE_HASH_SIZE <= SHA256_DIGEST_LENGTH);

	memcpy(sc_out + (2 * sizeof(aux)), digest,
	       SRVR_HMAC_SHA256_64_SIMPLE_HASH_SIZE);
	*sc_size = (2 * sizeof(aux)) + SRVR_HMAC_SHA256_64_SIMPLE_HASH_SIZE;
	assert(SRVR_HMAC_SHA256_64_SIZE == *sc_size);

	ret = kr_ok();

fail:
	HMAC_CTX_cleanup(&ctx);
	return ret;
}

const struct kr_srvr_cookie_alg_descr kr_srvr_cookie_algs[] = {
	{ "FNV-64-SIMPLE", SRVR_FNV64_SIMPLE_HASH_SIZE, srvr_cookie_parse_simple, kr_srvr_cookie_alg_fnv64_simple },
	{ "FNV-64", SRVR_FNV64_SIZE, srvr_cookie_parse, kr_srvr_cookie_alg_fnv64 },
	{ "HMAC-SHA256-64-SIMPLE", SRVR_HMAC_SHA256_64_SIMPLE_HASH_SIZE, srvr_cookie_parse_simple, kr_srvr_cookie_alg_hmac_sha256_64_simple },
	{ "HMAC-SHA256-64", SRVR_HMAC_SHA256_64_SIZE, srvr_cookie_parse, kr_srvr_cookie_alg_hmac_sha256_64 },
	{ NULL, 0, NULL, NULL }
};

const struct kr_srvr_cookie_alg_descr *kr_srvr_cookie_alg(const struct kr_srvr_cookie_alg_descr sc_algs[],
                                                          const char *name)
{
	if (!sc_algs || !name) {
		return NULL;
	}

	const struct kr_srvr_cookie_alg_descr *aux_ptr = sc_algs;
	while (aux_ptr && aux_ptr->gen_func) {
		assert(aux_ptr->name);
		if (strcmp(aux_ptr->name, name) == 0) {
			return aux_ptr;
		}
		++aux_ptr;
	}

	return NULL;
}

int kr_srvr_cookie_check(const uint8_t cc[KNOT_OPT_COOKIE_CLNT],
                         const uint8_t *sc, uint16_t sc_len,
                         const struct kr_srvr_cookie_check_ctx *check_ctx,
                         const struct kr_srvr_cookie_alg_descr *sc_alg)
{
	if (!cc || !sc || !sc_len || !check_ctx || !sc_alg) {
		return kr_error(EINVAL);
	}

	if (!check_ctx->clnt_sockaddr ||
	    !check_ctx->secret_data || !check_ctx->secret_len) {
		return kr_error(EINVAL);
	}

	if (!sc_alg->srvr_cookie_size ||
	    !sc_alg->opt_parse_func || !sc_alg->gen_func) {
		return kr_error(EINVAL);
	}

	if (sc_len != sc_alg->srvr_cookie_size) {
		/* Cookie size does to match. */
		return kr_error(EBADMSG);
	}

	struct kr_srvr_cookie_inbound inbound_sc = { 0, };

	/* Obtain data from received server cookie. */
	int ret = sc_alg->opt_parse_func(sc, sc_len, &inbound_sc);
	if (ret != kr_ok()) {
		return ret;
	}

	uint8_t generated_sc[KNOT_OPT_COOKIE_SRVR_MAX] = { 0, };
	size_t generated_sc_len = KNOT_OPT_COOKIE_SRVR_MAX;
	struct kr_srvr_cookie_input sc_input = {
		.clnt_cookie = cc,
		.nonce = inbound_sc.nonce,
		.time = inbound_sc.time,
		.srvr_data = check_ctx
	};

	/* Generate a new server cookie. */
	ret = sc_alg->gen_func(&sc_input, generated_sc, &generated_sc_len);
	if (ret != kr_ok()) {
		return ret;
	}
	assert(generated_sc_len == sc_alg->srvr_cookie_size);

	ret = (memcmp(sc, generated_sc, generated_sc_len) == 0) ?
	       kr_ok() : kr_error(EBADMSG);

	return ret;
}
