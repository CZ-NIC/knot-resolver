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

#include <arpa/inet.h> /* inet_ntop() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "contrib/fnv/fnv.h"
#include "lib/cookies/alg_clnt.h"

//#define CC_HASH_USE_CLIENT_ADDRESS /* When defined, client address will be used when generating client cookie. */

/**
 * Compute client cookie using FNV-64.
 * @note At least one of the arguments must be non-null.
 * @param input  Input parameters.
 * @param cc_out Buffer for computed client cookie.
 * @return kr_ok() on success, error code else.
 */
static int kr_clnt_cookie_alg_fnv64(const struct kr_clnt_cookie_input *input,
                                    uint8_t cc_out[KNOT_OPT_COOKIE_CLNT])
{
	if (!input || !cc_out) {
		return kr_error(EINVAL);
	}

	if ((!input->clnt_sockaddr && !input->srvr_sockaddr) ||
	    !(input->secret_data && input->secret_len)) {
		return kr_error(EINVAL);
	}

	const uint8_t *addr = NULL;
	size_t alen = 0; /* Address length. */

	Fnv64_t hash_val = FNV1A_64_INIT;

#if defined(CC_HASH_USE_CLIENT_ADDRESS)
	if (input->clnt_sockaddr) {
		if (kr_ok() == kr_address_bytes(input->clnt_sockaddr, &addr,
		                                &alen)) {
			assert(addr && alen);
			hash_val = fnv_64a_buf(addr, alen, hash_val);
		}
	}
#endif /* defined(CC_HASH_USE_CLIENT_ADDRESS) */

	if (input->srvr_sockaddr) {
		if (kr_ok() == kr_address_bytes(input->srvr_sockaddr, &addr,
		                                &alen)) {
			assert(addr && alen);
			hash_val = fnv_64a_buf((void *) addr, alen, hash_val);
		}
	}

	hash_val = fnv_64a_buf((void *) input->secret_data, input->secret_len,
	                       hash_val);

	assert(KNOT_OPT_COOKIE_CLNT == sizeof(hash_val));

	memcpy(cc_out, &hash_val, KNOT_OPT_COOKIE_CLNT);

	return kr_ok();
}

/**
 * Compute client cookie using HMAC_SHA256-64.
 * @note At least one of the arguments must be non-null.
 * @param input  Input parameters.
 * @param cc_out Buffer for computed client cookie.
 * @return kr_ok() on success, error code else.
 */
static int kr_clnt_cookie_alg_hmac_sha256_64(const struct kr_clnt_cookie_input *input,
                                             uint8_t cc_out[KNOT_OPT_COOKIE_CLNT])
{
	if (!input || !cc_out) {
		return kr_error(EINVAL);
	}

	if ((!input->clnt_sockaddr && !input->srvr_sockaddr) ||
	    !(input->secret_data && input->secret_len)) {
		return kr_error(EINVAL);
	}

	const uint8_t *addr = NULL;
	size_t alen = 0; /* Address length. */

	uint8_t digest[SHA256_DIGEST_LENGTH];
	unsigned int digest_len = SHA256_DIGEST_LENGTH;

	/* text: (client IP | server IP)
	 * key: client secret */

	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);

	int ret = HMAC_Init_ex(&ctx, input->secret_data, input->secret_len,
	                       EVP_sha256(), NULL);
	if (ret != 1) {
		ret = kr_error(EINVAL);
		goto fail;
	}

#if defined(CC_HASH_USE_CLIENT_ADDRESS)
	if (input->clnt_sockaddr) {
		if (kr_ok() == kr_address_bytes(input->clnt_sockaddr, &addr,
		                                &alen)) {
			assert(addr && alen);
			ret = HMAC_Update(&ctx, addr, alen);
			if (ret != 1) {
				ret = kr_error(EINVAL);
				goto fail;
			}
		}
	}
#endif /* defined(CC_HASH_USE_CLIENT_ADDRESS) */

	if (input->srvr_sockaddr) {
		if (kr_ok() == kr_address_bytes(input->srvr_sockaddr, &addr,
		                                &alen)) {
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

	assert(KNOT_OPT_COOKIE_CLNT <= SHA256_DIGEST_LENGTH);

	memcpy(cc_out, digest, KNOT_OPT_COOKIE_CLNT);
	ret = kr_ok();

fail:
	HMAC_CTX_cleanup(&ctx);
	return ret;
}

const struct kr_clnt_cookie_alg_descr kr_clnt_cookie_algs[] = {
	{ "FNV-64",         kr_clnt_cookie_alg_fnv64 },
	{ "HMAC-SHA256-64", kr_clnt_cookie_alg_hmac_sha256_64 },
	{ NULL, NULL }
};

const struct kr_clnt_cookie_alg_descr *kr_clnt_cookie_alg(const struct kr_clnt_cookie_alg_descr cc_algs[],
                                                          const char *name)
{
	if (!cc_algs || !name) {
		return NULL;
	}

	const struct kr_clnt_cookie_alg_descr *aux_ptr = cc_algs;
	while (aux_ptr && aux_ptr->func) {
		assert(aux_ptr->name);
		if (strcmp(aux_ptr->name, name) == 0) {
			return aux_ptr;
		}
		++aux_ptr;
	}

	return NULL;
}

int kr_address_bytes(const void *sockaddr, const uint8_t **addr, size_t *len)
{
	if (!sockaddr || !addr || !len) {
		return kr_error(EINVAL);
	}

	int addr_family = ((struct sockaddr *) sockaddr)->sa_family;

	switch (addr_family) {
	case AF_INET:
		*addr = (uint8_t *) &((struct sockaddr_in *) sockaddr)->sin_addr;
		*len = 4;
		break;
	case AF_INET6:
		*addr = (uint8_t *) &((struct sockaddr_in6 *) sockaddr)->sin6_addr;
		*len = 16;
		break;
	default:
		*addr = NULL;
		*len = 0;
		addr_family = AF_UNSPEC;
		return kr_error(EINVAL);
		break;
	}

	return kr_ok();
}

int kr_clnt_cookie_check(const uint8_t cc[KNOT_OPT_COOKIE_CLNT],
                         const struct kr_clnt_cookie_input *input,
                         const struct kr_clnt_cookie_alg_descr *cc_alg)
{
	if (!cc || !input || !cc_alg || !cc_alg->func) {
		return kr_error(EINVAL);
	}

	uint8_t generated_cc[KNOT_OPT_COOKIE_CLNT] = {0, };

	int ret = cc_alg->func(input, generated_cc);
	if (ret != kr_ok()) {
		return ret;
	}

	ret = memcmp(cc, generated_cc, KNOT_OPT_COOKIE_CLNT);
	if (ret == 0) {
		return kr_ok();
	}

	return kr_error(EINVAL);
}
