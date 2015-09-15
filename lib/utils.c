/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "ccan/isaac/isaac.h"
#include "lib/defines.h"
#include "lib/utils.h"
#include "lib/generic/array.h"
#include "lib/nsrep.h"

/* Logging & debugging */
bool _env_debug = false;

/** @internal CSPRNG context */
static isaac_ctx ISAAC;
static bool isaac_seeded = false;
#define SEED_SIZE 256

/*
 * Macros.
 */
#define strlen_safe(x) ((x) ? strlen(x) : 0)

/*
 * Cleanup callbacks.
 */
void _cleanup_free(char **p)
{
	free(*p);
}

void _cleanup_close(int *p)
{
	if (*p > 0) close(*p);
}

void _cleanup_fclose(FILE **p)
{
	if (*p) fclose(*p);
}

char* kr_strcatdup(unsigned n, ...)
{
	/* Calculate total length */
	size_t total_len = 0;
	va_list vl;
	va_start(vl, n);
	for (unsigned i = 0; i < n; ++i) {
		char *item = va_arg(vl, char *);
		total_len += strlen_safe(item);
	}
	va_end(vl);

	/* Allocate result and fill */
	char *result = NULL;
	if (total_len > 0) {
		result = malloc(total_len + 1);
	}
	if (result) {
		char *stream = result;
		va_start(vl, n);
		for (unsigned i = 0; i < n; ++i) {
			char *item = va_arg(vl, char *);
			if (item) {
				size_t len = strlen(item);
				memcpy(stream, item, len + 1);
				stream += len;
			}
		}
		va_end(vl);
	}

	return result;
}

static int seed_file(FILE *fp, char *buf, size_t buflen)
{
	if (!fp) {
		return -1;
	}
	/* Read whole buffer even if interrupted */
	ssize_t readb = 0;
	while (!ferror(fp) && readb < buflen) {
		readb += fread(buf, 1, buflen - readb, fp);
	}
	return 0;
}

static int randseed(char *buf, size_t buflen)
{
    /* This is adapted from Tor's crypto_seed_rng() */
    static const char *filenames[] = {
        "/dev/srandom", "/dev/urandom", "/dev/random", NULL
    };
    for (unsigned i = 0; filenames[i]; ++i) {
        auto_fclose FILE *fp = fopen(filenames[i], "r");
        if (seed_file(fp, buf, buflen) == 0) {
            return 0;
        }
    }

    /* Seed from time, this is not going to be secure. */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    memcpy(buf, &tv, buflen < sizeof(tv) ? buflen : sizeof(tv));
    return 0;
}

int kr_rand_reseed(void)
{
	uint8_t seed[SEED_SIZE];
	randseed((char *)seed, sizeof(seed));
	isaac_reseed(&ISAAC, seed, sizeof(seed));
	return kr_ok();
}

unsigned kr_rand_uint(unsigned max)
{
	if (!isaac_seeded) {
		kr_rand_reseed();
		isaac_seeded = true;
	}
	return isaac_next_uint(&ISAAC, max);
}

int mm_reserve(void *baton, char **mem, size_t elm_size, size_t want, size_t *have)
{
    if (*have >= want) {
        return 0;
    } else {
        mm_ctx_t *pool = baton;
        size_t next_size = array_next_count(want);
        void *mem_new = mm_alloc(pool, next_size * elm_size);
        if (mem_new != NULL) {
            memcpy(mem_new, *mem, (*have)*(elm_size));
            mm_free(pool, *mem);
            *mem = mem_new;
            *have = next_size;
            return 0;
        }
    }
    return -1;
}

int kr_pkt_put(knot_pkt_t *pkt, const knot_dname_t *name, uint32_t ttl,
               uint16_t rclass, uint16_t rtype, const uint8_t *rdata, uint16_t rdlen)
{
	if (!pkt || !name)  {
		return kr_error(EINVAL);
	}
	/* Create empty RR */
	knot_rrset_t rr;
	knot_rrset_init(&rr, knot_dname_copy(name, &pkt->mm), rtype, rclass);
	/* Create RDATA */
	knot_rdata_t rdata_arr[knot_rdata_array_size(rdlen)];
	knot_rdata_init(rdata_arr, rdlen, rdata, ttl);
	knot_rdataset_add(&rr.rrs, rdata_arr, &pkt->mm);
	/* Append RR */
	return knot_pkt_put(pkt, 0, &rr, KNOT_PF_FREE);
}

const char *kr_inaddr(const struct sockaddr *addr)
{
	if (!addr) {
		return NULL;
	}
	switch (addr->sa_family) {
	case AF_INET:  return (const char *)&(((const struct sockaddr_in *)addr)->sin_addr);
	case AF_INET6: return (const char *)&(((const struct sockaddr_in6 *)addr)->sin6_addr);
	default:       return NULL;
	}
}

int kr_inaddr_len(const struct sockaddr *addr)
{
	if (!addr) {
		return kr_error(EINVAL);
	}
	return addr->sa_family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
}

int kr_straddr_family(const char *addr)
{
	if (!addr) {
		return kr_error(EINVAL);
	}
	if (strchr(addr, ':')) {
		return AF_INET6;
	}
	return AF_INET;
}

int kr_straddr_subnet(void *dst, const char *addr)
{
	if (!dst || !addr) {
		return kr_error(EINVAL);
	}
	/* Parse subnet */
	int bit_len = 0;
	int family = kr_straddr_family(addr);
	auto_free char *addr_str = strdup(addr);
	char *subnet = strchr(addr_str, '/');
	if (subnet) {
		*subnet = '\0';
		subnet += 1;
		bit_len = atoi(subnet);
		/* Check client subnet length */
		const int max_len = (family == AF_INET6) ? 128 : 32;
		if (bit_len < 0 || bit_len > max_len) {
			return kr_error(ERANGE);
		}
	}
	/* Parse address */
	int ret = inet_pton(family, addr_str, dst);
	if (ret < 0) {
		return kr_error(EILSEQ);
	}

	return bit_len;
}

int kr_bitcmp(const char *a, const char *b, int bits)
{
	if (!a || !b || bits == 0) {
		return kr_error(ENOMEM);
	}
	/* Compare part byte-divisible part. */
	const size_t chunk = bits / 8;
	int ret = memcmp(a, b, chunk);
	if (ret != 0) {
		return ret;
	}
	a += chunk;
	b += chunk;
	bits -= chunk * 8;
	/* Compare last partial byte address block. */
	if (bits > 0) {
		const size_t shift = (8 - bits);
		ret = ((uint8_t)(*a >> shift) - (uint8_t)(*b >> shift));
	}
	return ret;
}