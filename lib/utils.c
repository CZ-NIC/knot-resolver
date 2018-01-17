/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <contrib/cleanup.h>
#include <ccan/isaac/isaac.h>
#include <gnutls/gnutls.h>
#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/rrtype/rrsig.h>
#include <libknot/rrset-dump.h>
#include <libknot/version.h>
#include <uv.h>

#include "lib/defines.h"
#include "lib/utils.h"
#include "lib/generic/array.h"
#include "lib/nsrep.h"
#include "lib/module.h"
#include "lib/resolve.h"


/* Always compile-in log symbols, even if disabled. */
#undef kr_verbose_status
#undef kr_verbose_set
#undef kr_log_verbose

/* Logging & debugging */
bool kr_verbose_status = false;

/** @internal CSPRNG context */
static isaac_ctx ISAAC;
static bool isaac_seeded = false;
#define SEED_SIZE 256

/*
 * Macros.
 */
#define strlen_safe(x) ((x) ? strlen(x) : 0)

/**
 * @internal Convert 16bit unsigned to string, keeps leading spaces.
 * @note Always fills dst length = 5
 * Credit: http://computer-programming-forum.com/46-asm/7aa4b50bce8dd985.htm
 */
static inline int u16tostr(uint8_t *dst, uint16_t num)
{
	uint32_t tmp = num * (((1 << 28) / 10000) + 1) - (num / 4);
	for(size_t i = 0; i < 5; i++) {
		dst[i] = '0' + (char) (tmp >> 28);
		tmp = (tmp & 0x0fffffff) * 10;
	}
	return 5;
}

/*
 * Cleanup callbacks.
 */

static void kres_gnutls_log(int level, const char *message)
{
	kr_log_verbose("[gnutls] (%d) %s", level, message);
}

bool kr_verbose_set(bool status)
{
#ifndef NOVERBOSELOG
	kr_verbose_status = status;

	/* gnutls logs messages related to our TLS and also libdnssec,
	 * and the logging is set up in a global way only */
	if (status) {
		gnutls_global_set_log_function(kres_gnutls_log);
	}
	gnutls_global_set_log_level(status ? 5 : 0);
#endif
	return kr_verbose_status;
}

void kr_log_verbose(const char *fmt, ...)
{
	if (kr_verbose_status) {
		va_list args;
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		fflush(stdout);
	}
}

char* kr_strcatdup(unsigned n, ...)
{
	if (n < 1) {
		return NULL;
	}

	/* Calculate total length */
	size_t total_len = 0;
	va_list vl;
	va_start(vl, n);
	for (unsigned i = 0; i < n; ++i) {
		char *item = va_arg(vl, char *);
		const size_t new_len = total_len + strlen_safe(item);
		if (unlikely(new_len < total_len)) return NULL;
		total_len = new_len;
	}
	va_end(vl);

	/* Allocate result and fill */
	char *result = NULL;
	if (total_len > 0) {
		if (unlikely(total_len + 1 == 0)) return NULL;
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

static int seed_file(const char *fname, char *buf, size_t buflen)
{
	auto_fclose FILE *fp = fopen(fname, "r");
	if (!fp) {
		return kr_error(EINVAL);
	}
	/* Disable buffering to conserve randomness but ignore failing to do so. */
	setvbuf(fp, NULL, _IONBF, 0);
	do {
		if (feof(fp)) {
			return kr_error(ENOENT);
		}
		if (ferror(fp)) {
			return kr_error(ferror(fp));
		}
		if (fread(buf, buflen, 1, fp) == 1) { /* read in one chunk for simplicity */
			return kr_ok();
		}
	} while (true);
	return 0;
}

static int randseed(char *buf, size_t buflen)
{
    /* This is adapted from Tor's crypto_seed_rng() */
    static const char *filenames[] = {
        "/dev/srandom", "/dev/urandom", "/dev/random", NULL
    };
    for (unsigned i = 0; filenames[i]; ++i) {
        if (seed_file(filenames[i], buf, buflen) == 0) {
            return 0;
        }
    }

    /* Seed from time, this is not going to be secure. */
    kr_log_error("failed to obtain randomness, falling back to current time\n");
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

uint32_t kr_rand_uint(uint32_t max)
{
	if (unlikely(!isaac_seeded)) {
		kr_rand_reseed();
		isaac_seeded = true;
	}
	return max == 0
		? isaac_next_uint32(&ISAAC)
		: isaac_next_uint(&ISAAC, max);
}

int kr_memreserve(void *baton, char **mem, size_t elm_size, size_t want, size_t *have)
{
    if (*have >= want) {
        return 0;
    } else {
        knot_mm_t *pool = baton;
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

int kr_pkt_recycle(knot_pkt_t *pkt)
{
	pkt->rrset_count = 0;
	pkt->size = KNOT_WIRE_HEADER_SIZE;
	pkt->current = KNOT_ANSWER;
	knot_wire_set_qdcount(pkt->wire, 0);
	knot_wire_set_ancount(pkt->wire, 0);
	knot_wire_set_nscount(pkt->wire, 0);
	knot_wire_set_arcount(pkt->wire, 0);
	memset(pkt->sections, 0, sizeof(pkt->sections));
	knot_pkt_begin(pkt, KNOT_ANSWER);
	return knot_pkt_parse_question(pkt);
}

int kr_pkt_clear_payload(knot_pkt_t *pkt)
{
	pkt->rrset_count = 0;
	pkt->size = KNOT_WIRE_HEADER_SIZE + pkt->qname_size +
		    2 * sizeof(uint16_t); /* QTYPE + QCLASS */
	pkt->parsed = KNOT_WIRE_HEADER_SIZE;
	pkt->current = KNOT_ANSWER;
	knot_wire_set_ancount(pkt->wire, 0);
	knot_wire_set_nscount(pkt->wire, 0);
	knot_wire_set_arcount(pkt->wire, 0);
	memset(&pkt->sections[KNOT_ANSWER], 0, sizeof(knot_pktsection_t) *
	       (KNOT_PKT_SECTIONS - (KNOT_ANSWER + 1)));
	knot_pkt_begin(pkt, KNOT_ANSWER);
	return knot_pkt_parse_question(pkt);
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
	/* Create RDATA
	 * @warning _NOT_ thread safe.
	 */
	static knot_rdata_t rdata_arr[RDATA_ARR_MAX];
	knot_rdata_init(rdata_arr, rdlen, rdata, ttl);
	knot_rdataset_add(&rr.rrs, rdata_arr, &pkt->mm);
	/* Append RR */
	return knot_pkt_put(pkt, 0, &rr, KNOT_PF_FREE);
}

void kr_pkt_make_auth_header(knot_pkt_t *pkt)
{
	assert(pkt && pkt->wire);
	knot_wire_clear_ad(pkt->wire);
	knot_wire_set_aa(pkt->wire);
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

int kr_inaddr_family(const struct sockaddr *addr)
{
	if (!addr)
		return AF_UNSPEC;
	return addr->sa_family;
}

int kr_inaddr_len(const struct sockaddr *addr)
{
	if (!addr) {
		return kr_error(EINVAL);
	}
	return kr_family_len(addr->sa_family);
}

uint16_t kr_inaddr_port(const struct sockaddr *addr)
{
	if (!addr) {
		return 0;
	}
	switch (addr->sa_family) {
	case AF_INET:  return ntohs(((const struct sockaddr_in *)addr)->sin_port);
	case AF_INET6: return ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
	default:       return 0;
	}
}

int kr_inaddr_str(const struct sockaddr *addr, char *buf, size_t *buflen)
{
	int ret = kr_ok();
	if (!addr || !buf || !buflen) {
		return kr_error(EINVAL);
	}

	char str[INET6_ADDRSTRLEN + 6];
	if (!inet_ntop(addr->sa_family, kr_inaddr(addr), str, sizeof(str))) {
		return kr_error(errno);
	}
	int len = strlen(str);
	str[len] = '#';
	u16tostr((uint8_t *)&str[len + 1], kr_inaddr_port(addr));
	len += 6;
	str[len] = 0;
	if (len >= *buflen) {
		ret = kr_error(ENOSPC);
	} else {
		memcpy(buf, str, len + 1);
	}
	*buflen = len;
	return ret;
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

int kr_family_len(int family)
{
	switch (family) {
	case AF_INET:  return sizeof(struct in_addr);
	case AF_INET6: return sizeof(struct in6_addr);
	default:       return kr_error(EINVAL);
	}
}

struct sockaddr * kr_straddr_socket(const char *addr, int port)
{
	switch (kr_straddr_family(addr)) {
	case AF_INET: {
		struct sockaddr_in *res = malloc(sizeof(*res));
		if (uv_ip4_addr(addr, port, res) >= 0) {
			return (struct sockaddr *)res;
		} else {
			free(res);
			return NULL;
		}
	}
	case AF_INET6: {
		struct sockaddr_in6 *res = malloc(sizeof(*res));
		if (uv_ip6_addr(addr, port, res) >= 0) {
			return (struct sockaddr *)res;
		} else {
			free(res);
			return NULL;
		}
	}
	default:
		return NULL;
	}
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
		bit_len = strtol(subnet, NULL, 10);
		/* Check client subnet length */
		const int max_len = (family == AF_INET6) ? 128 : 32;
		if (bit_len < 0 || bit_len > max_len) {
			return kr_error(ERANGE);
		}
	} else {
		/* No subnet, use maximal subnet length. */
		bit_len = (family == AF_INET6) ? 128 : 32;
	}
	/* Parse address */
	int ret = inet_pton(family, addr_str, dst);
	if (ret < 0) {
		return kr_error(EILSEQ);
	}

	return bit_len;
}

int kr_straddr_split(const char *addr, char *buf, size_t buflen, uint16_t *port)
{
	const int base = 10;
	long p = 0;
	size_t addrlen = strlen(addr);
	char *p_start = strchr(addr, '@');
	char *p_end;

	if (!p_start) {
		p_start = strchr(addr, '#');
	}

	if (p_start) {
		if (p_start[1] != '\0'){
			p = strtol(p_start + 1, &p_end, base);
			if (*p_end != '\0' || p <= 0 || p > UINT16_MAX) {
				return kr_error(EINVAL);
			}
		}
		addrlen = p_start - addr;
	}

	/* Check if address is valid. */
	if (addrlen >= INET6_ADDRSTRLEN) {
		return kr_error(EINVAL);
	}

	char str[INET6_ADDRSTRLEN];
	struct sockaddr_storage ss;

	memcpy(str, addr, addrlen); str[addrlen] = '\0';

	int family = kr_straddr_family(str);
	if (family == kr_error(EINVAL) || !inet_pton(family, str, &ss)) {
		return kr_error(EINVAL);
	}

	/* Address and port contains valid values, return it to caller */
	if (buf) {
		if (addrlen >= buflen) {
			return kr_error(ENOSPC);
		}
		memcpy(buf, addr, addrlen); buf[addrlen] = '\0';
	}
	if (port) {
		*port = (uint16_t)p;
	}

	return kr_ok();
}

int kr_straddr_join(const char *addr, uint16_t port, char *buf, size_t *buflen)
{
	if (!addr || !buf || !buflen) {
		return kr_error(EINVAL);
	}

	struct sockaddr_storage ss;
	int family = kr_straddr_family(addr);
	if (family == kr_error(EINVAL) || !inet_pton(family, addr, &ss)) {
		return kr_error(EINVAL);
	}

	int len = strlen(addr);
	if (len + 6 >= *buflen) {
		return kr_error(ENOSPC);
	}

	memcpy(buf, addr, len + 1);
	buf[len] = '#';
	u16tostr((uint8_t *)&buf[len + 1], port);
	len += 6;
	buf[len] = 0;
	*buflen = len;

	return kr_ok();
}

int kr_bitcmp(const char *a, const char *b, int bits)
{
	/* We're using the function from lua directly, so at least for now
	 * we avoid crashing on bogus inputs.  Meaning: NULL is ordered before
	 * anything else, and negative length is the same as zero.
	 * TODO: review the call sites and probably remove the checks. */
	if (bits <= 0 || (!a && !b)) {
		return 0;
	} else if (!a) {
		return -1;
	} else if (!b) {
		return 1;
	}

	assert((a && b && bits >= 0)  ||  bits == 0);
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

int kr_rrkey(char *key, const knot_dname_t *owner, uint16_t type, uint8_t rank)
{
	if (!key || !owner) {
		return kr_error(EINVAL);
	}
	key[0] = (rank << 2) | 0x01; /* Must be non-zero */
	uint8_t *key_buf = (uint8_t *)key + 1;
	int ret = knot_dname_to_wire(key_buf, owner, KNOT_DNAME_MAXLEN);
	if (ret <= 0) {
		return ret;
	}
	knot_dname_to_lower(key_buf);
	key_buf += ret - 1;
	/* Must convert to string, as the key must not contain 0x00 */
	ret = u16tostr(key_buf, type);
	key_buf[ret] = '\0';
	return (char *)&key_buf[ret] - key;
}

int kr_rrmap_add(map_t *stash, const knot_rrset_t *rr, uint8_t rank, knot_mm_t *pool)
{
	if (!stash || !rr) {
		return kr_error(EINVAL);
	}

	/* Stash key = {[1] flags, [1-255] owner, [5] type, [1] \x00 } */
	char key[KR_RRKEY_LEN];
	uint8_t extra_flags = 0;
	uint16_t rrtype = kr_rrset_type_maysig(rr);
	/* Stash RRSIGs in a special cache, flag them and set type to its covering RR.
	 * This way it the stash won't merge RRSIGs together. */
	if (rr->type == KNOT_RRTYPE_RRSIG) {
		extra_flags |= KEY_FLAG_RRSIG;
	}
	int ret = kr_rrkey(key, rr->owner, rrtype, rank);
	if (ret <= 0) {
		return kr_error(EILSEQ);
	}
	key[0] |= extra_flags;

	/* Check if already exists */
	knot_rrset_t *stashed = map_get(stash, key);
	if (!stashed) {
		stashed = knot_rrset_copy(rr, pool);
		if (!stashed) {
			return kr_error(ENOMEM);
		}
		return map_set(stash, key, stashed);
	}
	/* Merge rdataset */
	return knot_rdataset_merge(&stashed->rrs, &rr->rrs, pool);
}

/** Return whether two RRsets match, i.e. would form the same set; see ranked_rr_array_t */
static inline bool rrsets_match(const knot_rrset_t *rr1, const knot_rrset_t *rr2)
{
	bool match = rr1->type == rr2->type && rr1->rclass == rr2->rclass;
	if (match && rr2->type == KNOT_RRTYPE_RRSIG) {
		match = match && knot_rrsig_type_covered(&rr1->rrs, 0)
				  == knot_rrsig_type_covered(&rr2->rrs, 0);
	}
	match = match && knot_dname_is_equal(rr1->owner, rr2->owner);
	return match;
}

/** Ensure that an index in a ranked array won't cause "duplicate" RRsets on wire.
 *
 * Other entries that would form the same RRset get to_wire = false.
 * See also rrsets_match.
 */
static int to_wire_ensure_unique(ranked_rr_array_t *array, size_t index)
{
	bool ok = array && index < array->len;
	if (!ok) {
		assert(false);
		return kr_error(EINVAL);
	}

	const struct ranked_rr_array_entry *e0 = array->at[index];
	if (!e0->to_wire) {
		return kr_ok();
	}

	for (ssize_t i = array->len - 1; i >= 0; --i) {
		/* ^ iterate backwards, as the end is more likely in CPU caches */
		struct ranked_rr_array_entry *ei = array->at[i];
		if (ei->qry_uid == e0->qry_uid /* assumption: no duplicates within qry */
		    || !ei->to_wire /* no use for complex comparison if @to_wire */
		   ) {
			continue;
		}
		if (rrsets_match(ei->rr, e0->rr)) {
			ei->to_wire = false;
		}
	}
	return kr_ok();
}

int kr_ranked_rrarray_add(ranked_rr_array_t *array, const knot_rrset_t *rr,
			  uint8_t rank, bool to_wire, uint32_t qry_uid, knot_mm_t *pool)
{
	/* rr always has one record per rrset
	 * check if another rrset with the same
	 * rclass/type/owner combination exists within current query
	 * and merge if needed */
	for (ssize_t i = array->len - 1; i >= 0; --i) {
		ranked_rr_array_entry_t *stashed = array->at[i];
		if (stashed->yielded) {
			break;
		}
		if (stashed->qry_uid != qry_uid) {
			break;
		}
		if (!rrsets_match(stashed->rr, rr)) {
			continue;
		}
		/* Found the entry to merge with.  Check consistency and merge. */
		bool ok = stashed->rank == rank
			&& !stashed->cached
			&& stashed->to_wire == to_wire;
		if (!ok) {
			assert(false);
			return kr_error(EEXIST);
		}
		return knot_rdataset_merge(&stashed->rr->rrs, &rr->rrs, pool);
	}

	/* No stashed rrset found, add */
	int ret = array_reserve_mm(*array, array->len + 1, kr_memreserve, pool);
	if (ret != 0) {
		return kr_error(ENOMEM);
	}

	ranked_rr_array_entry_t *entry = mm_alloc(pool, sizeof(ranked_rr_array_entry_t));
	if (!entry) {
		return kr_error(ENOMEM);
	}
	knot_rrset_t *copy = knot_rrset_copy(rr, pool);
	if (!copy) {
		mm_free(pool, entry);
		return kr_error(ENOMEM);
	}

	entry->qry_uid = qry_uid;
	entry->rr = copy;
	entry->rank = rank;
	entry->revalidation_cnt = 0;
	entry->cached = false;
	entry->yielded = false;
	entry->to_wire = to_wire;
	if (array_push(*array, entry) < 0) {
		/* Silence coverity.  It shouldn't be possible to happen,
		 * due to the array_reserve_mm call above. */
		mm_free(pool, entry);
		return kr_error(ENOMEM);
	}

	return to_wire_ensure_unique(array, array->len - 1);
}

int kr_ranked_rrarray_set_wire(ranked_rr_array_t *array, bool to_wire,
			       uint32_t qry_uid, bool check_dups,
			       bool (*extraCheck)(const ranked_rr_array_entry_t *))
{
	for (size_t i = 0; i < array->len; ++i) {
		ranked_rr_array_entry_t *entry = array->at[i];
		if (entry->qry_uid != qry_uid) {
			continue;
		}
		if (extraCheck != NULL && !extraCheck(entry)) {
			continue;
		}
		entry->to_wire = to_wire;
		if (check_dups) {
			int ret = to_wire_ensure_unique(array, i);
			if (ret) return ret;
		}
	}
	return kr_ok();
}


static char *callprop(struct kr_module *module, const char *prop, const char *input, void *env)
{
	if (!module || !module->props || !prop) {
		return NULL;
	}
	for (const struct kr_prop *p = module->props(); p && p->name; ++p) {
		if (p->cb != NULL && strcmp(p->name, prop) == 0) {
			return p->cb(env, module, input);
		}
	}
	return NULL;
}

char *kr_module_call(struct kr_context *ctx, const char *module, const char *prop, const char *input)
{
	if (!ctx || !ctx->modules || !module || !prop) {
		return NULL;
	}
	module_array_t *mod_list = ctx->modules;
	for (size_t i = 0; i < mod_list->len; ++i) {
		struct kr_module *mod = mod_list->at[i];
		if (strcmp(mod->name, module) == 0) {
			return callprop(mod, prop, input, ctx);
		}
	}
	return NULL;
}

void kr_rrset_print(const knot_rrset_t *rr, const char *prefix)
{
#if KNOT_VERSION_HEX < ((2 << 16) | (4 << 8))
	char rrtext[KNOT_DNAME_MAXLEN * 2] = {0};
	knot_rrset_txt_dump(rr, rrtext, sizeof(rrtext), &KNOT_DUMP_STYLE_DEFAULT);
	kr_log_verbose("%s%s", prefix, rrtext);
#else
	size_t size = 4000;
	char *rrtext = malloc(size);
	knot_rrset_txt_dump(rr, &rrtext, &size, &KNOT_DUMP_STYLE_DEFAULT);
	kr_log_verbose("%s%s", prefix, rrtext);
	free(rrtext);
#endif
}

static void flags_to_str(char *dst, const knot_pkt_t *pkt, size_t maxlen)
{
	int offset = 0;
	int ret = 0;
	struct {
		uint8_t (*get) (const uint8_t *packet);
		char name[3];
	} flag[7] = {
		{knot_wire_get_qr, "qr"},
		{knot_wire_get_aa, "aa"},
		{knot_wire_get_rd, "rd"},
		{knot_wire_get_ra, "ra"},
		{knot_wire_get_tc, "tc"},
		{knot_wire_get_ad, "ad"},
		{knot_wire_get_cd, "cd"}
	};
	for (int i = 0; i < 7; ++i) {
		if (!flag[i].get(pkt->wire)) {
			continue;
		}
		ret = snprintf(dst + offset, maxlen, "%s ", flag[i].name);
		if (ret <= 0 || ret >= maxlen) {
			dst[0] = 0;
			return;
		}
		offset += ret;
		maxlen -= ret;
	}
	dst[offset] = 0;
}

static void print_section_opt(const knot_rrset_t *rr, const uint8_t rcode)
{
	uint8_t ercode = knot_edns_get_ext_rcode(rr);
	uint16_t ext_rcode_id = knot_edns_whole_rcode(ercode, rcode);
	const char *ext_rcode_str = "Unused";
	const knot_lookup_t *ext_rcode;

	if (ercode > 0) {
		ext_rcode = knot_lookup_by_id(knot_rcode_names, ext_rcode_id);
		if (ext_rcode != NULL) {
			ext_rcode_str = ext_rcode->name;
		} else {
			ext_rcode_str = "Unknown";
		}
	}

	kr_log_verbose(";; EDNS PSEUDOSECTION:\n;; "
		       "Version: %u; flags: %s; UDP size: %u B; ext-rcode: %s\n\n",
		       knot_edns_get_version(rr),
		       (knot_edns_do(rr) != 0) ? "do" : "",
		       knot_edns_get_payload(rr),
		       ext_rcode_str);

}

void kr_pkt_print(knot_pkt_t *pkt)
{
	char *snames[] = {";; ANSWER SECTION",";; AUTHORITY SECTION",";; ADDITIONAL SECTION"};
	char rrtype[32];
	char flags[32];
	char qname[KNOT_DNAME_MAXLEN];
	uint8_t pkt_rcode = knot_wire_get_rcode(pkt->wire);
	uint8_t pkt_opcode = knot_wire_get_opcode(pkt->wire);
	const char *rcode_str = "Unknown";
	const char *opcode_str = "Unknown";
	const knot_lookup_t *rcode = knot_lookup_by_id(knot_rcode_names, pkt_rcode);
	const knot_lookup_t *opcode = knot_lookup_by_id(knot_opcode_names, pkt_opcode);
	uint16_t qry_id = knot_wire_get_id(pkt->wire);
	uint16_t qdcount = knot_wire_get_qdcount(pkt->wire);

	if (rcode != NULL) {
		rcode_str = rcode->name;
	}
	if (opcode != NULL) {
		opcode_str = opcode->name;
	}
	flags_to_str(flags, pkt, sizeof(flags));
	kr_log_verbose(";; ->>HEADER<<- opcode: %s; status: %s; id: %hu\n",
		       opcode_str, rcode_str, qry_id);

	kr_log_verbose(";; Flags: %s QUERY: %hu; ANSWER: %hu; "
		       "AUTHORITY: %hu; ADDITIONAL: %hu\n\n",
		       flags,
		       qdcount,
		       knot_wire_get_ancount(pkt->wire),
		       knot_wire_get_nscount(pkt->wire),
		       knot_wire_get_arcount(pkt->wire));

	if (knot_pkt_has_edns(pkt)) {
		print_section_opt(pkt->opt_rr,
		                  knot_wire_get_rcode(pkt->wire));
	}

	if (qdcount == 1) {
		knot_dname_to_str(qname, knot_pkt_qname(pkt), KNOT_DNAME_MAXLEN);
		knot_rrtype_to_string(knot_pkt_qtype(pkt), rrtype, sizeof(rrtype));
		kr_log_verbose(";; QUESTION SECTION\n%s\t\t%s\n\n", qname, rrtype);
	} else if (qdcount > 1) {
		kr_log_verbose(";; Warning: unsupported QDCOUNT %hu\n", qdcount);
	}
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_AUTHORITY; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		if (sec->count == 0) {
			continue;
		}
		kr_log_verbose("%s\n", snames[i - KNOT_ANSWER]);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			kr_rrset_print(rr, "");
		}
		kr_log_verbose("\n");
	}
	const knot_pktsection_t *sec = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	bool header_was_printed = false;
	for (unsigned k = 0; k < sec->count; ++k) {
		const knot_rrset_t *rr = knot_pkt_rr(sec, k);
		if (rr->type == KNOT_RRTYPE_OPT) {
			continue;
		}
		if (!header_was_printed) {
			header_was_printed = true;
			kr_log_verbose("%s\n", snames[KNOT_ADDITIONAL - KNOT_ANSWER]);
		}
		kr_rrset_print(rr, "");
	}
	kr_log_verbose("\n");
}

void kr_dname_print(const knot_dname_t *name, const char *prefix, const char *postfix)
{
	char str[KNOT_DNAME_MAXLEN] = {0};
	knot_dname_to_str(str, name, KNOT_DNAME_MAXLEN);
	kr_log_verbose("%s%s%s", prefix, str, postfix);
}

void kr_rrtype_print(const uint16_t rrtype, const char *prefix, const char *postfix)
{
	char str[32] = {0};
	knot_rrtype_to_string(rrtype, str, 32);
	kr_log_verbose("%s%s%s", prefix, str, postfix);
}

void kr_qry_print(const struct kr_query *qry, const char *prefix, const char *postfix)
{
	char str[6] = {0};
	knot_rrclass_to_string(qry->sclass, str, sizeof(str));
	kr_dname_print(qry->sname, prefix, " ");
	kr_log_verbose("%s",str);
	kr_rrtype_print(qry->stype, " ", postfix);
}

uint64_t kr_now()
{
	return uv_now(uv_default_loop());
}

