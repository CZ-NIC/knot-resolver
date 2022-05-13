/*  Copyright (C) 2014-2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/utils.h"

#include "contrib/ccan/asprintf/asprintf.h"
#include "contrib/cleanup.h"
#include "contrib/ucw/mempool.h"
#include "kresconfig.h"
#include "lib/defines.h"
#include "lib/generic/array.h"
#include "lib/module.h"
#include "lib/selection.h"
#include "lib/resolve.h"

#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/rrset-dump.h>
#include <libknot/rrtype/rrsig.h>
#include <libknot/version.h>
#include <uv.h>

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/un.h>

struct __attribute__((packed)) kr_sockaddr_key {
	int family;
};

struct __attribute__((packed)) kr_sockaddr_in_key {
	int family;
	char address[sizeof(((struct sockaddr_in *) NULL)->sin_addr)];
	uint16_t port;
};

struct __attribute__((packed)) kr_sockaddr_in6_key {
	int family;
	char address[sizeof(((struct sockaddr_in6 *) NULL)->sin6_addr)];
	uint32_t scope;
	uint16_t port;
};

struct __attribute((packed)) kr_sockaddr_un_key {
	int family;
	char path[sizeof(((struct sockaddr_un *) NULL)->sun_path)];
};

/* Logging & debugging */
bool kr_dbg_assertion_abort = DBG_ASSERTION_ABORT;
int kr_dbg_assertion_fork = DBG_ASSERTION_FORK;

void kr_fail(bool is_fatal, const char *expr, const char *func, const char *file, int line)
{
	const int errno_orig = errno;
	if (is_fatal)
		kr_log_crit(SYSTEM, "requirement \"%s\" failed in %s@%s:%d\n", expr, func, file, line);
	else
		kr_log_error(SYSTEM, "assertion \"%s\" failed in %s@%s:%d\n", expr, func, file, line);

	if (is_fatal || (kr_dbg_assertion_abort && !kr_dbg_assertion_fork))
		abort();
	else if (!kr_dbg_assertion_abort || !kr_dbg_assertion_fork)
		goto recover;
	// We want to fork and abort the child, unless rate-limited.
	static uint64_t limited_until = 0;
	const uint64_t now = kr_now();
	if (now < limited_until)
		goto recover;
	if (kr_dbg_assertion_fork > 0) {
		// Add jitter +- 25%; in other words: 75% + uniform(0,50%).
		// Motivation: if a persistent problem starts happening, desynchronize
		// coredumps from different instances as they're not cheap.
		limited_until = now + kr_dbg_assertion_fork * 3 / 4
			+ kr_dbg_assertion_fork * kr_rand_bytes(1) / 256 / 2;
	}
	if (fork() == 0)
		abort();
recover:
	errno = errno_orig;
}

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
		if (unlikely(new_len < total_len)) {
			va_end(vl);
			return NULL;
		}
		total_len = new_len;
	}
	va_end(vl);

	/* Allocate result and fill */
	char *result = NULL;
	if (total_len > 0) {
		if (unlikely(total_len == SIZE_MAX)) return NULL;
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

char * kr_absolutize_path(const char *dirname, const char *fname)
{
	if (kr_fails_assert(dirname && fname)) {
		errno = EINVAL;
		return NULL;
	}
	char *result;
	int aret;
	if (dirname[0] == '/') { // absolute path is easier
		aret = asprintf(&result, "%s/%s", dirname, fname);
	} else { // relative path, but don't resolve symlinks
		char buf[PATH_MAX];
		const char *cwd = getcwd(buf, sizeof(buf));
		if (!cwd)
			return NULL; // errno has been set already
		if (strcmp(dirname, ".") == 0) {
			// get rid of one common case of extraneous "./"
			aret = asprintf(&result, "%s/%s", cwd, fname);
		} else {
			aret = asprintf(&result, "%s/%s/%s", cwd, dirname, fname);
		}
	}
	if (aret > 0)
		return result;
	errno = -aret;
	return NULL;
}

int kr_memreserve(void *baton, void **mem, size_t elm_size, size_t want, size_t *have)
{
    if (*have >= want) {
        return 0;
    } else {
        knot_mm_t *pool = baton;
        size_t next_size = array_next_count(want);
        void *mem_new = mm_alloc(pool, next_size * elm_size);
        if (mem_new != NULL) {
	    if (*mem) { /* 0-length memcpy from NULL isn't technically OK */
		memcpy(mem_new, *mem, (*have)*(elm_size));
		mm_free(pool, *mem);
	    }
            *mem = mem_new;
            *have = next_size;
            return 0;
        }
    }
    return -1;
}

static int pkt_recycle(knot_pkt_t *pkt, bool keep_question)
{
	/* The maximum size of a header + query name + (class, type) */
	uint8_t buf[KNOT_WIRE_HEADER_SIZE + KNOT_DNAME_MAXLEN + 2 * sizeof(uint16_t)];

	/* Save header and the question section */
	size_t base_size = KNOT_WIRE_HEADER_SIZE;
	if (keep_question) {
		base_size += knot_pkt_question_size(pkt);
	}
	if (kr_fails_assert(base_size <= sizeof(buf))) return kr_error(EINVAL);
	memcpy(buf, pkt->wire, base_size);

	/* Clear the packet and its auxiliary structures */
	knot_pkt_clear(pkt);

	/* Restore header and question section and clear counters */
	pkt->size = base_size;
	memcpy(pkt->wire, buf, base_size);
	knot_wire_set_qdcount(pkt->wire, keep_question);
	knot_wire_set_ancount(pkt->wire, 0);
	knot_wire_set_nscount(pkt->wire, 0);
	knot_wire_set_arcount(pkt->wire, 0);

	/* Reparse question */
	knot_pkt_begin(pkt, KNOT_ANSWER);
	return knot_pkt_parse_question(pkt);
}

int kr_pkt_recycle(knot_pkt_t *pkt)
{
	return pkt_recycle(pkt, false);
}

int kr_pkt_clear_payload(knot_pkt_t *pkt)
{
	return pkt_recycle(pkt, knot_wire_get_qdcount(pkt->wire));
}

int kr_pkt_put(knot_pkt_t *pkt, const knot_dname_t *name, uint32_t ttl,
               uint16_t rclass, uint16_t rtype, const uint8_t *rdata, uint16_t rdlen)
{
	/* LATER(opt.): there's relatively lots of copying, but ATM kr_pkt_put()
	 * isn't considered to be used in any performance-critical parts (just lua). */
	if (!pkt || !name)  {
		return kr_error(EINVAL);
	}
	/* Create empty RR */
	knot_rrset_t rr;
	knot_rrset_init(&rr, knot_dname_copy(name, &pkt->mm), rtype, rclass, ttl);
	/* Create RDATA */
	knot_rdata_t *rdata_tmp = mm_alloc(&pkt->mm, offsetof(knot_rdata_t, data) + rdlen);
	knot_rdata_init(rdata_tmp, rdlen, rdata);
	knot_rdataset_add(&rr.rrs, rdata_tmp, &pkt->mm);
	mm_free(&pkt->mm, rdata_tmp); /* we're always on mempool for now, but whatever */
	/* Append RR */
	return knot_pkt_put(pkt, 0, &rr, KNOT_PF_FREE);
}

void kr_pkt_make_auth_header(knot_pkt_t *pkt)
{
	if (kr_fails_assert(pkt && pkt->wire)) return;
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

int kr_sockaddr_len(const struct sockaddr *addr)
{
	if (!addr) {
		return kr_error(EINVAL);
	}
	switch (addr->sa_family) {
	case AF_INET:  return sizeof(struct sockaddr_in);
	case AF_INET6: return sizeof(struct sockaddr_in6);
	case AF_UNIX:  return sizeof(struct sockaddr_un);
	default:       return kr_error(EINVAL);
	}
}

ssize_t kr_sockaddr_key(struct kr_sockaddr_key_storage *dst,
                        const struct sockaddr *addr)
{
	kr_require(addr);

	switch (addr->sa_family) {
	case AF_INET:;
		const struct sockaddr_in *addr_in = (const struct sockaddr_in *) addr;
		struct kr_sockaddr_in_key *inkey = (struct kr_sockaddr_in_key *) dst;
		inkey->family = AF_INET;
		memcpy(&inkey->address, &addr_in->sin_addr, sizeof(inkey->address));
		memcpy(&inkey->port, &addr_in->sin_port, sizeof(inkey->port));
		return sizeof(*inkey);

	case AF_INET6:;
		const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *) addr;
		struct kr_sockaddr_in6_key *in6key = (struct kr_sockaddr_in6_key *) dst;
		in6key->family = AF_INET6;
		memcpy(&in6key->address, &addr_in6->sin6_addr, sizeof(in6key->address));
		memcpy(&in6key->port, &addr_in6->sin6_port, sizeof(in6key->port));
		if (kr_sockaddr_link_local(addr))
			memcpy(&in6key->scope, &addr_in6->sin6_scope_id, sizeof(in6key->scope));
		else
			in6key->scope = 0;
		return sizeof(*in6key);

	case AF_UNIX:;
		const struct sockaddr_un *addr_un = (const struct sockaddr_un *) addr;
		struct kr_sockaddr_un_key *unkey = (struct kr_sockaddr_un_key *) dst;
		unkey->family = AF_UNIX;
		size_t pathlen = strnlen(addr_un->sun_path, sizeof(unkey->path));
		if (pathlen == 0 || pathlen >= sizeof(unkey->path)) {
			/* Abstract sockets are not supported - we would need
			 * to also supply a length value for the abstract
			 * pathname.
			 *
			 * UNIX socket path should be null-terminated.
			 *
			 * See unix(7). */
			return kr_error(EINVAL);
		}

		pathlen += 1; /* Include null-terminator */
		strncpy(unkey->path, addr_un->sun_path, pathlen);
		return offsetof(struct kr_sockaddr_un_key, path) + pathlen;

	default:
		return kr_error(EAFNOSUPPORT);
	}
}

struct sockaddr *kr_sockaddr_from_key(struct sockaddr_storage *dst,
                                      const char *key)
{
	kr_require(key);

	switch (((struct kr_sockaddr_key *) key)->family) {
	case AF_INET:;
		const struct kr_sockaddr_in_key *inkey = (struct kr_sockaddr_in_key *) key;
		struct sockaddr_in *addr_in = (struct sockaddr_in *) dst;
		addr_in->sin_family = AF_INET;
		memcpy(&addr_in->sin_addr, &inkey->address, sizeof(inkey->address));
		memcpy(&addr_in->sin_port, &inkey->port, sizeof(inkey->port));
		return (struct sockaddr *) addr_in;

	case AF_INET6:;
		const struct kr_sockaddr_in6_key *in6key = (struct kr_sockaddr_in6_key *) key;
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) dst;
		addr_in6->sin6_family = AF_INET6;
		memcpy(&addr_in6->sin6_addr, &in6key->address, sizeof(in6key->address));
		memcpy(&addr_in6->sin6_port, &in6key->port, sizeof(in6key->port));
		memcpy(&addr_in6->sin6_scope_id, &in6key->scope, sizeof(in6key->scope));
		return (struct sockaddr *) addr_in6;

	case AF_UNIX:;
		const struct kr_sockaddr_un_key *unkey = (struct kr_sockaddr_un_key *) key;
		struct sockaddr_un *addr_un = (struct sockaddr_un *) dst;
		addr_un->sun_family = AF_UNIX;
		strncpy(addr_un->sun_path, unkey->path, sizeof(unkey->path));
		return (struct sockaddr *) addr_un;

	default:
		kr_assert(false);
		return NULL;
	}
}

bool kr_sockaddr_key_same_addr(const char *key_a, const char *key_b)
{
	const struct kr_sockaddr_in6_key *kkey_a = (struct kr_sockaddr_in6_key *) key_a;
	const struct kr_sockaddr_in6_key *kkey_b = (struct kr_sockaddr_in6_key *) key_b;

	if (kkey_a->family != kkey_b->family)
		return false;

	ptrdiff_t offset;
	switch (kkey_a->family) {
		case AF_INET:
			offset = offsetof(struct kr_sockaddr_in_key, address);
			break;
		case AF_INET6:
			if (unlikely(kkey_a->scope != kkey_b->scope))
				return false;
			offset = offsetof(struct kr_sockaddr_in6_key, address);
			break;

		case AF_UNIX:;
			const struct kr_sockaddr_un_key *unkey_a =
				(struct kr_sockaddr_un_key *) key_a;
			const struct kr_sockaddr_un_key *unkey_b =
				(struct kr_sockaddr_un_key *) key_b;

			return strncmp(unkey_a->path, unkey_b->path,
			               sizeof(unkey_a->path)) == 0;

		default:
			kr_assert(false);
			return false;
	}

	size_t len = kr_family_len(kkey_a->family);
	return memcmp(key_a + offset, key_b + offset, len) == 0;
}

int kr_sockaddr_cmp(const struct sockaddr *left, const struct sockaddr *right)
{
	if (!left || !right) {
		return kr_error(EINVAL);
	}
	if (left->sa_family != right->sa_family) {
		return kr_error(EFAULT);
	}
	if (left->sa_family == AF_INET) {
		struct sockaddr_in *left_in = (struct sockaddr_in *)left;
		struct sockaddr_in *right_in = (struct sockaddr_in *)right;
		if (left_in->sin_addr.s_addr != right_in->sin_addr.s_addr) {
			return kr_error(EFAULT);
		}
		if (left_in->sin_port != right_in->sin_port) {
			return kr_error(EFAULT);
		}
	} else if (left->sa_family == AF_INET6) {
		struct sockaddr_in6 *left_in6 = (struct sockaddr_in6 *)left;
		struct sockaddr_in6 *right_in6 = (struct sockaddr_in6 *)right;
		if (memcmp(&left_in6->sin6_addr, &right_in6->sin6_addr,
			   sizeof(struct in6_addr)) != 0) {
			return kr_error(EFAULT);
		}
		if (left_in6->sin6_port != right_in6->sin6_port) {
			return kr_error(EFAULT);
		}
	} else {
		return kr_error(ENOENT);
	}
	return kr_ok();
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

void kr_inaddr_set_port(struct sockaddr *addr, uint16_t port)
{
	if (!addr) {
		return;
	}
	switch (addr->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)addr)->sin_port = htons(port);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
		break;
	default:
		break;
	}
}

int kr_inaddr_str(const struct sockaddr *addr, char *buf, size_t *buflen)
{
	if (!addr) {
		return kr_error(EINVAL);
	}
	return kr_ntop_str(addr->sa_family, kr_inaddr(addr), kr_inaddr_port(addr),
			   buf, buflen);
}

int kr_ntop_str(int family, const void *src, uint16_t port, char *buf, size_t *buflen)
{
	if (!src || !buf || !buflen) {
		return kr_error(EINVAL);
	}

	if (!inet_ntop(family, src, buf, *buflen)) {
		return kr_error(errno);
	}
	const int len = strlen(buf);
	const int len_need = len + 1 + 5 + 1;
	if (len_need > *buflen) {
		*buflen = len_need;
		return kr_error(ENOSPC);
	}
	*buflen = len_need;
	buf[len] = '#';
	u16tostr((uint8_t *)&buf[len + 1], port);
	buf[len_need - 1] = 0;
	return kr_ok();
}

int kr_straddr_family(const char *addr)
{
	if (!addr) {
		return kr_error(EINVAL);
	}
	if (addr[0] == '/') {
		return AF_UNIX;
	}
	if (strchr(addr, ':')) {
		return AF_INET6;
	}
	if (strchr(addr, '.')) {
		return AF_INET;
	}
	return kr_error(EINVAL);
}

int kr_family_len(int family)
{
	switch (family) {
	case AF_INET:  return sizeof(struct in_addr);
	case AF_INET6: return sizeof(struct in6_addr);
	default:       return kr_error(EINVAL);
	}
}

struct sockaddr * kr_straddr_socket(const char *addr, int port, knot_mm_t *pool)
{
	switch (kr_straddr_family(addr)) {
	case AF_INET: {
		struct sockaddr_in *res = mm_alloc(pool, sizeof(*res));
		if (uv_ip4_addr(addr, port, res) >= 0) {
			return (struct sockaddr *)res;
		} else {
			mm_free(pool, res);
			return NULL;
		}
	}
	case AF_INET6: {
		struct sockaddr_in6 *res = mm_alloc(pool, sizeof(*res));
		if (uv_ip6_addr(addr, port, res) >= 0) {
			return (struct sockaddr *)res;
		} else {
			mm_free(pool, res);
			return NULL;
		}
	}
	case AF_UNIX: {
		struct sockaddr_un *res;
		const size_t alen = strlen(addr) + 1;
		if (alen > sizeof(res->sun_path)) {
			return NULL;
		}
		res = mm_alloc(pool, sizeof(*res));
		res->sun_family = AF_UNIX;
		memcpy(res->sun_path, addr, alen);
		return (struct sockaddr *)res;
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
	if (family != AF_INET && family != AF_INET6)
		return kr_error(EINVAL);
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
	if (ret != 1) {
		return kr_error(EILSEQ);
	}

	return bit_len;
}

int kr_straddr_split(const char *instr, char ipaddr[static restrict (INET6_ADDRSTRLEN + 1)],
		     uint16_t *port)
{
	if (kr_fails_assert(instr && ipaddr && port)) return kr_error(EINVAL);
	/* Find where port number starts. */
	const char *p_start = strchr(instr, '@');
	if (!p_start)
		p_start = strchr(instr, '#');
	if (p_start) { /* Get and check the port number. */
		if (p_start[1] == '\0') /* Don't accept empty port string. */
			return kr_error(EILSEQ);
		char *p_end;
		long p = strtol(p_start + 1, &p_end, 10);
		if (*p_end != '\0' || p <= 0 || p > UINT16_MAX)
			return kr_error(EILSEQ);
		*port = p;
	}
	/* Copy the address. */
	const size_t addrlen = p_start ? p_start - instr : strlen(instr);
	if (addrlen > INET6_ADDRSTRLEN)
		return kr_error(EILSEQ);
	memcpy(ipaddr, instr, addrlen);
	ipaddr[addrlen] = '\0';
	return kr_ok();
}

int kr_straddr_join(const char *addr, uint16_t port, char *buf, size_t *buflen)
{
	if (!addr || !buf || !buflen) {
		return kr_error(EINVAL);
	}

	struct sockaddr_storage ss;
	int family = kr_straddr_family(addr);
	if (family == kr_error(EINVAL) || inet_pton(family, addr, &ss) != 1) {
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

	kr_require((a && b && bits >= 0)  ||  bits == 0);
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

void kr_bitmask(unsigned char *a, size_t a_len, int bits)
{
	if (bits < 0 || !a || !a_len) {
		return;
	}

	size_t i = bits / 8;
	const size_t mid_bits = 8 - (bits % 8);
	const unsigned char mask = 0xFF << mid_bits;
	if (i < a_len)
		a[i] &= mask;

	for (++i; i < a_len; ++i)
		a[i] = 0;
}

int kr_rrkey(char *key, uint16_t class, const knot_dname_t *owner,
	     uint16_t type, uint16_t additional)
{
	if (!key || !owner) {
		return kr_error(EINVAL);
	}
	uint8_t *key_buf = (uint8_t *)key;
	int ret = u16tostr(key_buf, class);
	if (ret <= 0) {
		return ret;
	}
	key_buf += ret;
	ret = knot_dname_to_wire(key_buf, owner, KNOT_DNAME_MAXLEN);
	if (ret <= 0) {
		return ret;
	}
	knot_dname_to_lower(key_buf);
	key_buf += ret - 1;
	ret = u16tostr(key_buf, type);
	if (ret <= 0) {
		return ret;
	}
	key_buf += ret;
	ret = u16tostr(key_buf, additional);
	if (ret <= 0) {
		return ret;
	}
	key_buf[ret] = '\0';
	return (char *)&key_buf[ret] - key;
}

/** Return whether two RRsets match, i.e. would form the same set; see ranked_rr_array_t */
static inline bool rrsets_match(const knot_rrset_t *rr1, const knot_rrset_t *rr2)
{
	bool match = rr1->type == rr2->type && rr1->rclass == rr2->rclass;
	if (match && rr2->type == KNOT_RRTYPE_RRSIG) {
		match = match && knot_rrsig_type_covered(rr1->rrs.rdata)
				  == knot_rrsig_type_covered(rr2->rrs.rdata);
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
	if (kr_fails_assert(array && index < array->len)) return kr_error(EINVAL);

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

/* Implementation overview of _add() and _finalize():
 * - for rdata we just maintain a list of pointers (in knot_rrset_t::additional)
 * - we only construct the final rdataset at the end (and thus more efficiently)
 */
typedef array_t(knot_rdata_t *) rdata_array_t;
int kr_ranked_rrarray_add(ranked_rr_array_t *array, const knot_rrset_t *rr,
			  uint8_t rank, bool to_wire, uint32_t qry_uid, knot_mm_t *pool)
{
	/* From normal packet parser we always get RRs one by one,
	 * but cache and prefil modules (also) feed us larger RRsets. */
	kr_assert(rr->rrs.count >= 1);
	/* Check if another rrset with the same
	 * rclass/type/owner combination exists within current query
	 * and merge if needed */
	for (ssize_t i = array->len - 1; i >= 0; --i) {
		ranked_rr_array_entry_t *stashed = array->at[i];
		if (stashed->yielded) {
			break;
		}
		if (stashed->qry_uid != qry_uid) {
			break;
			/* We do not guarantee merging RRs "across" any point that switched
			 * to processing a different upstream packet (i.e. qry_uid).
			 * In particular, iterator never returns KR_STATE_YIELD. */
		}
		if (!rrsets_match(stashed->rr, rr)) {
			continue;
		}
		/* Found the entry to merge with.  Check consistency and merge. */
		if (kr_fails_assert(stashed->rank == rank && !stashed->cached && stashed->in_progress))
			return kr_error(EEXIST);

		/* It may happen that an RRset is first considered useful
		 * (to_wire = false, e.g. due to being part of glue),
		 * and later we may find we also want it in the answer. */
		stashed->to_wire = stashed->to_wire || to_wire;

		/* We just add the reference into this in_progress RRset. */
		rdata_array_t *ra = stashed->rr->additional;
		if (ra == NULL) {
			/* RRset not in array format yet -> convert it. */
			ra = stashed->rr->additional = mm_alloc(pool, sizeof(*ra));
			if (!ra) {
				return kr_error(ENOMEM);
			}
			array_init(*ra);
			int ret = array_reserve_mm(*ra, stashed->rr->rrs.count + rr->rrs.count,
							kr_memreserve, pool);
			if (ret) {
				return kr_error(ret);
			}
			knot_rdata_t *r_it = stashed->rr->rrs.rdata;
			for (int ri = 0; ri < stashed->rr->rrs.count;
					++ri, r_it = knot_rdataset_next(r_it)) {
				kr_require(array_push(*ra, r_it) >= 0);
			}
		} else {
			int ret = array_reserve_mm(*ra, ra->len + rr->rrs.count,
							kr_memreserve, pool);
			if (ret) {
				return kr_error(ret);
			}
		}
		/* Append to the array. */
		knot_rdata_t *r_it = rr->rrs.rdata;
		for (int ri = 0; ri < rr->rrs.count;
				++ri, r_it = knot_rdataset_next(r_it)) {
			kr_require(array_push(*ra, r_it) >= 0);
		}
		return i;
	}

	/* No stashed rrset found, add */
	int ret = array_reserve_mm(*array, array->len + 1, kr_memreserve, pool);
	if (ret) {
		return kr_error(ret);
	}

	ranked_rr_array_entry_t *entry = mm_calloc(pool, 1, sizeof(*entry));
	if (!entry) {
		return kr_error(ENOMEM);
	}

	knot_rrset_t *rr_new = knot_rrset_new(rr->owner, rr->type, rr->rclass, rr->ttl, pool);
	if (!rr_new) {
		mm_free(pool, entry);
		return kr_error(ENOMEM);
	}
	rr_new->rrs = rr->rrs;
	if (kr_fails_assert(rr_new->additional == NULL)) {
		mm_free(pool, entry);
		return kr_error(EINVAL);
	}

	entry->qry_uid = qry_uid;
	entry->rr = rr_new;
	entry->rank = rank;
	entry->to_wire = to_wire;
	entry->in_progress = true;
	if (array_push(*array, entry) < 0) {
		/* Silence coverity.  It shouldn't be possible to happen,
		 * due to the array_reserve_mm call above. */
		mm_free(pool, entry);
		return kr_error(ENOMEM);
	}

	ret = to_wire_ensure_unique(array, array->len - 1);
	if (ret < 0) return ret;
	return array->len - 1;
}

/** Comparator for qsort() on an array of knot_data_t pointers. */
static int rdata_p_cmp(const void *rp1, const void *rp2)
{
	/* Just correct types of the parameters and pass them dereferenced. */
	const knot_rdata_t
		*const *r1 = rp1,
		*const *r2 = rp2;
	return knot_rdata_cmp(*r1, *r2);
}
int kr_ranked_rrarray_finalize(ranked_rr_array_t *array, uint32_t qry_uid, knot_mm_t *pool)
{
	for (ssize_t array_i = array->len - 1; array_i >= 0; --array_i) {
		ranked_rr_array_entry_t *stashed = array->at[array_i];
		if (stashed->qry_uid != qry_uid) {
			continue; /* We apparently can't always short-cut the cycle. */
		}
		if (!stashed->in_progress) {
			continue;
		}
		rdata_array_t *ra = stashed->rr->additional;
		if (!ra) {
			/* No array, so we just need to copy the rdataset. */
			knot_rdataset_t *rds = &stashed->rr->rrs;
			knot_rdataset_t tmp = *rds;
			int ret = knot_rdataset_copy(rds, &tmp, pool);
			if (ret) {
				return kr_error(ret);
			}
		} else {
			/* Multiple RRs; first: sort the array. */
			stashed->rr->additional = NULL;
			qsort(ra->at, ra->len, sizeof(ra->at[0]), rdata_p_cmp);
			/* Prune duplicates: NULL all except the last instance. */
			int dup_count = 0;
			for (int i = 0; i + 1 < ra->len; ++i) {
				if (knot_rdata_cmp(ra->at[i], ra->at[i + 1]) == 0) {
					ra->at[i] = NULL;
					++dup_count;
					kr_log_q(NULL, ITERATOR, "deleted duplicate RR\n");
				}
			}
			/* Prepare rdataset, except rdata contents. */
			knot_rdataset_t *rds = &stashed->rr->rrs;
			rds->size = 0;
			for (int i = 0; i < ra->len; ++i) {
				if (ra->at[i]) {
					rds->size += knot_rdata_size(ra->at[i]->len);
				}
			}
			rds->count = ra->len - dup_count;
			if (rds->size) {
				rds->rdata = mm_alloc(pool, rds->size);
				if (!rds->rdata) {
					return kr_error(ENOMEM);
				}
			} else {
				rds->rdata = NULL;
			}
			/* Everything is ready; now just copy all the rdata. */
			uint8_t *raw_it = (uint8_t *)rds->rdata;
			for (int i = 0; i < ra->len; ++i) {
				if (ra->at[i] && rds->size/*linters*/) {
					const int size = knot_rdata_size(ra->at[i]->len);
					memcpy(raw_it, ra->at[i], size);
					raw_it += size;
				}
			}
			if (kr_fails_assert(raw_it == (uint8_t *)rds->rdata + rds->size))
				return kr_error(EINVAL);
		}
		stashed->in_progress = false;
	}
	return kr_ok();
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
	for (const struct kr_prop *p = module->props; p && p->name; ++p) {
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

static char *print_section_opt(struct mempool *mp, char *endp, const knot_rrset_t *rr, const uint8_t rcode)
{
	uint8_t errcode = knot_edns_get_ext_rcode(rr);
	uint16_t ext_rcode_id = knot_edns_whole_rcode(errcode, rcode);
	const char *ext_rcode_str = "Unused";
	const knot_lookup_t *ext_rcode;

	if (errcode > 0) {
		ext_rcode = knot_lookup_by_id(knot_rcode_names, ext_rcode_id);
		if (ext_rcode != NULL) {
			ext_rcode_str = ext_rcode->name;
		} else {
			ext_rcode_str = "Unknown";
		}
	}

	return mp_printf_append(mp, endp,
		";; EDNS PSEUDOSECTION:\n;; "
		"Version: %u; flags: %s; UDP size: %u B; ext-rcode: %s\n\n",
		knot_edns_get_version(rr),
		(knot_edns_do(rr) != 0) ? "do" : "",
		knot_edns_get_payload(rr),
		ext_rcode_str);

}

/**
 * Detect if qname contains an uppercase letter.
 */
static bool qname_has_uppercase(const knot_dname_t *qname) {
	const int len = knot_dname_size(qname) - 1;  /* skip root label at the end */
	for (int i = 1; i < len; ++i) {  /* skip first length byte */
		/* Note: this relies on the fact that correct label lengths
		 * can't pass this test by "luck" and that correctness
		 * is checked earlier by packet parser. */
		if (qname[i] >= 'A' && qname[i] <= 'Z')
			return true;
	}
	return false;
}

char *kr_pkt_text(const knot_pkt_t *pkt)
{
	if (!pkt) {
		return NULL;
	}

	struct mempool *mp = mp_new(512);

	static const char * snames[] = {
		";; ANSWER SECTION", ";; AUTHORITY SECTION", ";; ADDITIONAL SECTION"
	};
	char flags[32];
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

	char *ptr = mp_printf(mp,
		";; ->>HEADER<<- opcode: %s; status: %s; id: %hu\n"
		";; Flags: %s QUERY: %hu; ANSWER: %hu; "
		"AUTHORITY: %hu; ADDITIONAL: %hu\n\n",
		opcode_str, rcode_str, qry_id,
		flags,
		qdcount,
		knot_wire_get_ancount(pkt->wire),
		knot_wire_get_nscount(pkt->wire),
		knot_wire_get_arcount(pkt->wire));

	if (knot_pkt_has_edns(pkt)) {
		ptr = print_section_opt(mp, ptr, pkt->opt_rr, knot_wire_get_rcode(pkt->wire));
	}

	if (qdcount == 1) {
		KR_DNAME_GET_STR(qname, knot_pkt_qname(pkt));
		KR_RRTYPE_GET_STR(rrtype, knot_pkt_qtype(pkt));
		const char *qnwarn;
		if (qname_has_uppercase(knot_pkt_qname(pkt)))
			qnwarn = \
"; WARNING! Uppercase letters indicate positions with letter case mismatches!\n"
";          Normally you should see all-lowercase qname here.\n";
		else
			qnwarn = "";
		ptr = mp_printf_append(mp, ptr, ";; QUESTION SECTION\n%s%s\t\t%s\n", qnwarn, qname, rrtype);
	} else if (qdcount > 1) {
		ptr = mp_printf_append(mp, ptr, ";; Warning: unsupported QDCOUNT %hu\n", qdcount);
	}

	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		if (sec->count == 0) {
			continue;
		}

		ptr = mp_printf_append(mp, ptr, "\n%s\n", snames[i - KNOT_ANSWER]);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			if (rr->type == KNOT_RRTYPE_OPT) {
				continue;
			}
			auto_free char *rr_text = kr_rrset_text(rr);
			ptr = mp_printf_append(mp, ptr, "%s", rr_text);
		}
	}

	/* Close growing buffer and duplicate result before deleting */
	char *result = strdup(ptr);
	mp_delete(mp);
	return result;
}

const knot_dump_style_t KR_DUMP_STYLE_DEFAULT = { /* almost all = false, */
	.show_ttl = true,
};

char *kr_rrset_text(const knot_rrset_t *rr)
{
	if (!rr) {
		return NULL;
	}

	/* Note: knot_rrset_txt_dump will double the size until the rrset fits */
	size_t bufsize = 128;
	char *buf = malloc(bufsize);
	int ret = knot_rrset_txt_dump(rr, &buf, &bufsize, &KR_DUMP_STYLE_DEFAULT);
	if (ret < 0) {
		free(buf);
		return NULL;
	}

	return buf;
}

uint64_t kr_now()
{
	return uv_now(uv_default_loop());
}

void kr_uv_free_cb(uv_handle_t* handle)
{
	free(handle->data);
}

const char *kr_strptime_diff(const char *format, const char *time1_str,
		             const char *time0_str, double *diff) {
	if (kr_fails_assert(format && time1_str && time0_str && diff)) return NULL;

	struct tm time1_tm;
	time_t time1_u;
	struct tm time0_tm;
	time_t time0_u;

	char *err = strptime(time1_str, format, &time1_tm);
	if (err == NULL || err != time1_str + strlen(time1_str))
		return "strptime failed for time1";
	time1_tm.tm_isdst = -1; /* determine if DST is active or not */
	time1_u = mktime(&time1_tm);
	if (time1_u == (time_t)-1)
		return "mktime failed for time1";

	err = strptime(time0_str, format, &time0_tm);
	if (err == NULL || err != time0_str + strlen(time0_str))
		return "strptime failed for time0";
	time0_tm.tm_isdst = -1; /* determine if DST is active or not */
	time0_u = mktime(&time0_tm);
	if (time0_u == (time_t)-1)
		return "mktime failed for time0";
	*diff = difftime(time1_u, time0_u);

	return NULL;
}

int knot_dname_lf2wire(knot_dname_t * const dst, uint8_t len, const uint8_t *lf)
{
	knot_dname_t *d = dst; /* moving "cursor" as we write it out */
	if (kr_fails_assert(d && (len == 0 || lf))) return kr_error(EINVAL);
	/* we allow the final zero byte to be omitted */
	if (!len) {
		goto finish;
	}
	if (lf[len - 1]) {
		++len;
	}
	/* convert the name, one label at a time */
	int label_end = len - 1; /* index of the zero byte after the current label */
	while (label_end >= 0) {
		/* find label_start */
		int i = label_end - 1;
		while (i >= 0 && lf[i])
			--i;
		const int label_start = i + 1; /* index of the first byte of the current label */
		const int label_len = label_end - label_start;
		kr_assert(label_len >= 0);
		if (label_len > 63 || label_len <= 0)
			return kr_error(EILSEQ);
		/* write the label */
		*d = label_len;
		++d;
		memcpy(d, lf + label_start, label_len);
		d += label_len;
		/* next label */
		label_end = label_start - 1;
	}
finish:
	*d = 0; /* the final zero */
	++d;
	return d - dst;
}

static void rnd_noerror(void *data, uint size)
{
	int ret = gnutls_rnd(GNUTLS_RND_NONCE, data, size);
	if (ret) {
		kr_log_error(SYSTEM, "gnutls_rnd(): %s\n", gnutls_strerror(ret));
		abort();
	}
}
void kr_rnd_buffered(void *data, uint size)
{
	/* static circular buffer, from index _begin (inclusive) to _end (exclusive) */
	static uint8_t buf[512/8]; /* gnutls_rnd() works on blocks of 512 bits (chacha) */
	static uint buf_begin = sizeof(buf);

	if (unlikely(size > sizeof(buf))) {
		rnd_noerror(data, size);
		return;
	}
	/* Start with contiguous chunk, possibly until the end of buffer. */
	const uint size1 = MIN(size, sizeof(buf) - buf_begin);
	uint8_t *d = data;
	memcpy(d, buf + buf_begin, size1);
	if (size1 == size) {
		buf_begin += size1;
		return;
	}
	d += size1;
	size -= size1;
	/* Refill the whole buffer, and finish by another contiguous chunk. */
	rnd_noerror(buf, sizeof(buf));
	memcpy(d, buf, size);
	buf_begin = size;
}

void kr_rrset_init(knot_rrset_t *rrset, knot_dname_t *owner,
			uint16_t type, uint16_t rclass, uint32_t ttl)
{
	if (kr_fails_assert(rrset)) return;
	knot_rrset_init(rrset, owner, type, rclass, ttl);
}
bool kr_pkt_has_wire(const knot_pkt_t *pkt)
{
	return pkt->size != KR_PKT_SIZE_NOWIRE;
}
bool kr_pkt_has_dnssec(const knot_pkt_t *pkt)
{
	return knot_pkt_has_dnssec(pkt);
}
uint16_t kr_pkt_qclass(const knot_pkt_t *pkt)
{
	return knot_pkt_qclass(pkt);
}
uint16_t kr_pkt_qtype(const knot_pkt_t *pkt)
{
	return knot_pkt_qtype(pkt);
}
uint32_t kr_rrsig_sig_inception(const knot_rdata_t *rdata)
{
	return knot_rrsig_sig_inception(rdata);
}
uint32_t kr_rrsig_sig_expiration(const knot_rdata_t *rdata)
{
	return knot_rrsig_sig_expiration(rdata);
}
uint16_t kr_rrsig_type_covered(const knot_rdata_t *rdata)
{
	return knot_rrsig_type_covered(rdata);
}

time_t kr_file_mtime (const char* fname) {
	struct stat fstat;

	if (stat(fname, &fstat) != 0) {
		return 0;
	}

	return fstat.st_mtime;
}

long long kr_fssize(const char *path)
{
	if (!path)
		return kr_error(EINVAL);

	struct statvfs buf;
	if (statvfs(path, &buf) != 0)
		return kr_error(errno);

	return buf.f_frsize * buf.f_blocks;
}

const char * kr_dirent_name(const struct dirent *de)
{
	return de ? de->d_name : NULL;
}

