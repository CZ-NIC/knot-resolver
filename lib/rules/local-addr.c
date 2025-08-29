/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/rules/api.h"
#include "lib/rules/impl.h"

#include "contrib/cleanup.h"

#include <stdio.h>

static int parse_addr_str(union kr_sockaddr *sa, const char *addr)
{
	int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
	memset(sa, 0, sizeof(*sa));
	sa->ip.sa_family = family;
	char *addr_bytes = (/*const*/char *)kr_inaddr(&sa->ip);
	if (inet_pton(family, addr, addr_bytes) != 1) {
		return kr_error(EILSEQ);
	}
	return 0;
}

static int add_pair(const char *name, const char *addr,
			bool use_nodata, uint32_t ttl, kr_rule_tags_t tags, kr_rule_opts_t opts)
{
	/* Build key */
	knot_dname_t key[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(key, name, sizeof(key))) {
		return kr_error(EINVAL);
	}
	knot_dname_to_lower(key);

	union kr_sockaddr ia;
	if (parse_addr_str(&ia, addr) != 0) {
		return kr_error(EINVAL);
	}

	uint16_t rrtype = ia.ip.sa_family == AF_INET6 ? KNOT_RRTYPE_AAAA : KNOT_RRTYPE_A;
	knot_rrset_t rrs;
	knot_rrset_init(&rrs, key, rrtype, KNOT_CLASS_IN, ttl);
	int ret;
	if (ia.ip.sa_family == AF_INET6) {
		ret = knot_rrset_add_rdata(&rrs, (const uint8_t *)&ia.ip6.sin6_addr, 16, NULL);
	} else {
		ret = knot_rrset_add_rdata(&rrs, (const uint8_t *)&ia.ip4.sin_addr, 4, NULL);
	}
	if (!ret) ret = kr_rule_local_data_merge(&rrs, tags, opts);
	if (!ret && use_nodata) {
		rrs.type = KNOT_RRTYPE_CNAME;
		rrs.rrs.count = 0;
		rrs.rrs.size = 0;
		// no point in the _merge() variant here
		ret = kr_rule_local_data_ins(&rrs, NULL, tags, opts);
	}

	knot_rdataset_clear(&rrs.rrs, NULL);
	return ret;
}

/** @warning _NOT_ thread-safe; returns a pointer to static data! */
static const knot_dname_t * raw_addr2reverse(const uint8_t *raw_addr, int family)
{
	#define REV_MAXLEN (4*16 + 16 /* the suffix, terminator, etc. */)
	char reverse_addr[REV_MAXLEN];
	static knot_dname_t dname[REV_MAXLEN];
	#undef REV_MAXLEN

	if (family == AF_INET) {
		(void)snprintf(reverse_addr, sizeof(reverse_addr),
			 "%d.%d.%d.%d.in-addr.arpa.",
		         raw_addr[3], raw_addr[2], raw_addr[1], raw_addr[0]);
	} else if (family == AF_INET6) {
		char *ra_it = reverse_addr;
		for (int i = 15; i >= 0; --i) {
			ssize_t free_space = reverse_addr + sizeof(reverse_addr) - ra_it;
			int written = snprintf(ra_it, free_space, "%x.%x.",
						raw_addr[i] & 0x0f, raw_addr[i] >> 4);
			if (kr_fails_assert(written < free_space))
				return NULL;
			ra_it += written;
		}
		ssize_t free_space = reverse_addr + sizeof(reverse_addr) - ra_it;
		if (snprintf(ra_it, free_space, "ip6.arpa.") >= free_space) {
			return NULL;
		}
	} else {
		return NULL;
	}

	if (!knot_dname_from_str(dname, reverse_addr, sizeof(dname))) {
		return NULL;
	}
	return dname;
}
static const knot_dname_t * addr2reverse(const char *addr)
{
	/* Parse address string */
	union kr_sockaddr ia;
	if (parse_addr_str(&ia, addr) != 0) {
		return NULL;
	}
	return raw_addr2reverse((const /*sign*/uint8_t *)kr_inaddr(&ia.ip),
				kr_inaddr_family(&ia.ip));
}

static int add_reverse_pair(const char *name, const char *addr,
			bool use_nodata, uint32_t ttl, kr_rule_tags_t tags, kr_rule_opts_t opts)
{
	const knot_dname_t *key = addr2reverse(addr);
	if (!key)
		return kr_error(EINVAL);
	knot_rrset_t rrs;
	knot_rrset_init(&rrs, /*const-cast*/(knot_dname_t *)key,
			KNOT_RRTYPE_PTR, KNOT_CLASS_IN, ttl);
	knot_dname_t ptr_name[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(ptr_name, name, sizeof(ptr_name)))
		return kr_error(EINVAL);
	int ret = knot_rrset_add_rdata(&rrs, ptr_name, knot_dname_size(ptr_name), NULL);
	if (!ret) {
		// We use _merge().  Using multiple PTR RRs is not recommended generally,
		// but here it seems better than choosing any "arbitrarily".
		ret = kr_rule_local_data_merge(&rrs, tags, opts);
		knot_rdataset_clear(&rrs.rrs, NULL);
	}
	return ret;
}

int kr_rule_local_address(const char *name, const char *addr, bool use_nodata,
				uint32_t ttl, kr_rule_tags_t tags, kr_rule_opts_t opts)
{
	int ret = add_reverse_pair(name, addr, use_nodata, ttl, tags, opts);
	if (ret) return ret;
	return add_pair(name, addr, use_nodata, ttl, tags, opts);
}

int kr_rule_local_address_del(const char *name, const char *addr,
				bool use_nodata, kr_rule_tags_t tags)
{
	// Parse addr
	if (!addr)
		return kr_error(ENOSYS);
	union kr_sockaddr ia;
	if (parse_addr_str(&ia, addr) != 0)
		return kr_error(EINVAL);

	// Remove the PTR
	const knot_dname_t *reverse_key = addr2reverse(addr);
	knot_rrset_t rrs;
	knot_rrset_init(&rrs, /*const-cast*/(knot_dname_t *)reverse_key,
			KNOT_RRTYPE_PTR, KNOT_CLASS_IN, 0);
	int ret = kr_rule_local_data_del(&rrs, tags);
	if (ret != 1)
		VERBOSE_MSG(NULL, "del_pair PTR for %s; error: %s\n", addr, kr_strerror(ret));
	if (ret != 1 && ret != kr_error(ENOENT)) // ignore ENOENT for PTR (duplicities)
		return ret;

	// Remove the forward entry
	knot_dname_t key_buf[KNOT_DNAME_MAXLEN];
	rrs.owner = knot_dname_from_str(key_buf, name, sizeof(key_buf));
	if (!rrs.owner)
		return kr_error(EINVAL);
	rrs.type = ia.ip.sa_family == AF_INET6 ? KNOT_RRTYPE_AAAA : KNOT_RRTYPE_A;
	ret = kr_rule_local_data_del(&rrs, tags);
	if (ret != 1)
		VERBOSE_MSG(NULL, "del_pair for %s; error: %s\n", name, kr_strerror(ret));

	// Remove the NODATA entry; again, not perfect matching,
	//  but we don't care much about this dynamic hints API.
	if (ret == 1 && use_nodata) {
		rrs.type = KNOT_RRTYPE_CNAME;
		ret = kr_rule_local_data_del(&rrs, tags);
		if (ret != 1)
			VERBOSE_MSG(NULL, "del_pair for NODATA %s; error: %s\n",
					name, kr_strerror(ret));
	}
	return ret < 0 ? ret : kr_ok();
}

int kr_rule_local_hosts(const char *path, bool use_nodata, uint32_t ttl,
			kr_rule_tags_t tags, kr_rule_opts_t opts)
{
	auto_fclose FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		kr_log_error(RULES, "reading '%s' failed: %s\n", path, strerror(errno));
		return kr_error(errno);
	} else {
		VERBOSE_MSG(NULL, "reading '%s'\n", path);
	}

	/* Load file to map */
	size_t line_len_unused = 0;
	size_t count = 0;
	size_t line_count = 0;
	auto_free char *line = NULL;
	int ret = kr_ok();

	while (getline(&line, &line_len_unused, fp) > 0) {
		++line_count;
		/* Ingore #comments as described in man hosts.5 */
		char *comm = strchr(line, '#');
		if (comm) {
			*comm = '\0';
		}

		char *saveptr = NULL;
		const char *addr = strtok_r(line, " \t\n", &saveptr);
		if (addr == NULL || strlen(addr) == 0) {
			continue;
		}
		const char *canonical_name = strtok_r(NULL, " \t\n", &saveptr);
		if (canonical_name == NULL) {
			ret = kr_error(EINVAL);
			goto error;
		}
		const char *name_tok;
		while ((name_tok = strtok_r(NULL, " \t\n", &saveptr)) != NULL) {
			ret = add_pair(name_tok, addr, use_nodata, ttl, tags, opts);
			if (ret)
				goto error;
			count += 1;
		}
		ret = add_pair(canonical_name, addr, use_nodata, ttl, tags, opts);
		if (!ret) // PTR only to the canonical name
			ret = add_reverse_pair(canonical_name, addr, use_nodata, ttl, tags, opts);
		if (ret)
			goto error;
		count += 1;
	}
error:
	if (ret) { // NOLINT(clang-analyzer-unix.Stream)
		ret = kr_error(ret);
		kr_log_error(RULES, "%s:%zu: invalid syntax\n", path, line_count);
	}
	VERBOSE_MSG(NULL, "loaded %zu hints\n", count);
	return ret;
}
