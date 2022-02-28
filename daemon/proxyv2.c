/*  Copyright (C) 2014-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/proxyv2.h"

#include "lib/generic/trie.h"

const char PROXY2_SIGNATURE[12] = {
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

#define PROXY2_IP6_ADDR_SIZE 16
#define PROXY2_UNIX_ADDR_SIZE 108

#define TLV_TYPE_SSL 0x20

enum proxy2_family {
	PROXY2_AF_UNSPEC = 0x0,
	PROXY2_AF_INET   = 0x1,
	PROXY2_AF_INET6  = 0x2,
	PROXY2_AF_UNIX   = 0x3
};

enum proxy2_protocol {
	PROXY2_PROTOCOL_UNSPEC = 0x0,
	PROXY2_PROTOCOL_STREAM = 0x1,
	PROXY2_PROTOCOL_DGRAM  = 0x2
};

/** PROXYv2 protocol header section */
struct proxy2_header {
	uint8_t signature[sizeof(PROXY2_SIGNATURE)];
	uint8_t version_command;
	uint8_t family_protocol;
	uint16_t length; /**< Length of the address section */
};

/** PROXYv2 additional information in Type-Length-Value (TLV) format. */
struct proxy2_tlv {
	uint8_t type;
	uint8_t length_hi;
	uint8_t length_lo;
	uint8_t value[];
};

/** PROXYv2 protocol address section */
union proxy2_address {
	struct {
		uint32_t src_addr;
		uint32_t dst_addr;
		uint16_t src_port;
		uint16_t dst_port;
	} ipv4_addr;
	struct {
		uint8_t src_addr[PROXY2_IP6_ADDR_SIZE];
		uint8_t dst_addr[PROXY2_IP6_ADDR_SIZE];
		uint16_t src_port;
		uint16_t dst_port;
	} ipv6_addr;
	struct {
		uint8_t src_addr[PROXY2_UNIX_ADDR_SIZE];
		uint8_t dst_addr[PROXY2_UNIX_ADDR_SIZE];
	} unix_addr;
};


/** Gets protocol version from the specified PROXYv2 header. */
static inline unsigned char proxy2_header_version(const struct proxy2_header* h)
{
	return (h->version_command & 0xF0) >> 4;
}

/** Gets command from the specified PROXYv2 header. */
static inline enum proxy2_command proxy2_header_command(const struct proxy2_header *h)
{
	return h->version_command & 0x0F;
}

/** Gets address family from the specified PROXYv2 header. */
static inline enum proxy2_family proxy2_header_family(const struct proxy2_header *h)
{
	return (h->family_protocol & 0xF0) >> 4;
}

/** Gets transport protocol from the specified PROXYv2 header. */
static inline enum proxy2_family proxy2_header_protocol(const struct proxy2_header *h)
{
	return h->family_protocol & 0x0F;
}

static inline union proxy2_address *proxy2_get_address(const struct proxy2_header *h)
{
	return (union proxy2_address *) ((uint8_t *) h + sizeof(struct proxy2_header));
}

static inline struct proxy2_tlv *get_tlvs(const struct proxy2_header *h, size_t addr_len)
{
	return (struct proxy2_tlv *) ((uint8_t *) proxy2_get_address(h) + addr_len);
}

/** Gets the length of the TLV's `value` attribute. */
static inline uint16_t proxy2_tlv_length(const struct proxy2_tlv *tlv)
{
	return ((uint16_t) tlv->length_hi << 16) | tlv->length_lo;
}

static inline bool has_tlv(const struct proxy2_header *h,
                           const struct proxy2_tlv *tlv)
{
	uint64_t addr_length = ntohs(h->length);
	ptrdiff_t hdr_len = sizeof(struct proxy2_header) + addr_length;

	uint8_t *tlv_hdr_end = (uint8_t *) tlv + sizeof(struct proxy2_tlv);
	ptrdiff_t distance = tlv_hdr_end - (uint8_t *) h;
	if (hdr_len < distance)
		return false;

	uint8_t *tlv_end = tlv_hdr_end + proxy2_tlv_length(tlv);
	distance = tlv_end - (uint8_t *) h;
	return hdr_len >= distance;
}

static inline void next_tlv(struct proxy2_tlv **tlv)
{
	uint8_t *next = ((uint8_t *) *tlv + sizeof(struct proxy2_tlv) + proxy2_tlv_length(*tlv));
	*tlv = (struct proxy2_tlv *) next;
}


bool proxy_allowed(const struct network *net, const struct sockaddr *saddr)
{
	union kr_in_addr addr;
	trie_t *trie;
	size_t addr_size;
	switch (saddr->sa_family) {
	case AF_INET:
		if (net->proxy_all4)
			return true;

		trie = net->proxy_addrs4;
		addr_size = sizeof(addr.ip4);
		addr.ip4 = ((struct sockaddr_in *) saddr)->sin_addr;
		break;
	case AF_INET6:
		if (net->proxy_all6)
			return true;

		trie = net->proxy_addrs6;
		addr_size = sizeof(addr.ip6);
		addr.ip6 = ((struct sockaddr_in6 *) saddr)->sin6_addr;
		break;
	default:
		kr_assert(false); // Only IPv4 and IPv6 proxy addresses supported
		return false;
	}

	trie_val_t *val;
	int ret = trie_get_leq(trie, (char *) &addr, addr_size, &val);
	if (ret != kr_ok() && ret != 1)
		return false;

	kr_assert(val);
	const struct net_proxy_data *found = *val;
	kr_assert(found);
	return kr_bitcmp((char *) &addr, (char *) &found->addr, found->netmask) == 0;
}

ssize_t proxy_process_header(struct proxy_result *out, struct session *s,
		const void *buf, const ssize_t nread)
{
	if (!buf)
		return kr_error(EINVAL);

	const struct proxy2_header *hdr = (struct proxy2_header *) buf;

	uint64_t content_length = ntohs(hdr->length);
	ssize_t hdr_len = sizeof(struct proxy2_header) + content_length;

	/* PROXYv2 requires the header to be received all at once */
	if (nread < hdr_len) {
		return kr_error(KNOT_EMALF);
	}

	unsigned char version = proxy2_header_version(hdr);
	if (version != 2) {
		/* Version MUST be 2 for PROXYv2 protocol */
		return kr_error(KNOT_EMALF);
	}

	enum proxy2_command command = proxy2_header_command(hdr);
	if (command == PROXY2_CMD_LOCAL) {
		/* Addresses for LOCAL are to be discarded */
		*out = (struct proxy_result) { .command = PROXY2_CMD_LOCAL };
		goto fill_wirebuf;
	}

	if (command != PROXY2_CMD_PROXY) {
		/* PROXYv2 prohibits values other than LOCAL and PROXY */
		return kr_error(KNOT_EMALF);
	}

	*out = (struct proxy_result) { .command = PROXY2_CMD_PROXY };

	/* Parse flags */
	enum proxy2_family family = proxy2_header_family(hdr);
	switch(family) {
	case PROXY2_AF_UNSPEC:
	case PROXY2_AF_UNIX: /* UNIX is unsupported, fall back to UNSPEC */
		out->family = AF_UNSPEC;
		break;
	case PROXY2_AF_INET:
		out->family = AF_INET;
		break;
	case PROXY2_AF_INET6:
		out->family = AF_INET6;
		break;
	default: /* PROXYv2 prohibits other values */
		return kr_error(KNOT_EMALF);
	}

	enum proxy2_family protocol = proxy2_header_protocol(hdr);
	switch (protocol) {
	case PROXY2_PROTOCOL_DGRAM:
		out->protocol = SOCK_DGRAM;
		break;
	case PROXY2_PROTOCOL_STREAM:
		out->protocol = SOCK_STREAM;
		break;
	default: /* PROXYv2 prohibits other values */
		return kr_error(KNOT_EMALF);
	}

	/* Parse addresses */
	union proxy2_address* addr = proxy2_get_address(hdr);
	size_t addr_length = 0;
	switch(out->family) {
	case AF_INET:
		addr_length = sizeof(addr->ipv4_addr);
		if (content_length < addr_length)
			return kr_error(KNOT_EMALF);

		out->src_addr.ip4 = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_addr = { .s_addr = addr->ipv4_addr.src_addr },
			.sin_port = addr->ipv4_addr.src_port,
		};
		out->dst_addr.ip4 = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_addr = { .s_addr = addr->ipv4_addr.dst_addr },
			.sin_port = addr->ipv4_addr.dst_port,
		};
		break;
	case AF_INET6:
		addr_length = sizeof(addr->ipv6_addr);
		if (content_length < addr_length)
			return kr_error(KNOT_EMALF);

		out->src_addr.ip6 = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_port = addr->ipv6_addr.src_port
		};
		memcpy(
				&out->src_addr.ip6.sin6_addr.s6_addr,
				&addr->ipv6_addr.src_addr,
				sizeof(out->src_addr.ip6.sin6_addr.s6_addr));
		out->dst_addr.ip6 = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_port = addr->ipv6_addr.dst_port
		};
		memcpy(
				&out->dst_addr.ip6.sin6_addr.s6_addr,
				&addr->ipv6_addr.dst_addr,
				sizeof(out->dst_addr.ip6.sin6_addr.s6_addr));
		break;
	}

	/* Process additional information */
	for (struct proxy2_tlv *tlv = get_tlvs(hdr, addr_length); has_tlv(hdr, tlv); next_tlv(&tlv)) {
		switch (tlv->type) {
		case TLV_TYPE_SSL:
			out->has_tls = true;
			break;
		/* TODO: add more TLV types if needed */
		}
	}

fill_wirebuf:
	return session_wirebuf_trim(s, hdr_len);
}
