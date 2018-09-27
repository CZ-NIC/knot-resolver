/*  Copyright (C) 2018 Cloudflare, Inc.

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

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "daemon/io.h"
#include "daemon/proxyprotocol.h"
#include "lib/utils.h"

/* Magic first bytes. */
static const char proxy_protocol_v1sig[6] = "\x50\x52\x4f\x58\x59\x20";
static const char proxy_protocol_v2sig[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
#define V2HEADERSIZE 16

/* PROXY header format. */
union proxy_protocol_hdr {
	struct {
		char line[108];
	} v1;
	struct {
		/* header size = 16 */
		uint8_t sig[12];
		uint8_t ver_cmd;
		uint8_t fam;
		uint16_t len;
		union {
			struct {	/* for TCP/UDP over IPv4, header size += 12 */
				uint32_t src_addr;
				uint32_t dst_addr;
				uint16_t src_port;
				uint16_t dst_port;
			} ipv4;
			struct {	/* for TCP/UDP over IPv6, header size += 36 */
				uint8_t src_addr[16];
				uint8_t dst_addr[16];
				uint16_t src_port;
				uint16_t dst_port;
			} ipv6;
			struct {	/* for AF_UNIX sockets, header size += 216 */
				uint8_t src_addr[108];
				uint8_t dst_addr[108];
			} unix;
		} addr;
	} v2;
};

/* Parse the v1 header. */
ssize_t proxy_protocol_readv1(uv_handle_t *handle, const ssize_t nread, union proxy_protocol_hdr *hdr)
{
	char *p = hdr->v1.line;
	ssize_t off = sizeof(proxy_protocol_v1sig);
	const ssize_t end = (nread < sizeof(hdr->v1.line)) ? nread : sizeof(hdr->v1.line);
	struct session *s = (struct session *)handle->data;
	struct in6_addr src_ip;
	uint16_t src_port = 0;

	if (((end - off) >= 7) && (strncmp(p + off, "UNKNOWN", 7) == 0)) {
		for (off += 7; off < (end - 1); ++off) {
			if (p[off] == '\r' && p[off + 1] == '\n') {
				return off + 2;
			}
		}
		if (off >= (end - 1)) {
			return -1;
		}
	} else if (((end - off) >= 5) && (strncmp(p + off, "TCP", 3) == 0)) {
		/* Scan for "TCP4 " or "TCP6 ". */
		if ((p[off + 3] != '4' && p[off + 3] != '6') || p[off + 4] != ' ') {
			return -1;
		}
		/* Remember for parsing IP addresses. */
		bool ipv6 = p[off + 3] == '6';
		off += 5;

		/* Scan for "<src_ip> ". */
		char *sep = (char *)memchr(p + off, ' ', end - off);
		if (!sep) {
			return -1;
		}
		/* Store original client source IP. */
		*sep = '\0';
		if (uv_inet_pton(ipv6 ? AF_INET6 : AF_INET, p + off, &src_ip) != 0) {
			return -1;
		}
		off = (sep - p) + 1;

		/* Scan for "<dst_ip> " but ignore it. */
		sep = (char *)memchr(p + off, ' ', end - off);
		if (!sep) {
			return -1;
		}
		off = (sep - p) + 1;

		/* Scan for "<src_port> ". */
		sep = (char *)memchr(p + off, ' ', end - off);
		if (!sep) {
			return -1;
		}
		/* Store original client source port. */
		*sep = '\0';
		src_port = htons(atoi(p + off));
		off = (sep - p) + 1;

		/* Scan for "<dst_port>\r\n" but ignore it. */
		sep = (char *)memchr(p + off, '\r', (end - off) - 1);
		if (!sep || sep[1] != '\n') {
			return -1;
		}

		if (ipv6) {
			s->peer.ip6.sin6_family = AF_INET6;
			s->peer.ip6.sin6_port = src_port;
			s->peer.ip6.sin6_addr = src_ip;
		} else {
			s->peer.ip4.sin_family = AF_INET;
			s->peer.ip4.sin_port = src_port;
			s->peer.ip4.sin_addr = *(struct in_addr *)&src_ip;
		}
		return (sep - p) + 2;

	} else {
		return -1;
	}

	return off;
}

/* Parse the v2 header. */
ssize_t proxy_protocol_readv2(uv_handle_t *handle, const ssize_t nread, const union proxy_protocol_hdr *hdr)
{
	ssize_t toskip = V2HEADERSIZE + ntohs(hdr->v2.len);
	struct session *s = (struct session *)handle->data;

	if ((hdr->v2.ver_cmd & 0xF0) != 0x20) {
		return -1;
	}
	if (nread < toskip) {
		return -1;
	}

	switch (hdr->v2.ver_cmd & 0xF) {
	case 0x0: /* LOCAL command */
		break;
	case 0x1: /* PROXY command */
		switch (hdr->v2.fam) {
		case 0x00:	/* UNSPEC */
			break;
		case 0x11:	/* TCP over IPv4 */
		case 0x12:	/* UDP over IPv4 */
			if (ntohs(hdr->v2.len) < sizeof(hdr->v2.addr.ipv4)) {
				return -1;
			}
			s->peer.ip4.sin_family = AF_INET;
			s->peer.ip4.sin_addr.s_addr = hdr->v2.addr.ipv4.src_addr;
			s->peer.ip4.sin_port = hdr->v2.addr.ipv4.src_port;
			break;
		case 0x21:	/* TCP over IPv6 */
		case 0x22:	/* UDP over IPv6 */
			if (ntohs(hdr->v2.len) < sizeof(hdr->v2.addr.ipv6)) {
				return -1;
			}
			s->peer.ip6.sin6_family = AF_INET6;
			memcpy(s->peer.ip6.sin6_addr.s6_addr, hdr->v2.addr.ipv6.src_addr, sizeof(hdr->v2.addr.ipv6.src_addr));
			s->peer.ip6.sin6_port = hdr->v2.addr.ipv6.src_port;
			break;
		case 0x31:	/* AF_UNIX stream */
		case 0x32:	/* AF_UNIX datagram */
			break;
		default:
			return -1;
		}
		break;
	default:
		return -1;
	}
	return toskip;
}

int proxy_protocol_parse(uv_handle_t *handle, ssize_t *nread, uv_buf_t *buf)
{
	ssize_t toskip = 0;

	if (!handle || !buf) {
		return kr_error(EINVAL);
	}
	if (V2HEADERSIZE < sizeof(proxy_protocol_v1sig) ||
		V2HEADERSIZE < sizeof(proxy_protocol_v2sig)) {
		return kr_error(EINVAL);
	}
	if (*nread < V2HEADERSIZE) {
#ifdef DEBUG
		kr_log_verbose("[prxy] read less than %u bytes - if this is a fragmented PROXY header it will be rejected\n", V2HEADERSIZE);
#endif
		return kr_ok();
	}

	union proxy_protocol_hdr *hdr = (union proxy_protocol_hdr *)buf->base;

	if (memcmp(hdr->v1.line, proxy_protocol_v1sig, sizeof(proxy_protocol_v1sig)) == 0) {
		kr_log_verbose("[prxy] parsing a PROXYv1 header\n");
		toskip = proxy_protocol_readv1(handle, *nread, hdr);
	}
	else if (memcmp(hdr->v2.sig, proxy_protocol_v2sig, sizeof(proxy_protocol_v2sig)) == 0) {
		kr_log_verbose("[prxy] parsing a PROXYv2 header\n");
		toskip = proxy_protocol_readv2(handle, *nread, hdr);
	}

	if ((toskip < 0) || (*nread < toskip)) {
		return kr_error(EINVAL);
	}
	buf->base += toskip;
	buf->len -= toskip;
	*nread -= toskip;
	return kr_ok();
}
