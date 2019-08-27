#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/xsk.h>
#include <zlib.h>

#include <byteswap.h>

#include <arpa/inet.h>
//#include <net/if.h>
#include <netinet/in.h>
//#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
//#include <linux/icmpv6.h>

// placate libclang :-/
typedef uint64_t size_t;


// TODO
#define unlikely(x) x

#define INVALID_UMEM_FRAME SIZE_MAX

#define FRAME_SIZE 2048
#define NUM_FRAMES 4096
static const size_t packet_buffer_size = NUM_FRAMES * FRAME_SIZE;

void *packet_buffer;


struct udpv4 {
	struct ethhdr eth; // no VLAN support; CRC at the "end" of .data!
	struct iphdr ipv4;
	struct udphdr udp;
	uint8_t data[];
} __attribute__((packed));


struct config {
	const char *ifname;
	int xsk_if_queue;

	struct xsk_socket_config xsk;

	struct udpv4 pkt_template;

	/*
	uint32_t xdp_flags;
	int ifindex;
	char *ifname;
	//char ifname_buf[IF_NAMESIZE];
	int redirect_ifindex;
	char *redirect_ifname;
	//char redirect_ifname_buf[IF_NAMESIZE];
	bool do_unload;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	char src_mac[18];
	char dest_mac[18];
	uint16_t xsk_bind_flags;
	bool xsk_poll_mode;
	*/
};

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};
struct xsk_socket_info {
	//struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;

	//struct stats_record stats;
	//struct stats_record prev_stats;
};


/** Swap two bytes as a *constant* expression.  ATM we assume we're LE, i.e. we do need to swap. */
#define BS16(n) (((n) >> 8) + (((n) & 0xff) << 8))
#define BS32 bswap_32

static struct xsk_umem_info *configure_xsk_umem(void *buffer, size_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	// NOTE: we don't need a fill queue (fq), but the API won't allow us to call
	// with NULL - perhaps it doesn't matter that we don't utilize it later.
	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

/*
static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) // TODO: confusing to use xsk_
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}
*/


static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem)
{
	//uint32_t idx;
	//uint32_t prog_id = 0;
	int i;
	int ret;

	struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, NULL/*&xsk_info->rx*/,
				 &xsk_info->tx, &cfg->xsk);

	if (ret)
		goto error_exit;

	/*
	ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
	if (ret)
		goto error_exit;
	*/

	/* Initialize umem frame allocation */

	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	/*
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info);

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);
	*/

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}



/* Two helper functions taken from Linux kernel 5.2, slightly modified. */
static inline uint32_t from64to32(uint64_t x)
{
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return (uint32_t)x;
}
static inline uint16_t from32to16(uint32_t sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}
/** Compute the checksum of the IPv4 header.
 *
 * Slightly inspired by Linux 5.2 csum_tcpudp_* and friends.
 * This version only works on little endian; the result is in BE/network order.
 *
 * FIXME: this is wrong, apparently; use *_2() at least for now.
 */
static __be16 pkt_ipv4_checksum(const struct iphdr *h)
{
	int64_t s = 0;
	s += (h->ihl << 8) + (h->version << 12) + h->tos;
	s += (h->tot_len + h->id + h->frag_off) << 8;
	s += (h->ttl << 8) + h->protocol;
	s += h->saddr;
	s += h->daddr;
	uint16_t res_le = ~from32to16(from64to32(s));
	return BS16(res_le);
}
static void test_pkt_ipv4_checksum()
{
	// https://en.wikipedia.org/wiki/IPv4_header_checksum#Calculating_the_IPv4_header_checksum
	const struct iphdr h1 = {
		.version = 4,
		.ihl = 5,
		.tos = 0,
		.tot_len = BS16(0x73),
		.id = BS16(0),
		.frag_off = BS16(0x4000),
		.ttl = 0x40,
		.protocol = 0x11, // UDP
		.check = 0, // unused
		.saddr = 0xc0a80001,
		.daddr = 0xc0a800c7,
	};
	const uint16_t c1 = 0xb861;

	uint16_t cc1 = BS16(pkt_ipv4_checksum(&h1)); // we work in native order here
	if (cc1 == c1)
		fprintf(stderr, "OK\n");
	else
		fprintf(stderr, "0x%x != 0x%x\n", cc1, c1);
}

static __be16 pkt_ipv4_checksum_2(const struct iphdr *h)
{
	const uint16_t *ha = (const uint16_t *)h;
	uint32_t sum32 = 0;
	for (int i = 0; i < 10; ++i)
		if (i != 5)
			sum32 += BS16(ha[i]);
	return ~BS16(from32to16(sum32));
}

static void pkt_fill_headers(struct udpv4 *dst, struct udpv4 *template, int data_len)
{
	memcpy(dst, template, sizeof(*template));

	const uint16_t udp_len = sizeof(dst->udp) + data_len;
	dst->udp.len = BS16(udp_len);

	assert(dst->ipv4.ihl == 5); // header length 20
	dst->ipv4.tot_len = BS16(20 + udp_len);
	dst->ipv4.check = pkt_ipv4_checksum_2(&dst->ipv4);

	return; // ethernet checksum not needed?

	/* Finally CRC32 over the whole ethernet frame; we use zlib here. */
	uLong eth_crc = crc32(0L, Z_NULL, 0);
	eth_crc = crc32(eth_crc, (const void *)dst, offsetof(struct udpv4, data) + data_len);
	uint32_t eth_crc_be = BS32(eth_crc);
	memcpy(dst->data + data_len, &eth_crc_be, sizeof(eth_crc_be));

	return; // code below is broken/wrong, probably
#ifndef NDEBUG
	fprintf(stderr, "%x\n", (uint32_t)eth_crc);
	eth_crc = crc32(eth_crc, (const void *)&dst->data[data_len], 4);
	fprintf(stderr, "%x\n", (uint32_t)eth_crc);
	eth_crc = crc32(0L, Z_NULL, 0);
	eth_crc = crc32(eth_crc, (const void *)dst, offsetof(struct udpv4, data) + data_len + 4);
	fprintf(stderr, "%x\n", (uint32_t)eth_crc);
	assert(eth_crc == 0xC704DD7B);
#endif
}

static void pkt_send(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len)
{
	uint32_t tx_idx;
	int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
	if (unlikely(ret != 1)) {
		fprintf(stderr, "No more transmit slots, dropping the packet\n");
		return ;
	}

	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
	xsk_ring_prod__submit(&xsk->tx, 1);

	// We need to wake up the kernel, apparently.
	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}



static bool process_packet(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len)
{
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

        /* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
	 *
	 * Some assumptions to make it easier:
	 * - No VLAN handling
	 * - Only if nexthdr is ICMP
	 * - Just return all data with MAC/IP swapped, and type set to
	 *   ICMPV6_ECHO_REPLY
	 * - Recalculate the icmp checksum */

	int ret;
	uint32_t tx_idx = 0;
	uint8_t tmp_mac[ETH_ALEN];
	struct in6_addr tmp_ip;
	struct ethhdr *eth = (struct ethhdr *) pkt;
	struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
	//struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv6 + 1);

	if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
	    len < (sizeof(*eth) + sizeof(*ipv6)))
		return false;

	memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, tmp_mac, ETH_ALEN);

	memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
	memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
	memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));

	/*
	icmp->icmp6_type = ICMPV6_ECHO_REPLY;

	csum_replace2(&icmp->icmp6_cksum,
		      htons(ICMPV6_ECHO_REQUEST << 8),
		      htons(ICMPV6_ECHO_REPLY << 8));
	*/

	/* Here we sent the packet out of the receive port. Note that
	 * we allocate one entry and schedule it. Your design would be
	 * faster if you do batch processing/transmission */

	ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
	if (ret != 1) {
		/* No more transmit slots, drop the packet */
		return false;
	}

	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
	xsk_ring_prod__submit(&xsk->tx, 1);
	xsk->outstanding_tx++;

	return true;
}




int main(int argc, char **argv)
{
	/* Hard-coded configuration */
	const char
		sip_str[] = "192.168.8.71",
		dip_str[] = "192.168.8.1";
	static struct config cfg = { // static to get zeroed by default
		.ifname = "enp9s0",
		.xsk_if_queue = 0,
		.xsk = {
			.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
			/* Otherwise it tries to load the non-existent program. */
			.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		},
		.pkt_template = {
			.eth = {
				.h_dest   = "\xd8\x58\xd7\x00\x74\x34",
				.h_source = "\x70\x85\xc2\x3a\xc7\x84",
				.h_proto = BS16(ETH_P_IP),
			},
			.ipv4 = {
				.version = 4,
				.ihl = 5,
				.tos = 0, // default: best-effort DSCP + no ECN support
				.tot_len = BS16(0), // to be overwritten
				.id = BS16(0), // probably anything; details: RFC 6864
				.frag_off = BS16(0), // TODO: add the DF flag, probably (1 << 14)
				.ttl = 5,
				.protocol = 0x11, // UDP
				.check = 0, // to be overwritten
			},
			.udp = {
				.source = BS16(5353),
				.dest   = BS16(5353),
				.len    = BS16(0), // to be overwritten
				.check  = BS16(0), // checksum is optional
			},
		},
	};
	if (inet_pton(AF_INET, sip_str, &cfg.pkt_template.ipv4.saddr) != 1
	    || inet_pton(AF_INET, dip_str, &cfg.pkt_template.ipv4.daddr) != 1) {
		fprintf(stderr, "ERROR: failed to convert IPv4 address\n");
		exit(EXIT_FAILURE);
	}

	/* Some failed test
	void *data = malloc(2048);
	struct udpv4 *pkt = data;
	pkt_fill_headers(pkt, &cfg.pkt_template, 0);
	// */

	/* This one is OK!
	test_pkt_ipv4_checksum();
	return 0;
	// */



	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
	struct xsk_umem_info *umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}


	/* Open and configure the AF_XDP (xsk) socket */
	struct xsk_socket_info *xsk_socket = xsk_configure_socket(&cfg, umem);
	if (xsk_socket == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct udpv4 *pkt = umem->buffer;
	int len = 0;
	pkt_fill_headers(pkt, &cfg.pkt_template, len);
	pkt_send(xsk_socket, 0/*byte address relative to start of umem->buffer*/,
			offsetof(struct udpv4, data) + len + 4);



	return 0; // for now, try to make it work up to here



	return 0;
}

