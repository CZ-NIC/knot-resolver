#include "daemon/af_xdp.h"


#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/xsk.h>
#include <uv.h>

#ifdef KR_XDP_ETH_CRC
#include <zlib.h>
#endif

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


#include "contrib/ucw/lib.h"

#include "lib/resolve.h"
#include "daemon/worker.h"

// placate libclang :-/
typedef uint64_t size_t;


#define INVALID_UMEM_FRAME SIZE_MAX

#define FRAME_SIZE 2048

struct udpv4 {
	union { uint8_t bytes[1]; struct {

	struct ethhdr eth; // no VLAN support; CRC at the "end" of .data!
	struct iphdr ipv4;
	struct udphdr udp;
	uint8_t data[];

	} __attribute__((packed)); };
};

/** The memory layout of each umem frame. */
struct umem_frame {
	union { uint8_t bytes[FRAME_SIZE]; struct {

	struct qr_task *task;
	struct udpv4 udpv4;

	}; };
};

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
	/** Fill queue (unused): passing memory frames to kernel - ready to receive. */
	struct xsk_ring_prod fq;
	/** Completion queue: passing memory frames from kernel - after send finishes. */
	struct xsk_ring_cons cq;
	/** Handle internal to libbpf. */
	struct xsk_umem *umem;

	struct umem_frame *frames; /**< The memory frames. TODO: (uint8_t *frammem) might be more practical. */
	uint32_t frame_count;
	uint32_t free_count; /**< The number of free frames. */
	uint32_t *free_indices; /**< Stack of indices of the free frames. */
};
struct xsk_socket_info {
	//struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	bool kernel_needs_wakeup;
	uv_check_t check_handle;
};

struct xsk_socket_info *the_socket = NULL;
struct config *the_config = NULL;

/** Swap two bytes as a *constant* expression.  ATM we assume we're LE, i.e. we do need to swap. */
#define BS16(n) (((n) >> 8) + (((n) & 0xff) << 8))
#define BS32 bswap_32

static struct xsk_umem_info *configure_xsk_umem(uint32_t frame_count)
{
	struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
	if (!umem) return NULL;

	/* Allocate memory for the frames, aligned to a page boundary. */
	umem->frame_count = frame_count;
	errno = posix_memalign((void **)&umem->frames, getpagesize(), FRAME_SIZE * frame_count);
	if (errno) goto failed;
	/* Initialize our "frame allocator". */
	umem->free_indices = malloc(frame_count * sizeof(umem->free_indices[0]));
	if (!umem->free_indices) goto failed;
	umem->free_count = frame_count;
	for (uint32_t i = 0; i < frame_count; ++i)
		umem->free_indices[i] = i;

	// NOTE: we don't need a fill queue (fq), but the API won't allow us to call
	// with NULL - perhaps it doesn't matter that we don't utilize it later.
	errno = -xsk_umem__create(&umem->umem, umem->frames, FRAME_SIZE * frame_count,
				  &umem->fq, &umem->cq, NULL);
	if (errno) goto failed;

	return umem;
failed:
	free(umem->free_indices);
	free(umem->frames);
	free(umem);
	return NULL;
}

static struct umem_frame *xsk_alloc_umem_frame(struct xsk_umem_info *umem) // TODO: confusing to use xsk_
{
	if (unlikely(umem->free_count == 0))
		return NULL;
	uint32_t index = umem->free_indices[--umem->free_count];
	#ifndef NDEBUG
		umem->free_indices[umem->free_count] = -1;
	#endif
	return umem->frames + index;
}
void *kr_xsk_alloc_wire(uint16_t *maxlen)
{
	struct umem_frame *uframe = xsk_alloc_umem_frame(the_socket->umem);
	if (!uframe) return NULL;
	*maxlen = MIN(UINT16_MAX, FRAME_SIZE - offsetof(struct umem_frame, udpv4.data)
				- 4/*eth CRC*/);
	return uframe->udpv4.data;
}

static void xsk_dealloc_umem_frame(struct xsk_umem_info *umem, uint8_t *uframe_p)
// TODO: confusing to use xsk_
{
	assert(umem->free_count < umem->frame_count);
	ptrdiff_t diff = uframe_p - umem->frames->bytes;
	assert(diff % FRAME_SIZE == 0);
	size_t index = diff / FRAME_SIZE;
	assert(index < umem->frame_count);
	umem->free_indices[umem->free_count++] = index;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem)
{
	struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	int ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, NULL/*&xsk_info->rx*/,
				 &xsk_info->tx, &cfg->xsk);

	if (ret)
		goto error_exit;

	/*
	ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
	if (ret)
		goto error_exit;
	*/

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

	// Ethernet checksum not needed, apparently.
#ifdef KR_XDP_ETH_CRC
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
#endif
}

static void pkt_send(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len)
{
	uint32_t tx_idx;
	int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
	if (unlikely(ret != 1)) {
		fprintf(stderr, "No more transmit slots, dropping the packet\n");
		return;
	}

	*xsk_ring_prod__tx_desc(&xsk->tx, tx_idx) = (struct xdp_desc){
		.addr = addr,
		.len = len,
	};
	xsk_ring_prod__submit(&xsk->tx, 1);
	xsk->kernel_needs_wakeup = true;
}



void kr_xsk_push(const struct sockaddr *src, const struct sockaddr *dst,
		 struct kr_request *req, struct qr_task *task)
{
	kr_log_verbose("[uxsk] pushing a packet\n");
	assert(src->sa_family == AF_INET && dst->sa_family == AF_INET);
	uint8_t *uframe_p = req->answer->wire - offsetof(struct umem_frame, udpv4.data);
	const uint8_t *umem_mem_start = the_socket->umem->frames->bytes;
	#ifndef NDEBUG
		assert((uframe_p - (uint8_t *)NULL) % FRAME_SIZE == 0);
		size_t offset = uframe_p - umem_mem_start;
		assert(offset / FRAME_SIZE < the_socket->umem->frame_count);
	#endif
	struct umem_frame *uframe = (struct umem_frame *)uframe_p;
	uframe->task = task;



	// Filling headers; testing version in pkt_fill_headers()

	// sockaddr* contents is already in network byte order
	const struct sockaddr_in *src_v4 = (const struct sockaddr_in *)src;
	const struct sockaddr_in *dst_v4 = (const struct sockaddr_in *)dst;
	// Copy eth and ipv4; there's nothing useful in udp anymore
	// TODO: hardcoded eth addresses.
	memcpy(&uframe->udpv4, &the_config->pkt_template, offsetof(struct udpv4, udp));

	const uint16_t udp_len = sizeof(uframe->udpv4.udp) + req->answer->size;
	uframe->udpv4.udp.len = BS16(udp_len);
	uframe->udpv4.udp.source = src_v4->sin_port;
	uframe->udpv4.udp.dest   = dst_v4->sin_port;

	assert(uframe->udpv4.ipv4.ihl == 5); // header length 20
	uframe->udpv4.ipv4.tot_len = BS16(20 + udp_len);
	memcpy(&uframe->udpv4.ipv4.saddr, &src_v4->sin_addr, sizeof(src_v4->sin_addr));
	memcpy(&uframe->udpv4.ipv4.daddr, &dst_v4->sin_addr, sizeof(dst_v4->sin_addr));
	uframe->udpv4.ipv4.check = pkt_ipv4_checksum_2(&uframe->udpv4.ipv4);

	uint32_t eth_len = offsetof(struct udpv4, data) + req->answer->size + 4/*CRC*/;
	pkt_send(the_socket, uframe->udpv4.bytes - umem_mem_start, eth_len);
}


/** Periodical callback . */
static void xsk_check(uv_check_t *handle)
{
	/* Send queued packets. */
	if (the_socket->kernel_needs_wakeup) {
		the_socket->kernel_needs_wakeup = false;
		int ret = sendto(xsk_socket__fd(the_socket->xsk), NULL, 0,
				 MSG_DONTWAIT, NULL, 0);
		if (unlikely(ret == -1))
			fprintf(stderr, "sendto: %s\n", strerror(errno));
	}

	/* Collect completed packets. */
	struct xsk_ring_cons *cq = &the_socket->umem->cq;
	uint32_t idx_cq;
	const uint32_t completed = xsk_ring_cons__peek(cq, UINT32_MAX, &idx_cq);
	if (!completed) return;
	for (int i = 0; i < completed; ++i, ++idx_cq) {
		uint8_t *uframe_p = (uint8_t *)the_socket->umem->frames
				+ *xsk_ring_cons__comp_addr(cq, idx_cq)
				- offsetof(struct umem_frame, udpv4);
		const struct umem_frame *uframe = (struct umem_frame *)uframe_p;
		qr_task_on_send(uframe->task, NULL, 0/*no error feedback*/);
		xsk_dealloc_umem_frame(the_socket->umem, uframe_p);
	}
	xsk_ring_cons__release(cq, completed);
	kr_log_verbose("[uxsk] completed %d frames; busy frames: %d\n", (int)completed,
			the_socket->umem->frame_count - the_socket->umem->free_count);
	//TODO: one uncompleted packet/batch is left until the next I/O :-/
}


static struct config the_config_storage = { // static to get zeroed by default
	.ifname = "eno1",
	.xsk_if_queue = 0,
	.xsk = {
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		/* Otherwise it tries to load the non-existent program. */
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
	},
	.pkt_template = {
		.eth = {
			//.h_dest   = "\xd8\x58\xd7\x00\x74\x34",
			//.h_source = "\x70\x85\xc2\x3a\xc7\x84",
			// mirkwood -> knot-bench-player:
			//.h_dest   = "\xa0\x36\x9f\x50\x2a\x9c",
			//.h_source = "\x3c\xfd\xfe\x2b\xcf\x02",
			// doriath -> eriador
			.h_dest   = "\x00\x15\x17\xf8\xd0\x4a",
			.h_source = "\xf0\x1f\xaf\xe2\x80\x0d",
			//.h_source = "\x00\x1e\x67\xe3\xb1\x24", // rohan
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

int kr_xsk_init_global(uv_loop_t *loop)
{
	/* Hard-coded configuration */
	const int FRAME_COUNT = 4096;
	const char
		//sip_str[] = "192.168.8.71",
		//dip_str[] = "192.168.8.1";
		//sip_str[] = "192.168.100.8",
		//dip_str[] = "192.168.100.3";
		sip_str[] = "217.31.193.167",
		dip_str[] = "217.31.193.166";
	the_config = &the_config_storage;
	if (inet_pton(AF_INET, sip_str, &the_config->pkt_template.ipv4.saddr) != 1
	    || inet_pton(AF_INET, dip_str, &the_config->pkt_template.ipv4.daddr) != 1) {
		fprintf(stderr, "ERROR: failed to convert IPv4 address\n");
		exit(EXIT_FAILURE);
	}

	/* Some failed test
	void *data = malloc(2048);
	struct udpv4 *pkt = data;
	pkt_fill_headers(pkt, &the_config->pkt_template, 0);
	// */

	/* This one is OK!
	test_pkt_ipv4_checksum();
	return 0;
	// */

	/* Initialize shared packet_buffer for umem usage */
	struct xsk_umem_info *umem = configure_xsk_umem(FRAME_COUNT);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	assert(!the_socket);
	the_socket = xsk_configure_socket(the_config, umem);
	if (!the_socket) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	kr_log_verbose("[uxsk] busy frames: %d\n",
			the_socket->umem->frame_count - the_socket->umem->free_count);
	//return 0;
	int ret = uv_check_init(loop, &the_socket->check_handle);
	if (!ret) ret = uv_check_start(&the_socket->check_handle, xsk_check);
	return ret;
}

#define SOL_XDP 283
static void print_stats()
{
	struct xdp_statistics stats;
	socklen_t optlen = sizeof(stats);
	int err = getsockopt(xsk_socket__fd(the_socket->xsk), SOL_XDP, XDP_STATISTICS,
				&stats, &optlen);
	if (err) {
		fprintf(stderr, "getsockopt: %s\n", strerror(errno));
	} else {
		fprintf(stderr, "stats: RX drop %d, RX ID %d, TX ID %d\n",
			(int)stats.rx_dropped, (int)stats.rx_invalid_descs,
			(int)stats.tx_invalid_descs);
	}
}

#if 0
int main(int argc, char **argv)
{
	if (argc >= 2) {
		the_config_storage.ifname = argv[1];
	}
	fprintf(stderr, "ifname = '%s'\n", the_config_storage.ifname);
	kr_xsk_init_global(NULL);

	print_stats();
	int ret = sendto(xsk_socket__fd(the_socket->xsk), NULL, 0,
			 MSG_DONTWAIT, NULL, 0);
	fprintf(stderr, "sendto: %d %s\n", ret, strerror(errno));
	print_stats();

	struct udpv4 *pkt = (struct udpv4 *)the_socket->umem->frames;
	int len = 0;
	pkt_fill_headers(pkt, &the_config->pkt_template, len);
	pkt_send(the_socket, 0/*byte address relative to start of umem->buffer*/,
			offsetof(struct udpv4, data) + len + 4);
	print_stats();
	// We need to wake up the kernel, apparently.
	ret = sendto(xsk_socket__fd(the_socket->xsk), NULL, 0,
			 MSG_DONTWAIT, NULL, 0);
	if (unlikely(ret == -1))
		fprintf(stderr, "sendto: %s\n", strerror(errno));
	print_stats();
	ret = sendto(1, NULL, 0,
			 MSG_DONTWAIT, NULL, 0);
	if (unlikely(ret == -1))
		fprintf(stderr, "sendto: %s\n", strerror(errno));
	print_stats();
}
#endif

