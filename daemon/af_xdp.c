/* LATER:
 *  - XDP_USE_NEED_WAKEUP (optimization discussed in summer 2019)
 */



#include "daemon/af_xdp.h"


#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#ifdef KR_XDP_ETH_CRC
#include <zlib.h>
#endif

#include <byteswap.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_link.h>
#include <linux/filter.h>
//#include <linux/icmpv6.h>

#include "contrib/ucw/lib.h"
#include "contrib/ucw/mempool.h"

#include "lib/resolve.h"
#include "daemon/session.h"
#include "daemon/worker.h"


#include "daemon/kxsk/impl.h"

// placate libclang :-/
typedef uint64_t size_t;

#define FRAME_SIZE 4096
#define RX_BATCH_SIZE 64

/** The memory layout of each umem frame. */
struct umem_frame {
	union { uint8_t bytes[FRAME_SIZE]; struct {

	struct qr_task *task;
	struct udpv4 udpv4;

	}; };
};


struct xsk_socket_info *the_socket = NULL;
struct config *the_config = NULL;

/** Swap two bytes as a *constant* expression.  ATM we assume we're LE, i.e. we do need to swap. */
#define BS16(n) (((n) >> 8) + (((n) & 0xff) << 8))
#define BS32 bswap_32

static struct xsk_umem_info *configure_xsk_umem(const struct xsk_umem_config *umem_config,
						uint32_t frame_count)
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
				  &umem->fq, &umem->cq, umem_config);
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
	if (unlikely(umem->free_count == 0)) {
		fprintf(stderr, "[uxsk] no free frame!\n");
		return NULL;
	}
	uint32_t index = umem->free_indices[--umem->free_count];
	//kr_log_verbose("[uxsk] allocating frame %d\n", (int)index);
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
	size_t index = diff / FRAME_SIZE;
	assert(index < umem->frame_count);
	umem->free_indices[umem->free_count++] = index;
}

void kr_xsk_deinit_global(void)
{
	if (!the_socket)
		return;
	kxsk_socket_stop(the_socket->iface, the_config->xsk_if_queue);
	xsk_socket__delete(the_socket->xsk);
	xsk_umem__delete(the_socket->umem->umem);

	kxsk_iface_free((struct kxsk_iface *)/*const-cast*/the_socket->iface, false);
	//TODO: more memory
}

/** Add some free frames into the RX fill queue (possibly zero, etc.) */
int kxsk_umem_refill(const struct config *cfg, struct xsk_umem_info *umem)
{
	/* First find to_reserve: how many frames to move to the RX fill queue.
	 * Let's keep about as many frames ready for TX (free_count) as for RX (fq_ready),
	 * and don't fill the queue to more than a half. */
	const int fq_target = cfg->umem.fill_size / 2;
	uint32_t fq_free = xsk_prod_nb_free(&umem->fq, fq_target);
	if (fq_free <= fq_target)
		return 0;
	const int fq_ready = cfg->umem.fill_size - fq_free;
	const int balance = (fq_ready + umem->free_count) / 2;
	const int fq_want = MIN(balance, fq_target); // don't overshoot the target
	const int to_reserve = fq_want - fq_ready;
	kr_log_verbose("[uxsk] refilling %d frames TX->RX; TX = %d, RX = %d\n",
			to_reserve, (int)umem->free_count, (int)fq_ready);
	if (to_reserve <= 0)
		return 0;

	/* Now really reserve the frames. */
	uint32_t idx;
	int ret = xsk_ring_prod__reserve(&umem->fq, to_reserve, &idx);
	if (ret != to_reserve) {
		assert(false);
		return ENOSPC;
	}
	for (int i = 0; i < to_reserve; ++i, ++idx) {
		struct umem_frame *uframe = xsk_alloc_umem_frame(umem);
		if (!uframe) {
			assert(false);
			return ENOSPC;
		}
		size_t offset = uframe->bytes - umem->frames->bytes;
		*xsk_ring_prod__fill_addr(&umem->fq, idx) = offset;
	}
	xsk_ring_prod__submit(&umem->fq, to_reserve);
	return 0;
}

static struct xsk_socket_info * xsk_configure_socket(struct config *cfg,
				struct xsk_umem_info *umem, const struct kxsk_iface *iface)
{
	/* Put a couple RX buffers into the fill queue.
	 * Even if we don't need them, it silences a dmesg line,
	 * and it avoids 100% CPU usage of ksoftirqd/i for each queue i!
	 */
	errno = kxsk_umem_refill(cfg, umem);
	if (errno)
		return NULL;

	struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;
	xsk_info->iface = iface;
	xsk_info->umem = umem;

	assert(cfg->xsk.libbpf_flags & XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD);
	errno = xsk_socket__create(&xsk_info->xsk, iface->ifname,
				 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &cfg->xsk);

	return xsk_info;
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
		 struct kr_request *req, struct qr_task *task, uint8_t eth_addrs[2][6])
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

	const struct udpv4 *t = &the_config->pkt_template;
	struct udpv4 *h = &uframe->udpv4;

	// UDP: struct udphdr
	const uint16_t udp_len = sizeof(h->udp) + req->answer->size;
	h->udp.len = BS16(udp_len);
	h->udp.source = src_v4->sin_port;
	h->udp.dest   = dst_v4->sin_port;
	h->udp.check  = 0;

	// IPv4: struct iphdr
	h->ipv4.ihl      = t->ipv4.ihl;
	h->ipv4.version  = t->ipv4.version;
	h->ipv4.tos      = t->ipv4.tos;
	assert(h->ipv4.ihl == 5); // header length 20
	h->ipv4.tot_len  = BS16(20 + udp_len);
	h->ipv4.id       = t->ipv4.id;
	h->ipv4.frag_off = t->ipv4.frag_off;
	h->ipv4.ttl      = t->ipv4.ttl;
	h->ipv4.protocol = t->ipv4.protocol;
	memcpy(&h->ipv4.saddr, &src_v4->sin_addr, sizeof(src_v4->sin_addr));
	memcpy(&h->ipv4.daddr, &dst_v4->sin_addr, sizeof(dst_v4->sin_addr));
	h->ipv4.check = pkt_ipv4_checksum_2(&h->ipv4);

	// Ethernet: struct ethhdr
	memcpy(h->eth.h_dest,   eth_addrs[1], sizeof(eth_addrs[1]));
	memcpy(h->eth.h_source, eth_addrs[0], sizeof(eth_addrs[0]));
	h->eth.h_proto = t->eth.h_proto;
	uint32_t eth_len = offsetof(struct udpv4, data) + req->answer->size + 4/*CRC*/;
	pkt_send(the_socket, h->bytes - umem_mem_start, eth_len);
}

/** Periodical callback . */
static void xsk_check(uv_check_t *handle)
{
	/* Trigger sending queued packets.
	 * LATER(opt.): the periodical epoll due to the uv_poll* stuff
	 * is probably enough to wake the kernel even for sending
	 * (though AFAIK it might be specific to driver and/or kernel version). */
	if (the_socket->kernel_needs_wakeup) {
		bool is_ok = sendto(xsk_socket__fd(the_socket->xsk), NULL, 0,
				 MSG_DONTWAIT, NULL, 0) != -1;
		const bool is_again = !is_ok && (errno == EWOULDBLOCK || errno == EAGAIN);
		if (is_ok || is_again) {
			the_socket->kernel_needs_wakeup = false;
			// EAGAIN is unclear; we'll retry the syscall later, to be sure
		}
		if (!is_ok && !is_again) {
			const uint64_t stamp_now = kr_now();
			static uint64_t stamp_last = 0;
			if (stamp_now > stamp_last + 10*1000) {
				kr_log_info("WARNING: sendto error (reported at most once per 10s)\n\t%s\n",
						strerror(errno));
				stamp_last = stamp_now;
			}
		}
	}

	/* Collect completed packets. */
	struct xsk_ring_cons *cq = &the_socket->umem->cq;
	uint32_t idx_cq;
	const uint32_t completed = xsk_ring_cons__peek(cq, UINT32_MAX, &idx_cq);
	kr_log_verbose(".");
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
	/* And feed frames into RX fill queue. */
	kxsk_umem_refill(the_config, the_socket->umem);
}


static void rx_desc(struct xsk_socket_info *xsi, const struct xdp_desc *desc)
{
	uint8_t *uframe_p = xsi->umem->frames->bytes + desc->addr;
	const struct ethhdr *eth = (struct ethhdr *)uframe_p;
	const struct iphdr *ipv4 = NULL;
	const struct ipv6hdr *ipv6 = NULL;
	const struct udphdr *udp;


	// FIXME: length checks on multiple places
	if (eth->h_proto == BS16(ETH_P_IP)) {
		ipv4 = (struct iphdr *)(uframe_p + sizeof(struct ethhdr));
		kr_log_verbose("[kxsk] frame len %d, ipv4 len %d\n",
				(int)desc->len, (int)BS16(ipv4->tot_len));
		// Any fragmentation stuff is bad for use, except for the DF flag
		if (ipv4->version != 4 || (ipv4->frag_off & ~(1 << 14))) {
			kr_log_info("[kxsk] weird IPv4 received: "
					"version %d, frag_off %d\n",
					(int)ipv4->version, (int)ipv4->frag_off);
			goto free_frame;
		}
		if (ipv4->protocol != 0x11) // UDP
			goto free_frame;
		// FIXME ipv4->check (sensitive to ipv4->ihl), ipv4->tot_len, udp->len
		udp = (struct udphdr *)(uframe_p + sizeof(struct ethhdr) + ipv4->ihl * 4);

	} else if (eth->h_proto == BS16(ETH_P_IPV6)) {
		(void)ipv6;
		goto free_frame; // TODO

	} else {
		kr_log_verbose("[kxsk] frame with unknown h_proto %d (ignored)\n",
				(int)BS16(eth->h_proto));
		goto free_frame;
	}

	assert(eth && (!!ipv4 != !!ipv6) && udp);
	uint8_t *udp_data = (uint8_t *)udp + sizeof(struct udphdr);
	const uint16_t udp_data_len = BS16(udp->len) - sizeof(struct udphdr);

	// process the packet; ownership is passed on, but beware of holding frames
	// LATER: filter the address-port combinations that we listen on?

	union inaddr sa_peer;
	if (ipv4) {
		sa_peer.ip4.sin_family = AF_INET;
		sa_peer.ip4.sin_port = udp->source;
		memcpy(&sa_peer.ip4.sin_addr, &ipv4->saddr, sizeof(ipv4->saddr));
	} else {
		sa_peer.ip6.sin6_family = AF_INET6;
		sa_peer.ip6.sin6_port = udp->source;
		memcpy(&sa_peer.ip6.sin6_addr, &ipv6->saddr, sizeof(ipv6->saddr));
		//sa_peer.ip6.sin6_scope_id = the_config->xsk_if_queue;
		//sin6_flowinfo: probably completely useless here
	}

	knot_pkt_t *kpkt = knot_pkt_new(udp_data, udp_data_len, &the_worker->pkt_pool);
	int ret = kpkt == NULL ? kr_error(ENOMEM) :
		worker_submit(xsi->session, &sa_peer.ip, (const uint8_t (*)[6])eth, kpkt);
	if (ret)
		kr_log_verbose("[kxsk] worker_submit() == %d: %s\n", ret, kr_strerror(ret));
	mp_flush(the_worker->pkt_pool.ctx);

	return;

free_frame:
	xsk_dealloc_umem_frame(xsi->umem, uframe_p);
}
// TODO: probably split up into generic part and kresd+UV part.
void kxsk_rx(uv_poll_t* handle, int status, int events)
{
	if (status < 0) {
		kr_log_error("[kxsk] poll status %d: %s\n", status, uv_strerror(status));
		return;
	}
	if (events != UV_READABLE) {
		kr_log_error("[kxsk] poll unexpected events: %d\n", events);
		return;
	}

	struct xsk_socket_info *xsi = handle->data;
	assert(xsi == the_socket); // for now

	uint32_t idx_rx;
	const size_t rcvd = xsk_ring_cons__peek(&xsi->rx, RX_BATCH_SIZE, &idx_rx);
	kr_log_verbose("[kxsk] poll triggered, processing a batch of %d packets\n",
			(int)rcvd);
	if (!rcvd)
		return;
	for (int i = 0; i < rcvd; ++i, ++idx_rx) {
		rx_desc(xsi, xsk_ring_cons__rx_desc(&xsi->rx, idx_rx));
	}
	xsk_ring_cons__release(&xsi->rx, rcvd);
}


static struct config the_config_storage = { // static to get zeroed by default
	.xsk_if_queue = 0, // defaults overridable by command-line -x eth3:0
	.umem_frame_count = 8192,
	.umem = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = FRAME_SIZE, // we need to know this value explicitly
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
	},
	.xsk = {
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
	},
	.pkt_template = {
		.eth = {
			//.h_dest   = "\xd8\x58\xd7\x00\x74\x34",
			//.h_source = "\x70\x85\xc2\x3a\xc7\x84",
			// mirkwood -> knot-bench-player:
			.h_dest   = "\xa0\x36\x9f\x50\x2a\x9c",
			.h_source = "\x3c\xfd\xfe\x2b\xcf\x02",
			// doriath -> eriador
			//.h_dest   = "\x00\x15\x17\xf8\xd0\x4a",
			//.h_source = "\xf0\x1f\xaf\xe2\x80\x0d",
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
			.ttl = IPDEFTTL,
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

int kr_xsk_init_global(uv_loop_t *loop, char *cmdarg)
{
	kxsk_alloc_hack = kr_xsk_alloc_wire;
	if (!cmdarg)
		return 0;

	/* Hard-coded configuration */
	const char
		//sip_str[] = "192.168.8.71",
		//dip_str[] = "192.168.8.1";
		sip_str[] = "192.168.100.8",
		dip_str[] = "192.168.100.3";
		//sip_str[] = "217.31.193.167",
		//dip_str[] = "217.31.193.166";
	the_config = &the_config_storage;
	if (inet_pton(AF_INET, sip_str, &the_config->pkt_template.ipv4.saddr) != 1
	    || inet_pton(AF_INET, dip_str, &the_config->pkt_template.ipv4.daddr) != 1) {
		fprintf(stderr, "ERROR: failed to convert IPv4 address\n");
		exit(EXIT_FAILURE);
	}

	char *colon = strchr(cmdarg, ':');
	if (colon) {
		*colon = '\0'; // yes, modifying argv[i][j] isn't very nice
		the_config->xsk_if_queue = atoi(colon + 1);
	}
	struct kxsk_iface *iface = kxsk_iface_new(cmdarg,
		"./bpf-kernel.o" // FIXME: proper installation, etc.
	);
	if (!iface) {
		fprintf(stderr, "ERROR: Can't set up network interface %s: %s\n",
			cmdarg, strerror(errno));
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
	struct xsk_umem_info *umem =
		configure_xsk_umem(&the_config->umem, the_config->umem_frame_count);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	assert(!the_socket);

	the_socket = xsk_configure_socket(the_config, umem, iface);
	if (!the_socket) {
		fprintf(stderr, "ERROR, can't setup AF_XDP socket on %s:%d: %s\n",
			iface->ifname, the_config->xsk_if_queue, strerror(errno));
		exit(EXIT_FAILURE);
	}

	int ret = kxsk_socket_start(iface, the_config->xsk_if_queue, the_socket->xsk);
	if (ret) {
		fprintf(stderr, "ERROR, can't start listening on AF_XDP socket on %s:%d: %s\n",
			iface->ifname, the_config->xsk_if_queue, strerror(ret));
		exit(EXIT_FAILURE);
	}

	kr_log_verbose("[uxsk] busy frames: %d\n",
			the_socket->umem->frame_count - the_socket->umem->free_count);


	ret = uv_check_init(loop, &the_socket->check_handle);
	if (!ret) ret = uv_check_start(&the_socket->check_handle, xsk_check);

	if (!ret) ret = uv_poll_init(loop, &the_socket->poll_handle,
					xsk_socket__fd(the_socket->xsk));
	if (!ret) {
		// beware: this sets poll_handle->data
		struct session *s = the_socket->session =
			session_new((uv_handle_t *)&the_socket->poll_handle, false);
		assert(!session_flags(s)->outgoing);

		// TMP: because worker will pass this back as source address to us
		struct sockaddr_in *ssa = (struct sockaddr_in *)session_get_sockname(s);
		ssa->sin_family = AF_INET;
		memcpy(&ssa->sin_addr, &the_config->pkt_template.ipv4.saddr,
				sizeof(ssa->sin_addr));
		ssa->sin_port = the_config->pkt_template.udp.source;

		ret = s ? 0 : kr_error(ENOMEM);
	}
	if (!ret) {
		the_socket->poll_handle.data = the_socket;
		ret = uv_poll_start(&the_socket->poll_handle, UV_READABLE, kxsk_rx);
	}
	return ret;
}

#define SOL_XDP 283
static void print_stats(struct xsk_socket *xsk)
{
	struct xdp_statistics stats;
	socklen_t optlen = sizeof(stats);
	if (getsockopt(xsk_socket__fd(xsk), SOL_XDP, XDP_STATISTICS, &stats, &optlen)) {
		fprintf(stderr, "getsockopt: %s\n", strerror(errno));
	} else {
		fprintf(stderr, "stats: RX drop %d, RX ID %d, TX ID %d\n",
			(int)stats.rx_dropped, (int)stats.rx_invalid_descs,
			(int)stats.tx_invalid_descs);
	}
}

