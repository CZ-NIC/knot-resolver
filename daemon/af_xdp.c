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

#include "contrib/ucw/lib.h"
#include "contrib/ucw/mempool.h"

#include "lib/resolve.h"
#include "daemon/session.h"
#include "daemon/worker.h"

#include "daemon/kxsk/impl.h"

// placate libclang :-/
typedef uint64_t size_t;

#define RX_BATCH_SIZE 64

/** WIP: resources around a single AF_XDP socket. */
struct ts_aux {
	struct knot_xsk_socket *socket;
	struct session *session; /**< mock session, to minimize kresd changes for now */
	uv_check_t check_handle; /**< LATER(optim.): wasteful not to consolidate?
					Maybe we won't need this at all; we'll see. */
	uv_poll_t poll_handle;
};


// TODO: temporary section, to be replaced
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
struct udpv4 {
	union { uint8_t bytes[1]; struct {

	struct ethhdr eth; // no VLAN support; CRC at the "end" of .data!
	struct iphdr ipv4;
	struct udphdr udp;
	uint8_t data[];

	} __attribute__((packed)); };
};
struct config {
	int xsk_if_queue;
	int port;
	struct udpv4 pkt_template;
};


struct knot_xsk_socket *the_socket = NULL;
struct ts_aux *the_socket_aux = NULL;
struct config *the_config = NULL;

/** Swap two bytes as a *constant* expression.  ATM we assume we're LE, i.e. we do need to swap. */
#define BS16(n) (((n) >> 8) + (((n) & 0xff) << 8))

void kr_xsk_deinit_global(void)
{
	if (!the_socket)
		return;
	knot_xsk_deinit(the_socket);
	//TODO: more memory
}

static void kxsk_rx(uv_poll_t* handle, int status, int events)
{
	if (status < 0) {
		kr_log_error("[kxsk] poll status %d: %s\n", status, uv_strerror(status));
		return;
	}
	if (events != UV_READABLE) {
		kr_log_error("[kxsk] poll unexpected events: %d\n", events);
		return;
	}

	struct ts_aux *socket_aux = handle->data;
	assert(socket_aux == the_socket_aux && socket_aux->socket == the_socket); // for now
	uint32_t rcvd;
	knot_xsk_msg_t msgs[RX_BATCH_SIZE];
	int ret = knot_xsk_recvmmsg(socket_aux->socket, msgs, RX_BATCH_SIZE, &rcvd);
	if (ret == KNOT_EOK) {
		kr_log_verbose("[kxsk] poll triggered, processing a batch of %d packets\n",
			(int)rcvd);
	} else {
		kr_log_error("[kxsk] knot_xsk_recvmmsg(): %d, %s\n",
				ret, knot_strerror(ret));
	}
	assert(rcvd <= RX_BATCH_SIZE);
	for (int i = 0; i < rcvd; ++i) {
		const knot_xsk_msg_t *msg = &msgs[i];
		knot_pkt_t *kpkt = knot_pkt_new(msg->payload.iov_base, msg->payload.iov_len,
						&the_worker->pkt_pool);
		ret = kpkt == NULL ? kr_error(ENOMEM) :
			worker_submit(socket_aux->session, (const struct sockaddr *)&msg->ip_from,
					msg->eth_from, msg->eth_to, kpkt);
		if (ret)
			kr_log_verbose("[kxsk] worker_submit() == %d: %s\n", ret, kr_strerror(ret));
		mp_flush(the_worker->pkt_pool.ctx);
		knot_xsk_free_recvd(socket_aux->socket, msg);
	}
}

static struct config the_config_storage = { // static to get zeroed by default
	.xsk_if_queue = 0, // defaults overridable by command-line -x eth3:0
	.port = KR_DNS_PORT,
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
			.source = BS16(53),
			.dest   = BS16(53),
			.len    = BS16(0), // to be overwritten
			.check  = BS16(0), // checksum is optional
		},
	},
};
static struct ts_aux the_socket_aux_storage;

static void *kr_xsk_alloc_wire(uint16_t *maxlen)
{
	assert(maxlen);
	knot_xsk_msg_t out;
	int ret = knot_xsk_alloc_packet(the_socket, false, &out, NULL);
	if (ret != KNOT_EOK) {
		assert(!ret);
		return NULL;
	}
	*maxlen = out.payload.iov_len;
	return out.payload.iov_base;
}
static void xsk_check(uv_check_t *handle)
{
	int ret = knot_xsk_check(the_socket);
	if (ret != KNOT_EOK)
		kr_log_error("[kxsk] check: ret = %d, %s\n", ret, knot_strerror(ret));
}
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

	/* Start the AF_XDP socket (xsk) */
	assert(!the_socket);
	int ret = knot_xsk_init(&the_socket, cmdarg, the_config->xsk_if_queue,
				the_config->port, true);
	/*
	kr_log_verbose("[uxsk] busy frames: %d\n",
			the_socket->umem->frame_count - the_socket->umem->free_count);
	*/
	assert(!the_socket_aux);
	the_socket_aux = &the_socket_aux_storage;
	the_socket_aux->socket = the_socket;

	ret = uv_check_init(loop, &the_socket_aux->check_handle);
	if (!ret) ret = uv_check_start(&the_socket_aux->check_handle, xsk_check);

	if (!ret) ret = uv_poll_init(loop, &the_socket_aux->poll_handle,
					knot_xsk_get_poll_fd(the_socket));
	if (!ret) {
		// beware: this sets poll_handle->data
		struct session *s = the_socket_aux->session =
			session_new((uv_handle_t *)&the_socket_aux->poll_handle, false);
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
		the_socket_aux->poll_handle.data = the_socket_aux;
		ret = uv_poll_start(&the_socket_aux->poll_handle, UV_READABLE, kxsk_rx);
	}
	return ret;
}

