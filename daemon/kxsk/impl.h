
#pragma once

#include <bpf/xsk.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <uv.h> // LATER: split kresd-specific stuff

struct udpv4 {
	union { uint8_t bytes[1]; struct {

	struct ethhdr eth; // no VLAN support; CRC at the "end" of .data!
	struct iphdr ipv4;
	struct udphdr udp;
	uint8_t data[];

	} __attribute__((packed)); };
};

struct config {
	const char *ifname;
	int ifindex; /**< computed from ifname */
	int xsk_if_queue;
	const char *xdp_prog_filename;

	struct xsk_umem_config umem;
	uint32_t umem_frame_count;

	struct xsk_socket_config xsk;

	struct udpv4 pkt_template;
};

struct xsk_umem_info {
	/** Fill queue: passing memory frames to kernel - ready to receive. */
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
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	bool kernel_needs_wakeup;
	/* File-descriptors to BPF maps for the program running on the interface. */
	int qidconf_map_fd;
	int xsks_map_fd;

	/* kresd-specific stuff */
	uv_check_t check_handle;
	uv_poll_t poll_handle;
	struct session *session; /**< mock session, to minimize kresd changes for now */
};


/* eBPF stuff (user-space part), implemented in ./bpf-user.c */

/** Ensure the BPF program and maps are set up; return it's FD or error < 0.
 *
 * Note: if one is loaded on the interface already, we assume it's ours.
 * LATER: it might be possible to check, e.g. by naming our maps unusually.
 */
int kxsk_bpf_init(const struct config *cfg, struct xsk_socket_info *xsk_info);

/** Stop the BPF part, so packets should no longer come to the socket.
 *
 * Note: the program is not unloaded, but that only adds some overhead.
 * This way only the single interface queue is affected.
 */
int kxsk_bpf_deinit(const struct config *cfg, struct xsk_socket_info *xsk_info);

/** Forcefully unload BPF program from the interface.  (whole interface is affected) */
static inline int kxsk_bpf_unload(struct config *cfg)
{
	return bpf_set_link_xdp_fd(cfg->ifindex, -1, cfg->xsk.xdp_flags);
}

