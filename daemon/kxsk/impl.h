
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


/** Data around one network interface. */
struct kxsk_iface {
	const char *ifname;
	int ifindex; /**< computed from ifname */

	/* File-descriptors to BPF maps for the program running on the interface. */
	int qidconf_map_fd;
	int xsks_map_fd;
};


struct config {
	int xsk_if_queue;

	struct xsk_umem_config umem; /**< For xsk_umem__create() from libbpf. */
	uint32_t umem_frame_count;

	struct xsk_socket_config xsk; /**< For xsk_socket__create() from libbpf. */

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
	/** Receive queue: passing arrived packets from kernel. */
	struct xsk_ring_cons rx;
	/** Transmit queue: passing packets to kernel for sending. */
	struct xsk_ring_prod tx;
	/** Information about memory frames for all the passed packets. */
	struct xsk_umem_info *umem;
	/** Handle internal to libbpf. */
	struct xsk_socket *xsk;

	bool kernel_needs_wakeup;

	const struct kxsk_iface *iface;

	/* kresd-specific stuff */
	uv_check_t check_handle;
	uv_poll_t poll_handle;
	struct session *session; /**< mock session, to minimize kresd changes for now */
};


/* eBPF stuff (user-space part), implemented in ./bpf-user.c */

/** Ensure the BPF program and maps are set up.  On failure return NULL + errno.
 *
 * Note: if one is loaded on the interface already, we assume it's ours.
 * LATER: it might be possible to check, e.g. by naming our maps unusually.
 */
struct kxsk_iface * kxsk_iface_new(const char *ifname, const char *prog_fname);

/** Undo kxsk_iface_new().  It's always freed, even if some problems happen.
 *
 * Unloading the BPF program is optional, as keeping it only adds some overhead,
 * and in case of multi-process it isn't easy to find that we're the last instance.
 */
int kxsk_iface_free(struct kxsk_iface *iface, bool unload_bpf);

/** Activate this AF_XDP socket through the BPF maps. */
int kxsk_socket_start(const struct kxsk_iface *iface, int queue_id, struct xsk_socket *xsk);

/** Deactivate this AF_XDP socket through the BPF maps. */
int kxsk_socket_stop(const struct kxsk_iface *iface, int queue_id);

