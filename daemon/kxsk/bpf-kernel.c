#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "parsing_helpers.h"

/** Assume netdev has no more than 64 queues
 * LATER: it might be better to detect this on startup time (per-device). */
#define QUEUE_MAX 64

/** A set entry here means that the corresponding queue_id
 * has an active AF_XDP socket bound to it. */
struct bpf_map_def SEC("maps") qidconf_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = QUEUE_MAX,
};
struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = QUEUE_MAX,
};

SEC("xdp_redirect_udp")
int xdp_redirect_udp_func(struct xdp_md *ctx)
{
	struct ethhdr *eth;
	struct iphdr *iphdr;
	//struct ipv6hdr *ipv6hdr;
	//struct udphdr *udphdr;

	void *data_end = (void *)(long)ctx->data_end;
	struct hdr_cursor nh = { .pos = (void *)(long)ctx->data };

	int ip_type;
	switch (parse_ethhdr(&nh, data_end, &eth)) {
		case ETH_P_IP:
			ip_type = parse_iphdr(&nh, data_end, &iphdr);
			break;
		/*
		case ETH_P_IPV6:
			ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
			break;
		*/
		default:
			return XDP_PASS;
	}

	if (ip_type != IPPROTO_UDP)
		return XDP_PASS;

	int index = ctx->rx_queue_index;
	int *qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
	if (!qidconf)
		return XDP_ABORTED;
	if (*qidconf)
		return bpf_redirect_map(&xsks_map, index, 0);
	return XDP_PASS;
}

