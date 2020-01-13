
#pragma once

#include <libknot/xdp/bpf-user.h> // TMP?

struct config {
	int xsk_if_queue;
	int port;
	struct udpv4 pkt_template;
};


