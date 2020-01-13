
#pragma once

#include <stdint.h>
#include <uv.h>
#include <libknot/xdp/af_xdp.h>

int kr_xsk_init_global(uv_loop_t *loop, char *cmdarg);
void kr_xsk_deinit_global(void);

//void *kr_xsk_alloc_wire(uint16_t *maxlen);

struct sockaddr;
struct kr_request;
struct qr_task;
/** Send req->answer via UDP, possibly not immediately. */
void kr_xsk_push(const struct sockaddr *src, const struct sockaddr *dest,
		 struct kr_request *req, struct qr_task *task/*FIXME: remove*/, uint8_t eth_addrs[2][6]);

/** FIXME: temporary */
extern struct knot_xsk_socket *the_socket;

