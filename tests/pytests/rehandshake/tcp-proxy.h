#pragma once

struct proxy_ctx;

struct proxy_ctx *proxy_allocate();
void proxy_free(struct proxy_ctx *proxy);
int proxy_init(struct proxy_ctx *proxy,
	       const char *server_addr, int server_port,
	       const char *upstream_addr, int upstream_port);
int proxy_start_listen(struct proxy_ctx *proxy);
int proxy_run(struct proxy_ctx *proxy);

