#pragma once
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

struct args {
	const char *local_addr;
	uint16_t local_port;
	const char *upstream;
	uint16_t upstream_port;

	bool rehandshake;
	bool close_connection;
	bool accept_only;
	bool tls_13;

	uint64_t close_timeout;
	uint32_t max_conn_sequence;

	const char *cert_file;
	const char *key_file;
};

struct tls_proxy_ctx;

struct tls_proxy_ctx *tls_proxy_allocate();
void tls_proxy_free(struct tls_proxy_ctx *proxy);
int tls_proxy_init(struct tls_proxy_ctx *proxy, const struct args *a);
int tls_proxy_start_listen(struct tls_proxy_ctx *proxy);
int tls_proxy_run(struct tls_proxy_ctx *proxy);
