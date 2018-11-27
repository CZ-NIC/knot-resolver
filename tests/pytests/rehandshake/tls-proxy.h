#pragma once

struct tls_proxy_ctx;

struct tls_proxy_ctx *tls_proxy_allocate();
void tls_proxy_free(struct tls_proxy_ctx *proxy);
int tls_proxy_init(struct tls_proxy_ctx *proxy,
		   const char *server_addr, int server_port,
		   const char *upstream_addr, int upstream_port,
		   const char *cert_file, const char *key_file);
int tls_proxy_start_listen(struct tls_proxy_ctx *proxy);
int tls_proxy_run(struct tls_proxy_ctx *proxy);


