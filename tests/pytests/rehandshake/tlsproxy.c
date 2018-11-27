#include <stdio.h>
#include "tls-proxy.h"
#include <gnutls/gnutls.h>

int main()
{
	struct tls_proxy_ctx *proxy = tls_proxy_allocate();
	if (!proxy) {
		fprintf(stderr, "can't allocate tls_proxy structure\n");
		return 1;
	}
	int res = tls_proxy_init(proxy,
				 "127.0.0.1", 53921, /* Address to listen */
				 "127.0.0.1", 53910, /* Upstream address */
				 "../certs/tt.cert.pem",
				 "../certs/tt.key.pem");
	if (res) {
		fprintf(stderr, "can't initialize tls_proxy structure\n");
		return res;
	}
	res = tls_proxy_start_listen(proxy);
	if (res) {
		fprintf(stderr, "error starting listen, error code: %i\n", res);
		return res;
	}
	fprintf(stdout, "started...\n");
	res = tls_proxy_run(proxy);
	tls_proxy_free(proxy);
	return res;
}

