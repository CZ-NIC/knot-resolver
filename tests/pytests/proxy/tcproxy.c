#include <stdio.h>
#include "tcp-proxy.h"

int main()
{
	struct proxy_ctx *proxy = proxy_allocate();
	if (!proxy) {
		fprintf(stderr, "can't allocate proxy structure\n");
		return 1;
	}
	int res = proxy_init(proxy, "127.0.0.1", 54000, "127.0.0.1", 53001);
	if (res) {
		fprintf(stderr, "can't initialize proxy by given addresses\n");
		return res;
	}
	res = proxy_start_listen(proxy);
	if (res) {
		fprintf(stderr, "error starting listen, error code: %i\n", res);
		return res;
	}
	res = proxy_run(proxy);
	proxy_free(proxy);
	return res;
}

