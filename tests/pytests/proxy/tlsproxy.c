#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include "tls-proxy.h"
#include <gnutls/gnutls.h>

static char default_local_addr[] = "127.0.0.1";
static char default_upstream_addr[] = "127.0.0.1";
static char default_cert_path[] = "../certs/tt.cert.pem";
static char default_key_path[] = "../certs/tt.key.pem";

void help(char *argv[], struct args *a)
{
	printf("Usage: %s [parameters] [rundir]\n", argv[0]);
	printf("\nParameters:\n"
	       " -l, --local=[addr]     Server address to bind to (default: %s).\n"
	       " -p, --lport=[port]     Server port to bind to (default: %u).\n"
	       " -u, --upstream=[addr]  Upstream address (default: %s).\n"
	       " -d, --uport=[port]     Upstream port (default: %u).\n"
	       " -t, --cert=[path]      Path to certificate file (default: %s).\n"
	       " -k, --key=[path]       Path to key file (default: %s).\n"
	       " -c, --close=[N]        Close connection to client after every N ms (default: no).\n"
	       " -r, --rehandshake      Do TLS rehandshake after every 8 bytes sent to client (default: no).\n",
	       a->local_addr, a->local_port,
	       a->upstream, a->upstream_port,
	       a->cert_file, a->key_file
	);
}

void init_args(struct args *a)
{
	a->local_addr = default_local_addr;
	a->local_port = 54000;
	a->upstream = default_upstream_addr;
	a->upstream_port = 53000;
	a->cert_file = default_cert_path;
	a->key_file = default_key_path;
	a->rehandshake = false;
	a->close_connection = false;
}

int main(int argc, char **argv)
{
	long int li_value = 0;
	int c = 0, li = 0;
	struct option opts[] = {
		{"local",       required_argument, 0, 'l'},
		{"lport",       required_argument, 0, 'p'},
		{"upstream",    required_argument, 0, 'u'},
		{"uport",       required_argument, 0, 'd'},
		{"cert",        required_argument, 0, 't'},
		{"key",         required_argument, 0, 'k'},
		{"close",       required_argument, 0, 'c'},
		{"rehandshake", no_argument, 0, 'r'},
		{0, 0, 0, 0}
	};
	struct args args;
	init_args(&args);
	while ((c = getopt_long(argc, argv, "l:p:u:d:t:k:c:r", opts, &li)) != -1) {
		switch (c)
		{
		case 'a':
			args.local_addr = optarg;
			break;
		case 'u':
			args.upstream = optarg;
			break;
		case 't':
			args.cert_file = optarg;
			break;
		case 'k':
			args.key_file = optarg;
			break;
		case 'p':
			li_value = strtol(optarg, NULL, 10);
			if (li_value <= 0 || li_value > UINT16_MAX) {
				printf("error: '-p' requires a positive"
						" number less or equal to 65535, not '%s'\n", optarg);
				return -1;
			}
			args.local_port = (uint16_t)li_value;
			break;
		case 'd':
			li_value = strtol(optarg, NULL, 10);
			if (li_value <= 0 || li_value > UINT16_MAX) {
				printf("error: '-d' requires a positive"
						" number less or equal to 65535, not '%s'\n", optarg);
				return -1;
			}
			args.upstream_port = (uint16_t)li_value;
			break;
		case 'c':
			li_value = strtol(optarg, NULL, 10);
			if (li_value <= 0) {
				printf("[system] error '-c' requires a positive"
						" number, not '%s'\n", optarg);
				return -1;
			}
			args.close_connection = true;
			args.close_timeout = li_value;
			break;
		case 'r':
			args.rehandshake = true;
			break;
		default:
			init_args(&args);
			help(argv, &args);
			return -1;
		}
	}

	struct tls_proxy_ctx *proxy = tls_proxy_allocate();
	if (!proxy) {
		fprintf(stderr, "can't allocate tls_proxy structure\n");
		return 1;
	}
	int res = tls_proxy_init(proxy, &args);
	if (res) {
		fprintf(stderr, "can't initialize tls_proxy structure\n");
		return res;
	}
	res = tls_proxy_start_listen(proxy);
	if (res) {
		fprintf(stderr, "error starting listen, error code: %i\n", res);
		return res;
	}
	fprintf(stdout, "Listen on               %s#%u\n"
			"Upstream is expected on %s#%u\n"
			"Rehandshake             %s\n"
			"Close                   %s\n",
			args.local_addr, args.local_port,
			args.upstream, args.upstream_port,
			args.rehandshake ? "yes" : "no",
			args.close_connection ? "yes" : "no");
	res = tls_proxy_run(proxy);
	tls_proxy_free(proxy);
	return res;
}

