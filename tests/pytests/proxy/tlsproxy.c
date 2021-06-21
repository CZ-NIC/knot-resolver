/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include "tls-proxy.h"

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
	       " -k, --key=[path]       Path to key file (default: %" PRIu64 ").\n"
	       " -c, --close=[N]        Close connection to client after\n"
	       "                        every N ms (default: %li).\n"
	       " -f, --fail=[N]         Delay every Nth incoming connection by 10 sec,\n"
	       "                        0 disables delaying (default: 0).\n"
	       " -r, --rehandshake      Do TLS rehandshake after every 8 bytes\n"
	       "                        sent to the client (default: no).\n"
	       " -a, --acceptonly       Accept incoming connections, but don't\n"
	       "                        connect to upstream (default: no).\n"
	       " -v, --tls13            Force use of TLSv1.3. If not turned on,\n"
	       "                        TLSv1.2 will be used (default: no).\n"
	       ,
	       a->local_addr, a->local_port,
	       a->upstream, a->upstream_port,
	       a->cert_file, a->key_file,
	       a->close_timeout);
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
	a->accept_only = false;
	a->tls_13 = false;
	a->close_connection = false;
	a->close_timeout = 1000;
	a->max_conn_sequence = 0; /* disabled */
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
		{"fail",        required_argument, 0, 'f'},
		{"rehandshake", no_argument, 0, 'r'},
		{"acceptonly",  no_argument, 0, 'a'},
#if GNUTLS_VERSION_NUMBER >= 0x030604
		{"tls13",       no_argument, 0, 'v'},
#endif
		{0, 0, 0, 0}
	};
	struct args args;
	init_args(&args);
	while ((c = getopt_long(argc, argv, "l:p:u:d:t:k:c:f:rav", opts, &li)) != -1) {
		switch (c)
		{
		case 'l':
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
		case 'f':
			li_value = strtol(optarg, NULL, 10);
			if (li_value <= 0 || li_value > UINT32_MAX) {
				printf("error: '-f' requires a positive"
						" number less or equal to %i, not '%s'\n",
					        UINT32_MAX, optarg);
				return -1;
			}
			args.max_conn_sequence = (uint32_t)li_value;
			break;
		case 'r':
			args.rehandshake = true;
			break;
		case 'a':
			args.accept_only = true;
			break;
		case 'v':
#if GNUTLS_VERSION_NUMBER >= 0x030604
			args.tls_13 = true;
#endif
			break;
		default:
			init_args(&args);
			help(argv, &args);
			return -1;
		}
	}
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "failed to set up SIGPIPE handler to ignore(%s)\n",
				strerror(errno));
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
	fprintf(stdout, "Listen on                     %s#%u\n"
			"Upstream is expected on       %s#%u\n"
			"Certificate file              %s\n"
			"Key file                      %s\n"
			"Rehandshake                   %s\n"
			"Close                         %s\n"
			"Refuse incoming connections   every %ith%s\n"
			"Only accept, don't forward    %s\n"
			"Force TLSv1.3                 %s\n"
		        ,
			args.local_addr, args.local_port,
			args.upstream, args.upstream_port,
			args.cert_file, args.key_file,
			args.rehandshake ? "yes" : "no",
			args.close_connection ? "yes" : "no",
			args.max_conn_sequence, args.max_conn_sequence ? "" : " (disabled)",
			args.accept_only ? "yes" : "no",
#if GNUTLS_VERSION_NUMBER >= 0x030604
			args.tls_13 ? "yes" : "no"
#else
			"Not supported"
#endif
		);
	res = tls_proxy_run(proxy);
	tls_proxy_free(proxy);
	return res;
}

