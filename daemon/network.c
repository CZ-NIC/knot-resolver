/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <assert.h>
#include "daemon/network.h"
#include "daemon/worker.h"
#include "daemon/io.h"
#include "daemon/tls.h"

/* libuv 1.7.0+ is able to support SO_REUSEPORT for loadbalancing */
#if defined(UV_VERSION_HEX)
#if (__linux__ && SO_REUSEPORT)
  #define handle_init(type, loop, handle, family) do { \
	uv_ ## type ## _init_ex((loop), (handle), (family)); \
	uv_os_fd_t fd = 0; \
	if (uv_fileno((uv_handle_t *)(handle), &fd) == 0) { \
		int on = 1; \
		int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)); \
		if (ret) { \
			return ret; \
		} \
	} \
  } while (0)
/* libuv 1.7.0+ is able to assign fd immediately */
#else
  #define handle_init(type, loop, handle, family) do { \
	uv_ ## type ## _init_ex((loop), (handle), (family)); \
  } while (0)
#endif
#else
  #define handle_init(type, loop, handle, family) \
	uv_ ## type ## _init((loop), (handle))
#endif

void network_init(struct network *net, uv_loop_t *loop)
{
	if (net != NULL) {
		net->loop = loop;
		net->endpoints = map_make(NULL);
		net->tls_client_params = map_make(NULL);
	}
}

static void close_handle(uv_handle_t *handle, bool force)
{
	if (force) { /* Force close if event loop isn't running. */
		uv_os_fd_t fd = 0;
		if (uv_fileno(handle, &fd) == 0) {
			close(fd);
		}
		handle->loop = NULL;
		io_free(handle);
	} else { /* Asynchronous close */
		uv_close(handle, io_free);
	}
}

static int close_endpoint(struct endpoint *ep, bool force)
{
	if (ep->udp) {
		close_handle((uv_handle_t *)ep->udp, force);
	}
	if (ep->tcp) {
		close_handle((uv_handle_t *)ep->tcp, force);
	}

	free(ep);
	return kr_ok();
}

/** Endpoint visitor (see @file map.h) */
static int close_key(const char *key, void *val, void *ext)
{
	endpoint_array_t *ep_array = val;
	for (size_t i = ep_array->len; i--;) {
		close_endpoint(ep_array->at[i], true);
	}
	return 0;
}

static int free_key(const char *key, void *val, void *ext)
{
	endpoint_array_t *ep_array = val;
	array_clear(*ep_array);
	free(ep_array);
	return kr_ok();
}

void network_deinit(struct network *net)
{
	if (net != NULL) {
		map_walk(&net->endpoints, close_key, 0);
		map_walk(&net->endpoints, free_key, 0);
		map_clear(&net->endpoints);
		tls_credentials_free(net->tls_credentials);
		tls_client_params_free(&net->tls_client_params);
		net->tls_credentials = NULL;
	}
}

/** Fetch or create endpoint array and insert endpoint. */
static int insert_endpoint(struct network *net, const char *addr, struct endpoint *ep)
{
	/* Fetch or insert address into map */
	endpoint_array_t *ep_array = map_get(&net->endpoints, addr);
	if (ep_array == NULL) {
		ep_array = malloc(sizeof(*ep_array));
		if (ep_array == NULL) {
			return kr_error(ENOMEM);
		}
		if (map_set(&net->endpoints, addr, ep_array) != 0) {
			free(ep_array);
			return kr_error(ENOMEM);
		}
		array_init(*ep_array);
	}

	if (array_push(*ep_array, ep) < 0) {
		return kr_error(ENOMEM);
	}
	return kr_ok();
}

/** Open endpoint protocols. */
static int open_endpoint(struct network *net, struct endpoint *ep, struct sockaddr *sa, uint32_t flags)
{
	int ret = 0;
	if (flags & NET_UDP) {
		ep->udp = malloc(sizeof(*ep->udp));
		if (!ep->udp) {
			return kr_error(ENOMEM);
		}
		memset(ep->udp, 0, sizeof(*ep->udp));
		handle_init(udp, net->loop, ep->udp, sa->sa_family); /* can return! */
		ret = udp_bind(ep->udp, sa);
		if (ret != 0) {
			return ret;
		}
		ep->flags |= NET_UDP;
	}
	if (flags & NET_TCP) {
		ep->tcp = malloc(sizeof(*ep->tcp));
		if (!ep->tcp) {
			return kr_error(ENOMEM);
		}
		memset(ep->tcp, 0, sizeof(*ep->tcp));
		handle_init(tcp, net->loop, ep->tcp, sa->sa_family); /* can return! */
		if (flags & NET_TLS) {
			ret = tcp_bind_tls(ep->tcp, sa);
			ep->flags |= NET_TLS;
		} else {
			ret = tcp_bind(ep->tcp, sa);
		}
		if (ret != 0) {
			return ret;
		}
		ep->flags |= NET_TCP;
	}
	return ret;
}

/** Open fd as endpoint. */
static int open_endpoint_fd(struct network *net, struct endpoint *ep, int fd, int sock_type, bool use_tls)
{
	int ret = kr_ok();
	if (sock_type == SOCK_DGRAM) {
		if (use_tls) {
			/* we do not support TLS over UDP */
			return kr_error(EBADF);
		}
		if (ep->udp) {
			return kr_error(EEXIST);
		}
		ep->udp = malloc(sizeof(*ep->udp));
		if (!ep->udp) {
			return kr_error(ENOMEM);
		}
		uv_udp_init(net->loop, ep->udp);
		ret = udp_bindfd(ep->udp, fd);
		if (ret != 0) {
			close_handle((uv_handle_t *)ep->udp, false);
			return ret;
		}
		ep->flags |= NET_UDP;
		return kr_ok();
	} else if (sock_type == SOCK_STREAM) {
		if (ep->tcp) {
			return kr_error(EEXIST);
		}
		ep->tcp = malloc(sizeof(*ep->tcp));
		if (!ep->tcp) {
			return kr_error(ENOMEM);
		}
		uv_tcp_init(net->loop, ep->tcp);
		if (use_tls) {
			ret = tcp_bindfd_tls(ep->tcp, fd);
			ep->flags |= NET_TLS;
		} else {
			ret = tcp_bindfd(ep->tcp, fd);
		}
		if (ret != 0) {
			close_handle((uv_handle_t *)ep->tcp, false);
			return ret;
		}
		ep->flags |= NET_TCP;
		return kr_ok();
	}
	return kr_error(EINVAL);
}

/** @internal Fetch endpoint array and offset of the address/port query. */
static endpoint_array_t *network_get(struct network *net, const char *addr, uint16_t port, size_t *index)
{
	endpoint_array_t *ep_array = map_get(&net->endpoints, addr);
	if (ep_array) {
		for (size_t i = ep_array->len; i--;) {
			struct endpoint *ep = ep_array->at[i];
			if (ep->port == port) {
				*index = i;
				return ep_array;
			}
		}
	}
	return NULL;
}

int network_listen_fd(struct network *net, int fd, bool use_tls)
{
	/* Extract local address and socket type. */
	int sock_type = SOCK_DGRAM;
	socklen_t len = sizeof(sock_type);
	int ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &len);	
	if (ret != 0) {
		return kr_error(EBADF);
	}
	/* Extract local address for this socket. */
	struct sockaddr_storage ss = { .ss_family = AF_UNSPEC };
	socklen_t addr_len = sizeof(ss);
	ret = getsockname(fd, (struct sockaddr *)&ss, &addr_len);
	if (ret != 0) {
		return kr_error(EBADF);
	}
	int port = 0;
	char addr_str[INET6_ADDRSTRLEN]; /* https://tools.ietf.org/html/rfc4291 */
	if (ss.ss_family == AF_INET) {
		uv_ip4_name((const struct sockaddr_in*)&ss, addr_str, sizeof(addr_str));
		port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
	} else if (ss.ss_family == AF_INET6) {
		uv_ip6_name((const struct sockaddr_in6*)&ss, addr_str, sizeof(addr_str));
		port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
	} else {
		return kr_error(EAFNOSUPPORT);
	}

	/* always create endpoint for supervisor supplied fd
	 * even if addr+port is not unique */
	struct endpoint *ep = malloc(sizeof(*ep));
	memset(ep, 0, sizeof(*ep));
	ep->flags = NET_DOWN;
	ep->port = port;
	ret = insert_endpoint(net, addr_str, ep);
	if (ret != 0) {
		return ret;
	}
	/* Create a libuv struct for this socket. */
	return open_endpoint_fd(net, ep, fd, sock_type, use_tls);
}

int network_listen(struct network *net, const char *addr, uint16_t port, uint32_t flags)
{
	if (net == NULL || addr == 0 || port == 0) {
		return kr_error(EINVAL);
	}

	/* Already listening */
	size_t index = 0;
	if (network_get(net, addr, port, &index)) {
		return kr_ok();
	}

	/* Parse address. */
	int ret = 0;
	struct sockaddr_storage sa;
	if (strchr(addr, ':') != NULL) {
		ret = uv_ip6_addr(addr, port, (struct sockaddr_in6 *)&sa);
	} else {
		ret = uv_ip4_addr(addr, port, (struct sockaddr_in *)&sa);
	}
	if (ret != 0) {
		return ret;
	}

	/* Bind interfaces */
	struct endpoint *ep = malloc(sizeof(*ep));
	memset(ep, 0, sizeof(*ep));
	ep->flags = NET_DOWN;
	ep->port = port;
	ret = open_endpoint(net, ep, (struct sockaddr *)&sa, flags);
	if (ret == 0) {
		ret = insert_endpoint(net, addr, ep);
	}
	if (ret != 0) {
		close_endpoint(ep, false);
	}

	return ret;
}

int network_close(struct network *net, const char *addr, uint16_t port)
{
	size_t index = 0;
	endpoint_array_t *ep_array = network_get(net, addr, port, &index);
	if (!ep_array) {
		return kr_error(ENOENT);
	}

	/* Close endpoint in array. */
	close_endpoint(ep_array->at[index], false);
	array_del(*ep_array, index);

	/* Collapse key if it has no endpoint. */
	if (ep_array->len == 0) {
		free(ep_array);
		map_del(&net->endpoints, addr);
	}

	return kr_ok();
}

void network_new_hostname(struct network *net, struct engine *engine)
{
	if (net->tls_credentials &&
	    net->tls_credentials->ephemeral_servicename) {
		struct tls_credentials *newcreds;
		newcreds = tls_get_ephemeral_credentials(engine);
		if (newcreds) {
			tls_credentials_release(net->tls_credentials);
			net->tls_credentials = newcreds;
			kr_log_info("[tls] Updated ephemeral X.509 cert with new hostname\n");
		} else {
			kr_log_error("[tls] Failed to update ephemeral X.509 cert with new hostname, using existing one\n");
		}
	}
}
