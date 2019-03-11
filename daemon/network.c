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
	uv_ ## type ## _init_ex((loop), (uv_ ## type ## _t *)(handle), (family)); \
	uv_os_fd_t hi_fd = 0; \
	if (uv_fileno((handle), &hi_fd) == 0) { \
		int hi_on = 1; \
		int hi_ret = setsockopt(hi_fd, SOL_SOCKET, SO_REUSEPORT, &hi_on, sizeof(hi_on)); \
		if (hi_ret) { \
			return hi_ret; \
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

void network_init(struct network *net, uv_loop_t *loop, int tcp_backlog)
{
	if (net != NULL) {
		net->loop = loop;
		net->endpoints = map_make(NULL);
		net->tls_client_params = NULL;
		net->tls_session_ticket_ctx = /* unsync. random, by default */
		tls_session_ticket_ctx_create(loop, NULL, 0);
		net->tcp.in_idle_timeout = 10000;
		net->tcp.tls_handshake_timeout = TLS_MAX_HANDSHAKE_TIME;
		net->tcp_backlog = tcp_backlog;
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
	if (ep->handle) {
		close_handle(ep->handle, force);
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
		tls_client_params_free(net->tls_client_params);
		tls_session_ticket_ctx_destroy(net->tls_session_ticket_ctx);
		#ifndef NDEBUG
			memset(net, 0, sizeof(*net));
		#endif
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

/** Open endpoint protocols.  ep->flags were pre-set. */
static int open_endpoint(struct network *net, struct endpoint *ep,
			 const struct sockaddr *sa, int fd)
{
	if ((sa != NULL) == (fd != -1)) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
	if (ep->handle) {
		return kr_error(EEXIST);
	}

	if (ep->flags & NET_UDP) {
		if (ep->flags & (NET_TCP | NET_TLS)) {
			assert(!EINVAL);
			return kr_error(EINVAL);
		}
		uv_udp_t *ep_handle = calloc(1, sizeof(uv_udp_t));
		ep->handle = (uv_handle_t *)ep_handle;
		if (!ep->handle) {
			return kr_error(ENOMEM);
		}
		if (sa) {
			handle_init(udp, net->loop, ep->handle, sa->sa_family);
				/*^^ can return! */
			return udp_bind(ep_handle, sa);
		} else {
			int ret = uv_udp_init(net->loop, ep_handle);
			if (ret == 0) {
				ret = udp_bindfd(ep_handle, fd);
			}
			return ret;
		}
	} /* else */

	if (ep->flags & NET_TCP) {
		uv_tcp_t *ep_handle = calloc(1, sizeof(uv_tcp_t));
		ep->handle = (uv_handle_t *)ep_handle;
		if (!ep->handle) {
			return kr_error(ENOMEM);
		}
		if (sa) {
			handle_init(tcp, net->loop, ep->handle, sa->sa_family); /* can return! */
		} else {
			int ret = uv_tcp_init(net->loop, ep_handle);
			if (ret) {
				return ret;
			}
		}
		if (ep->flags & NET_TLS) {
			return sa
				? tcp_bind_tls  (ep_handle, sa, net->tcp_backlog)
				: tcp_bindfd_tls(ep_handle, fd, net->tcp_backlog);
		} else {
			return sa
				? tcp_bind  (ep_handle, sa, net->tcp_backlog)
				: tcp_bindfd(ep_handle, fd, net->tcp_backlog);
		}
	} /* else */

	assert(!EINVAL);
	return kr_error(EINVAL);
}

/** @internal Fetch endpoint array and offset of the address/port query. */
static endpoint_array_t *network_get(struct network *net, const char *addr, uint16_t port,
					uint16_t flags, size_t *index)
{
	endpoint_array_t *ep_array = map_get(&net->endpoints, addr);
	if (ep_array) {
		for (size_t i = ep_array->len; i--;) {
			struct endpoint *ep = ep_array->at[i];
			if (ep->port == port && ep->flags == flags) {
				*index = i;
				return ep_array;
			}
		}
	}
	return NULL;
}

/** \note pass either sa != NULL xor fd != -1 */
static int create_endpoint(struct network *net, const char *addr_str,
				uint16_t port, uint16_t flags,
				const struct sockaddr *sa, int fd)
{
	/* Bind interfaces */
	struct endpoint *ep = calloc(1, sizeof(*ep));
	if (!ep) {
		return kr_error(ENOMEM);
	}
	ep->flags = flags;
	ep->port = port;
	int ret = open_endpoint(net, ep, sa, fd);
	if (ret == 0) {
		ret = insert_endpoint(net, addr_str, ep);
	}
	if (ret != 0) {
		close_endpoint(ep, false);
	}
	return ret;
}

int network_listen_fd(struct network *net, int fd, bool use_tls)
{
	/* Extract fd's socket type. */
	int sock_type = SOCK_DGRAM;
	socklen_t len = sizeof(sock_type);
	int ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &len);
	if (ret != 0) {
		return kr_error(EBADF);
	}
	uint16_t flags;
	if (sock_type == SOCK_DGRAM) {
		flags = NET_UDP;
		if (use_tls) {
			assert(!EINVAL);
			return kr_error(EINVAL);
		}
	} else if (sock_type == SOCK_STREAM) {
		flags = NET_TCP;
		if (use_tls) {
			flags |= NET_TLS;
		}
	} else {
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
	return create_endpoint(net, addr_str, port, flags, NULL, fd);
}

int network_listen(struct network *net, const char *addr, uint16_t port, uint16_t flags)
{
	if (net == NULL || addr == 0 || port == 0) {
		return kr_error(EINVAL);
	}

	/* Already listening */
	size_t index = 0;
	if (network_get(net, addr, port, flags, &index)) {
		return kr_ok();
	}

	/* Parse address. */
	int ret = 0;
	union inaddr sa;
	if (strchr(addr, ':') != NULL) {
		ret = uv_ip6_addr(addr, port, &sa.ip6);
	} else {
		ret = uv_ip4_addr(addr, port, &sa.ip4);
	}
	if (ret != 0) {
		return ret;
	}

	if ((flags & NET_UDP) && (flags & NET_TCP)) {
		/* We accept  ^^ this shorthand at this API layer. */
		ret = create_endpoint(net, addr, port, flags & ~NET_TCP, &sa.ip, -1);
		if (ret == 0) {
			ret = create_endpoint(net, addr, port, flags & ~NET_UDP, &sa.ip, -1);
		}
	} else {
		ret = create_endpoint(net, addr, port, flags, &sa.ip, -1);
	}

	return ret;
}

int network_close(struct network *net, const char *addr, uint16_t port, uint16_t flags)
{
	endpoint_array_t *ep_array = map_get(&net->endpoints, addr);
	if (!ep_array) {
		return kr_error(ENOENT);
	}

	size_t i = 0;
	bool matched = false;
	while (i < ep_array->len) {
		struct endpoint *ep = ep_array->at[i];
		if (!flags || flags == ep->flags) {
			close_endpoint(ep, false);
			array_del(*ep_array, i);
			matched = true;
			/* do not advance i */
		} else {
			++i;
		}
	}
	if (!matched) {
		return kr_error(ENOENT);
	}

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

#ifdef SO_ATTACH_BPF
static int set_bpf_cb(const char *key, void *val, void *ext)
{
	endpoint_array_t *endpoints = (endpoint_array_t *)val;
	assert(endpoints != NULL);
	int *bpffd = (int *)ext;
	assert(bpffd != NULL);

	for (size_t i = 0; i < endpoints->len; i++) {
		struct endpoint *endpoint = endpoints->at[i];
		uv_os_fd_t sockfd = -1;
		if (endpoint->handle != NULL)
			uv_fileno(endpoint->handle, &sockfd);
		assert(sockfd != -1);

		if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_BPF, bpffd, sizeof(int)) != 0) {
			return 1; /* return error (and stop iterating over net->endpoints) */
		}
	}
	return 0; /* OK */
}
#endif

int network_set_bpf(struct network *net, int bpf_fd)
{
#ifdef SO_ATTACH_BPF
	if (map_walk(&net->endpoints, set_bpf_cb, &bpf_fd) != 0) {
		/* set_bpf_cb() has returned error. */
		network_clear_bpf(net);
		return 0;
	}
#else
	kr_log_error("[network] SO_ATTACH_BPF socket option doesn't supported\n");
	(void)net;
	(void)bpf_fd;
	return 0;
#endif
	return 1;
}

#ifdef SO_DETACH_BPF
static int clear_bpf_cb(const char *key, void *val, void *ext)
{
	endpoint_array_t *endpoints = (endpoint_array_t *)val;
	assert(endpoints != NULL);

	for (size_t i = 0; i < endpoints->len; i++) {
		struct endpoint *endpoint = endpoints->at[i];
		uv_os_fd_t sockfd = -1;
		if (endpoint->handle != NULL)
			uv_fileno(endpoint->handle, &sockfd);
		assert(sockfd != -1);

		if (setsockopt(sockfd, SOL_SOCKET, SO_DETACH_BPF, NULL, 0) != 0) {
			kr_log_error("[network] failed to clear SO_DETACH_BPF socket option\n");
		}
		/* Proceed even if setsockopt() failed,
		 * as we want to process all opened sockets. */
	}
	return 0;
}
#endif

void network_clear_bpf(struct network *net)
{
#ifdef SO_DETACH_BPF
	map_walk(&net->endpoints, clear_bpf_cb, NULL);
#else
	kr_log_error("[network] SO_DETACH_BPF socket option doesn't supported\n");
	(void)net;
#endif
}
