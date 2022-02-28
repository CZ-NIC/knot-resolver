/*  Copyright (C) 2015-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/network.h"

#include "daemon/bindings/impl.h"
#include "daemon/io.h"
#include "daemon/tls.h"
#include "daemon/worker.h"

#if ENABLE_XDP
	#include <libknot/xdp/eth.h>
#endif

#include <libgen.h>
#include <net/if.h>
#include <sys/un.h>
#include <unistd.h>

void network_init(struct network *net, uv_loop_t *loop, int tcp_backlog)
{
	if (net != NULL) {
		net->loop = loop;
		net->endpoints = map_make(NULL);
		net->endpoint_kinds = trie_create(NULL);
		net->proxy_all4 = false;
		net->proxy_all6 = false;
		net->proxy_addrs4 = trie_create(NULL);
		net->proxy_addrs6 = trie_create(NULL);
		net->tls_client_params = NULL;
		net->tls_session_ticket_ctx = /* unsync. random, by default */
		tls_session_ticket_ctx_create(loop, NULL, 0);
		net->tcp.in_idle_timeout = 10000;
		net->tcp.tls_handshake_timeout = TLS_MAX_HANDSHAKE_TIME;
		net->tcp_backlog = tcp_backlog;
	}
}

/** Notify the registered function about endpoint getting open.
 * If log_port < 1, don't log it. */
static int endpoint_open_lua_cb(struct network *net, struct endpoint *ep,
				const char *log_addr)
{
	const bool ok = ep->flags.kind && !ep->handle && !ep->engaged && ep->fd != -1;
	if (kr_fails_assert(ok))
		return kr_error(EINVAL);
	/* First find callback in the endpoint registry. */
	lua_State *L = the_worker->engine->L;
	void **pp = trie_get_try(net->endpoint_kinds, ep->flags.kind,
				strlen(ep->flags.kind));
	if (!pp && net->missing_kind_is_error) {
		kr_log_error(NETWORK, "error: network socket kind '%s' not handled when opening '%s",
				ep->flags.kind, log_addr);
		if (ep->family != AF_UNIX)
			kr_log_error(NETWORK, "#%d", ep->port);
		kr_log_error(NETWORK, "'\n");
		return kr_error(ENOENT);
	}
	if (!pp) return kr_ok();

	/* Now execute the callback. */
	const int fun_id = (char *)*pp - (char *)NULL;
	lua_rawgeti(L, LUA_REGISTRYINDEX, fun_id);
	lua_pushboolean(L, true /* open */);
	lua_pushpointer(L, ep);
	if (ep->family == AF_UNIX) {
		lua_pushstring(L, log_addr);
	} else {
		lua_pushfstring(L, "%s#%d", log_addr, ep->port);
	}
	if (lua_pcall(L, 3, 0, 0)) {
		kr_log_error(NETWORK, "error opening %s: %s\n", log_addr, lua_tostring(L, -1));
		return kr_error(ENOSYS); /* TODO: better value? */
	}
	ep->engaged = true;
	return kr_ok();
}

static int engage_endpoint_array(const char *key, void *endpoints, void *net)
{
	endpoint_array_t *eps = (endpoint_array_t *)endpoints;
	for (int i = 0; i < eps->len; ++i) {
		struct endpoint *ep = &eps->at[i];
		const bool match = !ep->engaged && ep->flags.kind;
		if (!match) continue;
		int ret = endpoint_open_lua_cb(net, ep, key);
		if (ret) return ret;
	}
	return 0;
}
int network_engage_endpoints(struct network *net)
{
	if (net->missing_kind_is_error)
		return kr_ok(); /* maybe weird, but let's make it idempotent */
	net->missing_kind_is_error = true;
	int ret = map_walk(&net->endpoints, engage_endpoint_array, net);
	if (ret) {
		net->missing_kind_is_error = false; /* avoid the same errors when closing */
		return ret;
	}
	return kr_ok();
}


/** Notify the registered function about endpoint about to be closed. */
static void endpoint_close_lua_cb(struct network *net, struct endpoint *ep)
{
	lua_State *L = the_worker->engine->L;
	void **pp = trie_get_try(net->endpoint_kinds, ep->flags.kind,
				strlen(ep->flags.kind));
	if (!pp && net->missing_kind_is_error) {
		kr_log_error(NETWORK, "internal error: missing kind '%s' in endpoint registry\n",
				ep->flags.kind);
		return;
	}
	if (!pp) return;

	const int fun_id = (char *)*pp - (char *)NULL;
	lua_rawgeti(L, LUA_REGISTRYINDEX, fun_id);
	lua_pushboolean(L, false /* close */);
	lua_pushpointer(L, ep);
	lua_pushstring(L, "FIXME:endpoint-identifier");
	if (lua_pcall(L, 3, 0, 0)) {
		kr_log_error(NETWORK, "failed to close FIXME:endpoint-identifier: %s\n",
				lua_tostring(L, -1));
	}
}

static void endpoint_close(struct network *net, struct endpoint *ep, bool force)
{
	const bool is_control = ep->flags.kind && strcmp(ep->flags.kind, "control") == 0;
	const bool is_xdp     = ep->family == AF_XDP;

	if (ep->family == AF_UNIX) { /* The FS name would be left behind. */
		/* Extract local address for this socket. */
		struct sockaddr_un sa;
		sa.sun_path[0] = '\0'; /*< probably only for lint:scan-build */
		socklen_t addr_len = sizeof(sa);
		if (getsockname(ep->fd, (struct sockaddr *)&sa, &addr_len)
		    || unlink(sa.sun_path)) {
			kr_log_error(NETWORK, "error (ignored) when closing unix socket (fd = %d): %s\n",
					ep->fd, strerror(errno));
			return;
		}
	}

	if (ep->flags.kind && !is_control && !is_xdp) {
		kr_assert(!ep->handle);
		/* Special lua-handled endpoint. */
		if (ep->engaged) {
			endpoint_close_lua_cb(net, ep);
		}
		if (ep->fd > 0) {
			close(ep->fd); /* nothing to do with errors */
		}
		free_const(ep->flags.kind);
		return;
	}

	free_const(ep->flags.kind); /* needed if (is_control) */
	kr_require(ep->handle);
	if (force) { /* Force close if event loop isn't running. */
		if (ep->fd >= 0) {
			close(ep->fd);
		}
		if (ep->handle) {
			ep->handle->loop = NULL;
			io_free(ep->handle);
		}
	} else { /* Asynchronous close */
		uv_close(ep->handle, io_free);
	}
}

/** Endpoint visitor (see @file map.h) */
static int close_key(const char *key, void *val, void *net)
{
	endpoint_array_t *ep_array = val;
	for (int i = 0; i < ep_array->len; ++i) {
		endpoint_close(net, &ep_array->at[i], true);
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

int kind_unregister(trie_val_t *tv, void *L)
{
	int fun_id = (char *)*tv - (char *)NULL;
	luaL_unref(L, LUA_REGISTRYINDEX, fun_id);
	return 0;
}

void network_close_force(struct network *net)
{
	if (net != NULL) {
		map_walk(&net->endpoints, close_key, net);
		map_walk(&net->endpoints, free_key, 0);
		map_clear(&net->endpoints);
	}
}

/** Frees all the `struct net_proxy_data` in the specified trie. */
void network_proxy_free_addr_data(trie_t* trie)
{
	trie_it_t *it;
	for (it = trie_it_begin(trie); !trie_it_finished(it); trie_it_next(it)) {
		struct net_proxy_data *data = *trie_it_val(it);
		free(data);
	}
	trie_it_free(it);
}

void network_deinit(struct network *net)
{
	if (net != NULL) {
		network_close_force(net);
		trie_apply(net->endpoint_kinds, kind_unregister, the_worker->engine->L);
		trie_free(net->endpoint_kinds);
		network_proxy_free_addr_data(net->proxy_addrs4);
		trie_free(net->proxy_addrs4);
		network_proxy_free_addr_data(net->proxy_addrs6);
		trie_free(net->proxy_addrs6);

		tls_credentials_free(net->tls_credentials);
		tls_client_params_free(net->tls_client_params);
		tls_session_ticket_ctx_destroy(net->tls_session_ticket_ctx);
		#ifndef NDEBUG
			memset(net, 0, sizeof(*net));
		#endif
	}
}

/** Fetch or create endpoint array and insert endpoint (shallow memcpy). */
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

	if (array_reserve(*ep_array, ep_array->len + 1)) {
		return kr_error(ENOMEM);
	}
	memcpy(&ep_array->at[ep_array->len++], ep, sizeof(*ep));
	return kr_ok();
}

/** Open endpoint protocols.  ep->flags were pre-set.
 * \p addr_str is only used for logging or for XDP "address". */
static int open_endpoint(struct network *net, const char *addr_str,
			 struct endpoint *ep, const struct sockaddr *sa)
{
	const bool is_control = ep->flags.kind && strcmp(ep->flags.kind, "control") == 0;
	const bool is_xdp     = ep->family == AF_XDP;
	bool ok = is_xdp
		? sa == NULL && ep->fd == -1 && ep->nic_queue >= 0
			&& ep->flags.sock_type == SOCK_DGRAM && !ep->flags.tls
		: (sa != NULL) != (ep->fd != -1);
	if (kr_fails_assert(ok))
		return kr_error(EINVAL);
	if (ep->handle) {
		return kr_error(EEXIST);
	}

	if (sa) {
		if (sa->sa_family == AF_UNIX) {
			struct sockaddr_un *sun = (struct sockaddr_un*)sa;
			char *dirc = strdup(sun->sun_path);
			char *dname = dirname(dirc);
			(void)unlink(sun->sun_path);  /** Attempt to unlink if socket path exists. */
			(void)mkdir(dname, S_IRWXU|S_IRWXG);  /** Attempt to create dir. */
			free(dirc);
		}
		ep->fd = io_bind(sa, ep->flags.sock_type, &ep->flags);
		if (ep->fd < 0) return ep->fd;
	}
	if (ep->flags.kind && !is_control && !is_xdp) {
		/* This EP isn't to be managed internally after binding. */
		return endpoint_open_lua_cb(net, ep, addr_str);
	} else {
		ep->engaged = true;
		/* .engaged seems not really meaningful in this case, but... */
	}

	int ret;
	if (is_control) {
		uv_pipe_t *ep_handle = malloc(sizeof(uv_pipe_t));
		ep->handle = (uv_handle_t *)ep_handle;
		ret = !ep->handle ? ENOMEM
			: io_listen_pipe(net->loop, ep_handle, ep->fd);
		goto finish_ret;
	}

	if (ep->family == AF_UNIX) {
		/* Some parts of connection handling would need more work,
		 * so let's support AF_UNIX only with .kind != NULL for now. */
		kr_log_error(NETWORK, "AF_UNIX only supported with set { kind = '...' }\n");
		ret = EAFNOSUPPORT;
		goto finish_ret;
		/*
		uv_pipe_t *ep_handle = malloc(sizeof(uv_pipe_t));
		*/
	}

	if (is_xdp) {
	#if ENABLE_XDP
		uv_poll_t *ep_handle = malloc(sizeof(uv_poll_t));
		ep->handle = (uv_handle_t *)ep_handle;
		ret = !ep->handle ? ENOMEM
			: io_listen_xdp(net->loop, ep, addr_str);
	#else
		ret = ESOCKTNOSUPPORT;
	#endif
		goto finish_ret;
	} /* else */

	if (ep->flags.sock_type == SOCK_DGRAM) {
		if (kr_fails_assert(!ep->flags.tls))
			return kr_error(EINVAL);
		uv_udp_t *ep_handle = malloc(sizeof(uv_udp_t));
		ep->handle = (uv_handle_t *)ep_handle;
		ret = !ep->handle ? ENOMEM
			: io_listen_udp(net->loop, ep_handle, ep->fd);
		goto finish_ret;
	} /* else */

	if (ep->flags.sock_type == SOCK_STREAM) {
		uv_tcp_t *ep_handle = malloc(sizeof(uv_tcp_t));
		ep->handle = (uv_handle_t *)ep_handle;
		ret = !ep->handle ? ENOMEM
			: io_listen_tcp(net->loop, ep_handle, ep->fd,
					net->tcp_backlog, ep->flags.tls, ep->flags.http);
		goto finish_ret;
	} /* else */

	kr_assert(false);
	return kr_error(EINVAL);
finish_ret:
	if (!ret) return ret;
	free(ep->handle);
	ep->handle = NULL;
	return kr_error(ret);
}

/** @internal Fetch a pointer to endpoint of given parameters (or NULL).
 * Beware that there might be multiple matches, though that's not common.
 * The matching isn't really precise in the sense that it might not find
 * and endpoint that would *collide* the passed one. */
static struct endpoint * endpoint_get(struct network *net, const char *addr,
					uint16_t port, endpoint_flags_t flags)
{
	endpoint_array_t *ep_array = map_get(&net->endpoints, addr);
	if (!ep_array) {
		return NULL;
	}
	for (int i = 0; i < ep_array->len; ++i) {
		struct endpoint *ep = &ep_array->at[i];
		if (ep->port == port && endpoint_flags_eq(ep->flags, flags)) {
			return ep;
		}
	}
	return NULL;
}

/** \note pass (either sa != NULL xor ep.fd != -1) or XDP case (neither sa nor ep.fd)
 *  \note in XDP case addr_str is interface name
 *  \note ownership of ep.flags.* is taken on success. */
static int create_endpoint(struct network *net, const char *addr_str,
				struct endpoint *ep, const struct sockaddr *sa)
{
	int ret = open_endpoint(net, addr_str, ep, sa);
	if (ret == 0) {
		ret = insert_endpoint(net, addr_str, ep);
	}
	if (ret != 0 && ep->handle) {
		endpoint_close(net, ep, false);
	}
	return ret;
}

int network_listen_fd(struct network *net, int fd, endpoint_flags_t flags)
{
	if (kr_fails_assert(!flags.xdp))
		return kr_error(EINVAL);
	/* Extract fd's socket type. */
	socklen_t len = sizeof(flags.sock_type);
	int ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, &flags.sock_type, &len);
	if (ret != 0)
		return kr_error(errno);
	const bool is_dtls = flags.sock_type == SOCK_DGRAM && !flags.kind && flags.tls;
	if (kr_fails_assert(!is_dtls))
		return kr_error(EINVAL);  /* Perhaps DTLS some day. */
	if (flags.sock_type != SOCK_DGRAM && flags.sock_type != SOCK_STREAM)
		return kr_error(EBADF);

	/* Extract local address for this socket. */
	struct sockaddr_storage ss = { .ss_family = AF_UNSPEC };
	socklen_t addr_len = sizeof(ss);
	ret = getsockname(fd, (struct sockaddr *)&ss, &addr_len);
	if (ret != 0)
		return kr_error(errno);

	struct endpoint ep = {
		.flags = flags,
		.family = ss.ss_family,
		.fd = fd,
	};
	/* Extract address string and port. */
	char addr_buf[INET6_ADDRSTRLEN]; /* https://tools.ietf.org/html/rfc4291 */
	const char *addr_str;
	switch (ep.family) {
	case AF_INET:
		ret = uv_ip4_name((const struct sockaddr_in*)&ss, addr_buf, sizeof(addr_buf));
		addr_str = addr_buf;
		ep.port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
		break;
	case AF_INET6:
		ret = uv_ip6_name((const struct sockaddr_in6*)&ss, addr_buf, sizeof(addr_buf));
		addr_str = addr_buf;
		ep.port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
		break;
	case AF_UNIX:
		/* No SOCK_DGRAM with AF_UNIX support, at least for now. */
		ret = flags.sock_type == SOCK_STREAM ? kr_ok() : kr_error(EAFNOSUPPORT);
		addr_str = ((struct sockaddr_un *)&ss)->sun_path;
		break;
	default:
		ret = kr_error(EAFNOSUPPORT);
	}
	if (ret) return ret;

	/* always create endpoint for supervisor supplied fd
	 * even if addr+port is not unique */
	return create_endpoint(net, addr_str, &ep, NULL);
}

/** Try selecting XDP queue automatically. */
static int16_t nic_queue_auto(void)
{
	const char *inst_str = getenv("SYSTEMD_INSTANCE");
	if (!inst_str)
		return 0; // should work OK for simple (single-kresd) deployments
	char *endp;
	errno = 0; // strtol() is special in this respect
	long inst = strtol(inst_str, &endp, 10);
	if (!errno && *endp == '\0' && inst > 0 && inst < UINT16_MAX)
		return inst - 1; // 1-based vs. 0-based indexing conventions
	return -1;
}

int network_listen(struct network *net, const char *addr, uint16_t port,
		   int16_t nic_queue, endpoint_flags_t flags)
{
	if (kr_fails_assert(net != NULL && addr != 0 && nic_queue >= -1))
		return kr_error(EINVAL);

	if (flags.xdp && nic_queue < 0) {
		nic_queue = nic_queue_auto();
		if (nic_queue < 0) {
			return kr_error(EINVAL);
		}
	}

	// Try parsing the address.
	const struct sockaddr *sa = kr_straddr_socket(addr, port, NULL);
	if (!sa && !flags.xdp) { // unusable address spec
		return kr_error(EINVAL);
	}
	char ifname_buf[64] UNUSED;
	if (sa && flags.xdp) { // auto-detection: address -> interface
	#if ENABLE_XDP
		int ret = knot_eth_name_from_addr((const struct sockaddr_storage *)sa,
						  ifname_buf, sizeof(ifname_buf));
		// even on success we don't want to pass `sa` on
		free_const(sa);
		sa = NULL;
		if (ret) {
			return kr_error(ret);
		}
		addr = ifname_buf;
	#else
		return kr_error(ESOCKTNOSUPPORT);
	#endif
	}
	// XDP: if addr failed to parse as address, we assume it's an interface name.

	if (endpoint_get(net, addr, port, flags)) {
		return kr_error(EADDRINUSE); // Already listening
	}

	struct endpoint ep = { 0 };
	ep.flags = flags;
	ep.fd = -1;
	ep.port = port;
	ep.family = flags.xdp ? AF_XDP : sa->sa_family;
	ep.nic_queue = nic_queue;

	int ret = create_endpoint(net, addr, &ep, sa);

	// Error reporting: more precision.
	if (ret == KNOT_EINVAL && !sa && flags.xdp && ENABLE_XDP) {
		if (!if_nametoindex(addr) && errno == ENODEV) {
			ret = kr_error(ENODEV);
		}
	}

	free_const(sa);
	return ret;
}

int network_proxy_allow(struct network *net, const char* addr)
{
	if (kr_fails_assert(net != NULL && addr != NULL))
		return kr_error(EINVAL);

	int family = kr_straddr_family(addr);
	if (family < 0) {
		kr_log_error(NETWORK, "Wrong address format for proxy_allowed: %s\n",
				addr);
		return kr_error(EINVAL);
	} else if (family == AF_UNIX) {
		kr_log_error(NETWORK, "Unix sockets not supported for proxy_allowed: %s\n",
				addr);
		return kr_error(EINVAL);
	}

	union kr_in_addr ia;
	int netmask = kr_straddr_subnet(&ia, addr);
	if (netmask < 0) {
		kr_log_error(NETWORK, "Wrong netmask format for proxy_allowed: %s\n", addr);
		return kr_error(EINVAL);
	} else if (netmask == 0) {
		/* Netmask is zero: allow all addresses to use PROXYv2 */
		switch (family) {
		case AF_INET:
			net->proxy_all4 = true;
			break;
		case AF_INET6:
			net->proxy_all6 = true;
			break;
		default:
			kr_assert(false);
			return kr_error(EINVAL);
		}

		return kr_ok();
	}

	size_t addr_length;
	trie_t *trie;
	switch (family) {
	case AF_INET:
		addr_length = sizeof(ia.ip4);
		trie = net->proxy_addrs4;
		break;
	case AF_INET6:
		addr_length = sizeof(ia.ip6);
		trie = net->proxy_addrs6;
		break;
	default:
		kr_assert(false);
		return kr_error(EINVAL);
	}

	kr_bitmask((unsigned char *) &ia, addr_length, netmask);
	trie_val_t *val = trie_get_ins(trie, (char *) &ia, addr_length);
	if (!val)
		return kr_error(ENOMEM);

	struct net_proxy_data *data = *val;
	if (!data) {
		/* Allocate data if the entry is new in the trie */
		*val = malloc(sizeof(struct net_proxy_data));
		data = *val;
		data->netmask = 0;
	}

	if (data->netmask == 0) {
		memcpy(&data->addr, &ia, addr_length);
		data->netmask = netmask;
	} else if (data->netmask > netmask) {
		/* A more relaxed netmask configured - replace it */
		data->netmask = netmask;
	}

	return kr_ok();
}

void network_proxy_reset(struct network *net)
{
	net->proxy_all4 = false;
	network_proxy_free_addr_data(net->proxy_addrs4);
	trie_clear(net->proxy_addrs4);
	net->proxy_all6 = false;
	network_proxy_free_addr_data(net->proxy_addrs6);
	trie_clear(net->proxy_addrs6);
}

int network_close(struct network *net, const char *addr, int port)
{
	endpoint_array_t *ep_array = map_get(&net->endpoints, addr);
	if (!ep_array) {
		return kr_error(ENOENT);
	}

	size_t i = 0;
	bool matched = false; /*< at least one match */
	while (i < ep_array->len) {
		struct endpoint *ep = &ep_array->at[i];
		if (port < 0 || ep->port == port) {
			endpoint_close(net, ep, false);
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
		array_clear(*ep_array);
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
			kr_log_info(TLS, "Updated ephemeral X.509 cert with new hostname\n");
		} else {
			kr_log_error(TLS, "Failed to update ephemeral X.509 cert with new hostname, using existing one\n");
		}
	}
}

#ifdef SO_ATTACH_BPF
static int set_bpf_cb(const char *key, void *val, void *ext)
{
	endpoint_array_t *endpoints = (endpoint_array_t *)val;
	int *bpffd = (int *)ext;
	if (kr_fails_assert(endpoints && bpffd))
		return kr_error(EINVAL);

	for (size_t i = 0; i < endpoints->len; i++) {
		struct endpoint *endpoint = &endpoints->at[i];
		uv_os_fd_t sockfd = -1;
		if (endpoint->handle != NULL)
			uv_fileno(endpoint->handle, &sockfd);
		kr_require(sockfd != -1);

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
	kr_log_error(NETWORK, "SO_ATTACH_BPF socket option doesn't supported\n");
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
	if (kr_fails_assert(endpoints))
		return kr_error(EINVAL);

	for (size_t i = 0; i < endpoints->len; i++) {
		struct endpoint *endpoint = &endpoints->at[i];
		uv_os_fd_t sockfd = -1;
		if (endpoint->handle != NULL)
			uv_fileno(endpoint->handle, &sockfd);
		kr_require(sockfd != -1);

		if (setsockopt(sockfd, SOL_SOCKET, SO_DETACH_BPF, NULL, 0) != 0) {
			kr_log_error(NETWORK, "failed to clear SO_DETACH_BPF socket option\n");
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
	kr_log_error(NETWORK, "SO_DETACH_BPF socket option doesn't supported\n");
	(void)net;
#endif
}
