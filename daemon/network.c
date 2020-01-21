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

#include "daemon/network.h"

#include "daemon/bindings/impl.h"
#include "daemon/io.h"
#include "daemon/tls.h"
#include "daemon/worker.h"

#include <assert.h>
#include <libgen.h>
#include <sys/un.h>
#include <unistd.h>

void network_init(struct network *net, uv_loop_t *loop, int tcp_backlog)
{
	if (net != NULL) {
		net->loop = loop;
		net->endpoints = map_make(NULL);
		net->endpoint_kinds = trie_create(NULL);
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
	if (!ok) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
	/* First find callback in the endpoint registry. */
	lua_State *L = the_worker->engine->L;
	void **pp = trie_get_try(net->endpoint_kinds, ep->flags.kind,
				strlen(ep->flags.kind));
	if (!pp && net->missing_kind_is_error) {
		kr_log_error("error: network socket kind '%s' not handled when opening '%s",
				ep->flags.kind, log_addr);
		if (ep->family != AF_UNIX)
			kr_log_error("#%d", ep->port);
		kr_log_error("'\n'");
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
		kr_log_error("error opening %s: %s\n", log_addr, lua_tostring(L, -1));
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
		kr_log_error("internal error: missing kind '%s' in endpoint registry\n",
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
		kr_log_error("failed to close FIXME:endpoint-identifier: %s\n",
				lua_tostring(L, -1));
	}
}

static void endpoint_close(struct network *net, struct endpoint *ep, bool force)
{
	bool control = ep->flags.kind && strcmp(ep->flags.kind, "control") == 0;

	if (ep->family == AF_UNIX) { /* The FS name would be left behind. */
		/* Extract local address for this socket. */
		struct sockaddr_un sa;
		sa.sun_path[0] = '\0'; /*< probably only for lint:scan-build */
		socklen_t addr_len = sizeof(sa);
		if (getsockname(ep->fd, (struct sockaddr *)&sa, &addr_len)
		    || unlink(sa.sun_path)) {
			kr_log_error("error (ignored) when closing unix socket (fd = %d): %s\n",
					ep->fd, strerror(errno));
			return;
		}
	}

	if (ep->flags.kind && !control) {
		assert(!ep->handle);
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

	free_const(ep->flags.kind); /* needed if (control) */
	assert(ep->handle);
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

void network_deinit(struct network *net)
{
	if (net != NULL) {
		network_close_force(net);
		trie_apply(net->endpoint_kinds, kind_unregister, the_worker->engine->L);
		trie_free(net->endpoint_kinds);

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

/** Open endpoint protocols.  ep->flags were pre-set. */
static int open_endpoint(struct network *net, struct endpoint *ep,
			 const struct sockaddr *sa, const char *log_addr)
{
	bool control = ep->flags.kind && strcmp(ep->flags.kind, "control") == 0;
	if ((sa != NULL) == (ep->fd != -1)) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
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
	if (ep->flags.kind && !control) {
		/* This EP isn't to be managed internally after binding. */
		return endpoint_open_lua_cb(net, ep, log_addr);
	} else {
		ep->engaged = true;
		/* .engaged seems not really meaningful with .kind == NULL, but... */
	}

	if (control) {
		uv_pipe_t *ep_handle = malloc(sizeof(uv_pipe_t));
		ep->handle = (uv_handle_t *)ep_handle;
		if (!ep->handle) {
			return kr_error(ENOMEM);
		}
		return io_listen_pipe(net->loop, ep_handle, ep->fd);
	}

	if (ep->family == AF_UNIX) {
		/* Some parts of connection handling would need more work,
		 * so let's support AF_UNIX only with .kind != NULL for now. */
		kr_log_error("[system] AF_UNIX only supported with set { kind = '...' }\n");
		return kr_error(EAFNOSUPPORT);
		/*
		uv_pipe_t *ep_handle = malloc(sizeof(uv_pipe_t));
		*/
	}

	if (ep->flags.sock_type == SOCK_DGRAM) {
		if (ep->flags.tls) {
			assert(!EINVAL);
			return kr_error(EINVAL);
		}
		uv_udp_t *ep_handle = malloc(sizeof(uv_udp_t));
		ep->handle = (uv_handle_t *)ep_handle;
		if (!ep->handle) {
			return kr_error(ENOMEM);
		}
		return io_listen_udp(net->loop, ep_handle, ep->fd);
	} /* else */

	if (ep->flags.sock_type == SOCK_STREAM) {
		uv_tcp_t *ep_handle = malloc(sizeof(uv_tcp_t));
		ep->handle = (uv_handle_t *)ep_handle;
		if (!ep->handle) {
			return kr_error(ENOMEM);
		}
		return io_listen_tcp(net->loop, ep_handle, ep->fd,
					net->tcp_backlog, ep->flags.tls);
	} /* else */

	assert(!EINVAL);
	return kr_error(EINVAL);
}

/** @internal Fetch a pointer to endpoint of given parameters (or NULL).
 * Beware that there might be multiple matches, though that's not common. */
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

/** \note pass either sa != NULL xor ep.fd != -1;
 *  \note ownership of ep.flags.* is taken on success. */
static int create_endpoint(struct network *net, const char *addr_str,
				struct endpoint *ep, const struct sockaddr *sa)
{
	int ret = open_endpoint(net, ep, sa, addr_str);
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
	/* Extract fd's socket type. */
	socklen_t len = sizeof(flags.sock_type);
	int ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, &flags.sock_type, &len);
	if (ret != 0) {
		return kr_error(errno);
	}
	if (flags.sock_type == SOCK_DGRAM && !flags.kind && flags.tls) {
		assert(!EINVAL); /* Perhaps DTLS some day. */
		return kr_error(EINVAL);
	}
	if (flags.sock_type != SOCK_DGRAM && flags.sock_type != SOCK_STREAM) {
		return kr_error(EBADF);
	}

	/* Extract local address for this socket. */
	struct sockaddr_storage ss = { .ss_family = AF_UNSPEC };
	socklen_t addr_len = sizeof(ss);
	ret = getsockname(fd, (struct sockaddr *)&ss, &addr_len);
	if (ret != 0) {
		return kr_error(errno);
	}

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

int network_listen(struct network *net, const char *addr, uint16_t port,
		   endpoint_flags_t flags)
{
	if (net == NULL || addr == 0 || port == 0) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
	if (endpoint_get(net, addr, port, flags)) {
		return kr_error(EADDRINUSE); /* Already listening */
	}

	/* Parse address. */
	const struct sockaddr *sa = kr_straddr_socket(addr, port, NULL);
	if (!sa) {
		return kr_error(EINVAL);
	}
	struct endpoint ep = {
		.flags = flags,
		.fd = -1,
		.port = port,
		.family = sa->sa_family,
	};
	int ret = create_endpoint(net, addr, &ep, sa);
	free_const(sa);
	return ret;
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
		struct endpoint *endpoint = &endpoints->at[i];
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
		struct endpoint *endpoint = &endpoints->at[i];
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
