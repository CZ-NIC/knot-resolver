/*  Copyright (C) 2015-2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/bindings/impl.h"

#include "contrib/base64.h"
#include "daemon/network.h"
#include "daemon/tls.h"

#include <stdlib.h>

/** Table and next index on top of stack -> append entries for given endpoint_array_t. */
static int net_list_add(const char *key, void *val, void *ext)
{
	lua_State *L = (lua_State *)ext;
	lua_Integer i = lua_tointeger(L, -1);
	endpoint_array_t *ep_array = val;
	for (int j = 0; j < ep_array->len; ++j) {
		struct endpoint *ep = &ep_array->at[j];
		lua_newtable(L);  // connection tuple

		if (ep->flags.kind) {
			lua_pushstring(L, ep->flags.kind);
		} else if (ep->flags.http && ep->flags.tls) {
			lua_pushliteral(L, "doh2");
		} else if (ep->flags.tls) {
			lua_pushliteral(L, "tls");
		} else if (ep->flags.xdp) {
			lua_pushliteral(L, "xdp");
		} else {
			lua_pushliteral(L, "dns");
		}
		lua_setfield(L, -2, "kind");

		lua_newtable(L);  // "transport" table

		switch (ep->family) {
		case AF_INET:
			lua_pushliteral(L, "inet4");
			break;
		case AF_INET6:
			lua_pushliteral(L, "inet6");
			break;
		case AF_XDP:
			lua_pushliteral(L, "inet4+inet6"); // both UDP ports at once
			break;
		case AF_UNIX:
			lua_pushliteral(L, "unix");
			break;
		default:
			lua_pushliteral(L, "invalid");
			assert(!EINVAL);
		}
		lua_setfield(L, -2, "family");

		lua_pushstring(L, key);
		if (ep->family == AF_INET || ep->family == AF_INET6) {
			lua_setfield(L, -2, "ip");
			lua_pushboolean(L, ep->flags.freebind);
			lua_setfield(L, -2, "freebind");
		} else if (ep->family == AF_UNIX) {
			lua_setfield(L, -2, "path");
		} else if (ep->family == AF_XDP) {
			lua_setfield(L, -2, "interface");
			lua_pushinteger(L, ep->nic_queue);
			lua_setfield(L, -2, "nic_queue");
		}

		if (ep->family != AF_UNIX) {
			lua_pushinteger(L, ep->port);
			lua_setfield(L, -2, "port");
		}

		if (ep->family == AF_UNIX) {
			lua_pushliteral(L, "stream");
		} else if (ep->flags.sock_type == SOCK_STREAM) {
			lua_pushliteral(L, "tcp");
		} else if (ep->flags.sock_type == SOCK_DGRAM) {
			lua_pushliteral(L, "udp");
		} else {
			assert(!EINVAL);
			lua_pushliteral(L, "invalid");
		}
		lua_setfield(L, -2, "protocol");

		lua_setfield(L, -2, "transport");

		lua_settable(L, -3);
		i++;
		lua_pushinteger(L, i);
	}
	return kr_ok();
}

/** List active endpoints. */
static int net_list(lua_State *L)
{
	lua_newtable(L);
	lua_pushinteger(L, 1);
	map_walk(&the_worker->engine->net.endpoints, net_list_add, L);
	lua_pop(L, 1);
	return 1;
}

/** Listen on an address list represented by the top of lua stack.
 * \note flags.kind ownership is not transferred, and flags.sock_type doesn't make sense
 * \return success */
static bool net_listen_addrs(lua_State *L, int port, endpoint_flags_t flags, int16_t nic_queue)
{
	assert(flags.xdp || nic_queue == -1);

	/* Case: table with 'addr' field; only follow that field directly. */
	lua_getfield(L, -1, "addr");
	if (!lua_isnil(L, -1)) {
		lua_replace(L, -2);
	} else {
		lua_pop(L, 1);
	}

	/* Case: string, representing a single address. */
	const char *str = lua_tostring(L, -1);
	if (str != NULL) {
		struct network *net = &the_worker->engine->net;
		const bool is_unix = str[0] == '/';
		int ret = 0;
		if (!flags.kind && !flags.tls) { /* normal UDP or XDP */
			flags.sock_type = SOCK_DGRAM;
			ret = network_listen(net, str, port, nic_queue, flags);
		}
		if (!flags.kind && !flags.xdp && ret == 0) { /* common for TCP, DoT and DoH (v2) */
			flags.sock_type = SOCK_STREAM;
			ret = network_listen(net, str, port, nic_queue, flags);
		}
		if (flags.kind) {
			flags.kind = strdup(flags.kind);
			flags.sock_type = SOCK_STREAM; /* TODO: allow to override this? */
			ret = network_listen(net, str, (is_unix ? 0 : port), nic_queue, flags);
		}
		if (ret == 0) return true; /* success */

		if (is_unix) {
			kr_log_error("[system] bind to '%s' (UNIX): %s\n",
					str, kr_strerror(ret));
		} else if (flags.xdp) {
			const char *err_str = knot_strerror(ret);
			if (ret == KNOT_ELIMIT) {
				if ((strcmp(str, "::") == 0 || strcmp(str, "0.0.0.0") == 0)) {
					err_str = "wildcard addresses not supported with XDP";
				} else {
					err_str = "address matched multiple network interfaces";
				}
			} else if (ret == kr_error(ENODEV)) {
				err_str = "invalid address or interface name";
			}
			/* Notable OK strerror: KNOT_EPERM Operation not permitted */

			if (nic_queue == -1) {
				kr_log_error("[system] failed to initialize XDP for '%s@%d'"
						" (nic_queue = <auto>): %s\n",
						str, port, err_str);
			} else {
				kr_log_error("[system] failed to initialize XDP for '%s@%d'"
						" (nic_queue = %d): %s\n",
						str, port, nic_queue, err_str);
			}

		} else {
			const char *stype = flags.sock_type == SOCK_DGRAM ? "UDP" : "TCP";
			kr_log_error("[system] bind to '%s@%d' (%s): %s\n",
					str, port, stype, kr_strerror(ret));
		}
		return false; /* failure */
	}

	/* Last case: table where all entries are added recursively. */
	if (!lua_istable(L, -1))
		lua_error_p(L, "bad type for address");
	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (!net_listen_addrs(L, port, flags, nic_queue))
			return false;
		lua_pop(L, 1);
	}
	return true;
}

static bool table_get_flag(lua_State *L, int index, const char *key, bool def)
{
	bool result = def;
	lua_getfield(L, index, key);
	if (lua_isboolean(L, -1)) {
		result = lua_toboolean(L, -1);
	}
	lua_pop(L, 1);
	return result;
}

/** Listen on endpoint. */
static int net_listen(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 1 || n > 3) {
		lua_error_p(L, "expected one to three arguments; usage:\n"
				"net.listen(addressses, [port = " STR(KR_DNS_PORT)
				", flags = {tls = (port == " STR(KR_DNS_TLS_PORT) ")}])\n");
	}

	int port = KR_DNS_PORT;
	if (n > 1) {
		if (lua_isnumber(L, 2)) {
			port = lua_tointeger(L, 2);
		} else
		if (!lua_isnil(L, 2)) {
			lua_error_p(L, "wrong type of second parameter (port number)");
		}
	}

	endpoint_flags_t flags = { 0 };
	if (port == KR_DNS_TLS_PORT) {
		flags.tls = true;
	} else if (port == KR_DNS_DOH_PORT) {
		flags.http = flags.tls = true;
	}

	int16_t nic_queue = -1;
	if (n > 2 && !lua_isnil(L, 3)) {
		if (!lua_istable(L, 3))
			lua_error_p(L, "wrong type of third parameter (table expected)");
		flags.tls = table_get_flag(L, 3, "tls", flags.tls);
		flags.freebind = table_get_flag(L, 3, "freebind", false);

		lua_getfield(L, 3, "kind");
		const char *k = lua_tostring(L, -1);
		if (k && strcasecmp(k, "dns") == 0) {
			flags.tls = flags.http = false;
		} else if (k && strcasecmp(k, "xdp") == 0) {
			flags.tls = flags.http = false;
			flags.xdp = true;
		} else if (k && strcasecmp(k, "tls") == 0) {
			flags.tls = true;
			flags.http = false;
		} else if (k && strcasecmp(k, "doh2") == 0) {
			flags.tls = flags.http = true;
		} else if (k) {
			flags.kind = k;
			if (strcasecmp(k, "doh") == 0) {
				kr_log_deprecate(
					"kind=\"doh\" is an obsolete DoH implementation, use kind=\"doh2\" instead\n");
			}
		}

		lua_getfield(L, 3, "nic_queue");
		if (lua_isnumber(L, -1)) {
			if (flags.xdp) {
				nic_queue = lua_tointeger(L, -1);
			} else {
				lua_error_p(L, "nic_queue only supported with kind = 'xdp'");
			}
		} else if (!lua_isnil(L, -1)) {
			lua_error_p(L, "wrong value of nic_queue (integer expected)");
		}
	}

	/* Memory management of `kind` string is difficult due to longjmp etc.
	 * Pop will unreference the lua value, so we store it on C stack instead (!) */
	const int kind_alen = flags.kind ? strlen(flags.kind) + 1 : 1 /* 0 length isn't C standard */;
	char kind_buf[kind_alen];
	if (flags.kind) {
		memcpy(kind_buf, flags.kind, kind_alen);
		flags.kind = kind_buf;
	}

	/* Now focus on the first argument. */
	lua_settop(L, 1);
	if (!net_listen_addrs(L, port, flags, nic_queue))
		lua_error_p(L, "net.listen() failed to bind");
	lua_pushboolean(L, true);
	return 1;
}

/** Close endpoint. */
static int net_close(lua_State *L)
{
	/* Check parameters */
	const int n = lua_gettop(L);
	bool ok = (n == 1 || n == 2) && lua_isstring(L, 1);
	const char *addr = lua_tostring(L, 1);
	int port;
	if (ok && (n < 2 || lua_isnil(L, 2))) {
	       port = -1;
	} else if (ok) {
		ok = lua_isnumber(L, 2);
		port = lua_tointeger(L, 2);
		ok = ok && port >= 0 && port <= 65535;
	}
	if (!ok)
		lua_error_p(L, "expected 'close(string addr, [number port])'");

	int ret = network_close(&the_worker->engine->net, addr, port);
	lua_pushboolean(L, ret == 0);
	return 1;
}

/** List available interfaces. */
static int net_interfaces(lua_State *L)
{
	/* Retrieve interface list */
	int count = 0;
	char buf[INET6_ADDRSTRLEN]; /* https://tools.ietf.org/html/rfc4291 */
	uv_interface_address_t *info = NULL;
	uv_interface_addresses(&info, &count);
	lua_newtable(L);
	for (int i = 0; i < count; ++i) {
		uv_interface_address_t iface = info[i];
		lua_getfield(L, -1, iface.name);
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			lua_newtable(L);
		}

		/* Address */
		lua_getfield(L, -1, "addr");
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			lua_newtable(L);
		}
		if (iface.address.address4.sin_family == AF_INET) {
			uv_ip4_name(&iface.address.address4, buf, sizeof(buf));
		} else if (iface.address.address4.sin_family == AF_INET6) {
			uv_ip6_name(&iface.address.address6, buf, sizeof(buf));
		} else {
			buf[0] = '\0';
		}
		lua_pushstring(L, buf);
		lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
		lua_setfield(L, -2, "addr");

		/* Hardware address. */
		char *p = buf;
		for (int k = 0; k < sizeof(iface.phys_addr); ++k) {
			sprintf(p, "%.2x:", (uint8_t)iface.phys_addr[k]);
			p += 3;
		}
		p[-1] = '\0';
		lua_pushstring(L, buf);
		lua_setfield(L, -2, "mac");

		/* Push table */
		lua_setfield(L, -2, iface.name);
	}
	uv_free_interface_addresses(info, count);

	return 1;
}

/** Set UDP maximum payload size. */
static int net_bufsize(lua_State *L)
{
	struct kr_context *ctx = &the_worker->engine->resolver;
	const int argc = lua_gettop(L);
	if (argc == 0) {
		lua_pushinteger(L, knot_edns_get_payload(ctx->downstream_opt_rr));
		lua_pushinteger(L, knot_edns_get_payload(ctx->upstream_opt_rr));
		return 2;
	}

	if (argc == 1) {
		int bufsize = lua_tointeger(L, 1);
		if (bufsize < 512 || bufsize > UINT16_MAX)
			lua_error_p(L, "bufsize must be within <512, " STR(UINT16_MAX) ">");
		knot_edns_set_payload(ctx->downstream_opt_rr, (uint16_t)bufsize);
		knot_edns_set_payload(ctx->upstream_opt_rr, (uint16_t)bufsize);
	} else if (argc == 2) {
		int bufsize_downstream = lua_tointeger(L, 1);
		int bufsize_upstream = lua_tointeger(L, 2);
		if (bufsize_downstream < 512 || bufsize_upstream < 512
		    || bufsize_downstream > UINT16_MAX || bufsize_upstream > UINT16_MAX) {
			lua_error_p(L, "bufsize must be within <512, " STR(UINT16_MAX) ">");
		}
		knot_edns_set_payload(ctx->downstream_opt_rr, (uint16_t)bufsize_downstream);
		knot_edns_set_payload(ctx->upstream_opt_rr, (uint16_t)bufsize_upstream);
	}
	return 0;
}

/** Set TCP pipelining size. */
static int net_pipeline(lua_State *L)
{
	struct worker_ctx *worker = the_worker;
	if (!worker) {
		return 0;
	}
	if (!lua_isnumber(L, 1)) {
		lua_pushinteger(L, worker->tcp_pipeline_max);
		return 1;
	}
	int len = lua_tointeger(L, 1);
	if (len < 0 || len > UINT16_MAX)
		lua_error_p(L, "tcp_pipeline must be within <0, " STR(UINT16_MAX) ">");
	worker->tcp_pipeline_max = len;
	lua_pushinteger(L, len);
	return 1;
}

static int net_tls(lua_State *L)
{
	struct network *net = &the_worker->engine->net;
	if (!net) {
		return 0;
	}

	/* Only return current credentials. */
	if (lua_gettop(L) == 0) {
		/* No credentials configured yet. */
		if (!net->tls_credentials) {
			return 0;
		}
		lua_newtable(L);
		lua_pushstring(L, net->tls_credentials->tls_cert);
		lua_setfield(L, -2, "cert_file");
		lua_pushstring(L, net->tls_credentials->tls_key);
		lua_setfield(L, -2, "key_file");
		return 1;
	}

	if ((lua_gettop(L) != 2) || !lua_isstring(L, 1) || !lua_isstring(L, 2))
		lua_error_p(L, "net.tls takes two parameters: (\"cert_file\", \"key_file\")");

	int r = tls_certificate_set(net, lua_tostring(L, 1), lua_tostring(L, 2));
	lua_error_maybe(L, r);

	lua_pushboolean(L, true);
	return 1;
}

/** Select HTTP headers to subscribe to for incoming DoH requests. */
static int net_doh_headers_in(lua_State *L)
{
	doh_headerlist_t *headers = &the_worker->doh_headers_in;
	int i;
	const char *name;

	/* Only return current configuration. */
	if (lua_gettop(L) == 0) {
		lua_newtable(L);
		for (i = 0; i < headers->len; i++) {
			lua_pushinteger(L, i + 1);
			name = headers->at[i];
			lua_pushlstring(L, name, strlen(name));
			lua_settable(L, -3);
		}
		return 1;
	}

	if (lua_gettop(L) != 1)
		lua_error_p(L, "net.doh_headers_in() takes one parameter (string or table)");

	if (!lua_istable(L, 1) && !lua_isstring(L, 1))
		lua_error_p(L, "net.doh_headers_in() argument must be string or table");

	/* Clear existing headers. */
	for (i = 0; i < headers->len; i++)
		free(headers->at[i]);
	array_clear(*headers);

	if (lua_istable(L, 1)) {
		for (i = 1; !lua_isnil(L, -1); i++) {
			lua_pushinteger(L, i);
			lua_gettable(L, 1);
			if (lua_isnil(L, -1))  /* missing value - end iteration */
				break;
			if (!lua_isstring(L, -1))
				lua_error_p(L, "net.doh_headers_in() argument table can only contain strings");
			name = lua_tostring(L, -1);
			array_push(*headers, strdup(name));
		}
	} else if (lua_isstring(L, 1)) {
		name = lua_tostring(L, 1);
		array_push(*headers, strdup(name));
	}

	return 0;
}

/** Return a lua table with TLS authentication parameters.
 * The format is the same as passed to policy.TLS_FORWARD();
 * more precisely, it's in a compatible canonical form. */
static int tls_params2lua(lua_State *L, trie_t *params)
{
	lua_newtable(L);
	if (!params) /* Allowed special case. */
		return 1;
	trie_it_t *it;
	size_t list_index = 0;
	for (it = trie_it_begin(params); !trie_it_finished(it); trie_it_next(it)) {
		/* Prepare table for the current address
		 * and its index in the returned list. */
		lua_pushinteger(L, ++list_index);
		lua_createtable(L, 0, 2);

		/* Get the "addr#port" string... */
		size_t ia_len;
		const char *key = trie_it_key(it, &ia_len);
		int af = AF_UNSPEC;
		if (ia_len == 2 + sizeof(struct in_addr)) {
			af = AF_INET;
		} else if (ia_len == 2 + sizeof(struct in6_addr)) {
			af = AF_INET6;
		}
		if (!key || af == AF_UNSPEC) {
			assert(false);
			lua_error_p(L, "internal error: bad IP address");
		}
		uint16_t port;
		memcpy(&port, key, sizeof(port));
		port = ntohs(port);
		const char *ia = key + sizeof(port);
		char str[INET6_ADDRSTRLEN + 1 + 5 + 1];
		size_t len = sizeof(str);
		if (kr_ntop_str(af, ia, port, str, &len) != kr_ok()) {
			assert(false);
			lua_error_p(L, "internal error: bad IP address conversion");
		}
		/* ...and push it as [1]. */
		lua_pushinteger(L, 1);
		lua_pushlstring(L, str, len - 1 /* len includes '\0' */);
		lua_settable(L, -3);

		const tls_client_param_t *e = *trie_it_val(it);
		if (!e)
			lua_error_p(L, "internal problem - NULL entry for %s", str);

		/* .hostname = */
		if (e->hostname) {
			lua_pushstring(L, e->hostname);
			lua_setfield(L, -2, "hostname");
		}

		/* .ca_files = */
		if (e->ca_files.len) {
			lua_createtable(L, e->ca_files.len, 0);
			for (size_t i = 0; i < e->ca_files.len; ++i) {
				lua_pushinteger(L, i + 1);
				lua_pushstring(L, e->ca_files.at[i]);
				lua_settable(L, -3);
			}
			lua_setfield(L, -2, "ca_files");
		}

		/* .pin_sha256 = ... ; keep sane indentation via goto. */
		if (!e->pins.len) goto no_pins;
		lua_createtable(L, e->pins.len, 0);
		for (size_t i = 0; i < e->pins.len; ++i) {
			uint8_t pin_base64[TLS_SHA256_BASE64_BUFLEN];
			int err = kr_base64_encode(e->pins.at[i], TLS_SHA256_RAW_LEN,
						pin_base64, sizeof(pin_base64));
			if (err < 0) {
				assert(false);
				lua_error_p(L,
					"internal problem when converting pin_sha256: %s",
					kr_strerror(err));
			}
			lua_pushinteger(L, i + 1);
			lua_pushlstring(L, (const char *)pin_base64, err);
				/* pin_base64 isn't 0-terminated     ^^^ */
			lua_settable(L, -3);
		}
		lua_setfield(L, -2, "pin_sha256");

	no_pins:/* .insecure = */
		if (e->insecure) {
			lua_pushboolean(L, true);
			lua_setfield(L, -2, "insecure");
		}
		/* Now the whole table is pushed atop the returned list. */
		lua_settable(L, -3);
	}
	trie_it_free(it);
	return 1;
}

static inline int cmp_sha256(const void *p1, const void *p2)
{
	return memcmp(*(char * const *)p1, *(char * const *)p2, TLS_SHA256_RAW_LEN);
}
static int net_tls_client(lua_State *L)
{
	/* TODO idea: allow starting the lua table with *multiple* IP targets,
	 * meaning the authentication config should be applied to each.
	 */
	struct network *net = &the_worker->engine->net;
	if (lua_gettop(L) == 0)
		return tls_params2lua(L, net->tls_client_params);
	/* Various basic sanity-checking. */
	if (lua_gettop(L) != 1 || !lua_istable(L, 1))
		lua_error_maybe(L, EINVAL);
	/* check that only allowed keys are present */
	{
		const char *bad_key = lua_table_checkindices(L, (const char *[])
			{ "1", "hostname", "ca_file", "pin_sha256", "insecure", NULL });
		if (bad_key)
			lua_error_p(L, "found unexpected key '%s'", bad_key);
	}

	/**** Phase 1: get the parameter into a C struct, incl. parse of CA files,
	 * 	 regardless of the address-pair having an entry already. */

	tls_client_param_t *newcfg = tls_client_param_new();
	if (!newcfg)
		lua_error_p(L, "out of memory or something like that :-/");
	/* Shortcut for cleanup actions needed from now on. */
	#define ERROR(...) do { \
		free(newcfg); \
		lua_error_p(L, __VA_ARGS__); \
	} while (false)

	/* .hostname - always accepted. */
	lua_getfield(L, 1, "hostname");
	if (!lua_isnil(L, -1)) {
		const char *hn_str = lua_tostring(L, -1);
		/* Convert to lower-case dname and back, for checking etc. */
		knot_dname_t dname[KNOT_DNAME_MAXLEN];
		if (!hn_str || !knot_dname_from_str(dname, hn_str, sizeof(dname)))
			ERROR("invalid hostname");
		knot_dname_to_lower(dname);
		char *h = knot_dname_to_str_alloc(dname);
		if (!h)
			ERROR("%s", kr_strerror(ENOMEM));
		/* Strip the final dot produced by knot_dname_*() */
		h[strlen(h) - 1] = '\0';
		newcfg->hostname = h;
	}
	lua_pop(L, 1);

	/* .ca_file - it can be a list of paths, contrary to the name. */
	bool has_ca_file = false;
	lua_getfield(L, 1, "ca_file");
	if (!lua_isnil(L, -1)) {
		if (!newcfg->hostname)
			ERROR("missing hostname but specifying ca_file");
		lua_listify(L);
		array_init(newcfg->ca_files); /*< placate apparently confused scan-build */
		if (array_reserve(newcfg->ca_files, lua_objlen(L, -1)) != 0) /*< optim. */
			ERROR("%s", kr_strerror(ENOMEM));
		/* Iterate over table at the top of the stack.
		 * http://www.lua.org/manual/5.1/manual.html#lua_next */
		for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
			has_ca_file = true; /* deferred here so that {} -> false */
			const char *ca_file = lua_tostring(L, -1);
			if (!ca_file)
				ERROR("ca_file contains a non-string");
			/* Let gnutls process it immediately, so garbage gets detected. */
			int ret = gnutls_certificate_set_x509_trust_file(
					newcfg->credentials, ca_file, GNUTLS_X509_FMT_PEM);
			if (ret < 0) {
				ERROR("failed to import certificate file '%s': %s - %s\n",
					ca_file, gnutls_strerror_name(ret),
					gnutls_strerror(ret));
			} else {
				kr_log_verbose(
					"[tls_client] imported %d certs from file '%s'\n",
					ret, ca_file);
			}

			ca_file = strdup(ca_file);
			if (!ca_file || array_push(newcfg->ca_files, ca_file) < 0)
				ERROR("%s", kr_strerror(ENOMEM));
		}
		/* Sort the strings for easier comparison later. */
		if (newcfg->ca_files.len) {
			qsort(&newcfg->ca_files.at[0], newcfg->ca_files.len,
				sizeof(newcfg->ca_files.at[0]), strcmp_p);
		}
	}
	lua_pop(L, 1);

	/* .pin_sha256 */
	lua_getfield(L, 1, "pin_sha256");
	if (!lua_isnil(L, -1)) {
		if (has_ca_file)
			ERROR("mixing pin_sha256 with ca_file is not supported");
		lua_listify(L);
		array_init(newcfg->pins); /*< placate apparently confused scan-build */
		if (array_reserve(newcfg->pins, lua_objlen(L, -1)) != 0) /*< optim. */
			ERROR("%s", kr_strerror(ENOMEM));
		/* Iterate over table at the top of the stack. */
		for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
			const char *pin = lua_tostring(L, -1);
			if (!pin)
				ERROR("pin_sha256 is not a string");
			uint8_t *pin_raw = malloc(TLS_SHA256_RAW_LEN);
			/* Push the string early to simplify error processing. */
			if (!pin_raw || array_push(newcfg->pins, pin_raw) < 0) {
				assert(false);
				free(pin_raw);
				ERROR("%s", kr_strerror(ENOMEM));
			}
			int ret = kr_base64_decode((const uint8_t *)pin, strlen(pin),
						pin_raw, TLS_SHA256_RAW_LEN + 8);
			if (ret < 0) {
				ERROR("not a valid pin_sha256: '%s' (length %d), %s\n",
					pin, (int)strlen(pin), knot_strerror(ret));
			} else if (ret != TLS_SHA256_RAW_LEN) {
				ERROR("not a valid pin_sha256: '%s', "
						"raw length %d instead of "
						STR(TLS_SHA256_RAW_LEN)"\n",
					pin, ret);
			}
		}
		/* Sort the raw strings for easier comparison later. */
		if (newcfg->pins.len) {
			qsort(&newcfg->pins.at[0], newcfg->pins.len,
				sizeof(newcfg->pins.at[0]), cmp_sha256);
		}
	}
	lua_pop(L, 1);

	/* .insecure */
	lua_getfield(L, 1, "insecure");
	if (lua_isnil(L, -1)) {
		if (!newcfg->hostname && !newcfg->pins.len)
			ERROR("no way to authenticate and not set as insecure");
	} else if (lua_isboolean(L, -1) && lua_toboolean(L, -1)) {
		newcfg->insecure = true;
		if (has_ca_file || newcfg->pins.len)
			ERROR("set as insecure but provided authentication config");
	} else {
		ERROR("incorrect value in the 'insecure' field");
	}
	lua_pop(L, 1);

	/* Init CAs from system trust store, if needed. */
	if (!newcfg->insecure && !newcfg->pins.len && !has_ca_file) {
		int ret = gnutls_certificate_set_x509_system_trust(newcfg->credentials);
		if (ret <= 0) {
			ERROR("failed to use system CA certificate store: %s",
				ret ? gnutls_strerror(ret) : kr_strerror(ENOENT));
		} else {
			kr_log_verbose(
				"[tls_client] imported %d certs from system store\n",
				ret);
		}
	}
	#undef ERROR

	/**** Phase 2: deal with the C authentication "table". */
	/* Parse address and port. */
	lua_pushinteger(L, 1);
	lua_gettable(L, 1);
	const char *addr_str = lua_tostring(L, -1);
	if (!addr_str)
		lua_error_p(L, "address is not a string");
	char buf[INET6_ADDRSTRLEN + 1];
	uint16_t port = 853;
	const struct sockaddr *addr = NULL;
	if (kr_straddr_split(addr_str, buf, &port) == kr_ok())
		addr = kr_straddr_socket(buf, port, NULL);
	/* Add newcfg into the C map, saving the original into oldcfg. */
	if (!addr)
		lua_error_p(L, "address '%s' could not be converted", addr_str);
	tls_client_param_t **oldcfgp = tls_client_param_getptr(
			&net->tls_client_params, addr, true);
	free_const(addr);
	if (!oldcfgp)
		lua_error_p(L, "internal error when extending tls_client_params map");
	tls_client_param_t *oldcfg = *oldcfgp;
	*oldcfgp = newcfg;  /* replace old config in trie with the new one */
	/* If there was no original entry, it's easy! */
	if (!oldcfg)
		return 0;

	/* Check for equality (newcfg vs. oldcfg), and print a warning if not equal.*/
	const bool ok_h = (!newcfg->hostname && !oldcfg->hostname)
		|| (newcfg->hostname && oldcfg->hostname && strcmp(newcfg->hostname, oldcfg->hostname) == 0);
	bool ok_ca = newcfg->ca_files.len == oldcfg->ca_files.len;
	for (int i = 0; ok_ca && i < newcfg->ca_files.len; ++i)
		ok_ca = strcmp(newcfg->ca_files.at[i], oldcfg->ca_files.at[i]) == 0;
	bool ok_pins = newcfg->pins.len == oldcfg->pins.len;
	for (int i = 0; ok_pins && i < newcfg->pins.len; ++i)
		ok_ca = memcmp(newcfg->pins.at[i], oldcfg->pins.at[i], TLS_SHA256_RAW_LEN) == 0;
	const bool ok_insecure = newcfg->insecure == oldcfg->insecure;
	if (!(ok_h && ok_ca && ok_pins && ok_insecure)) {
		kr_log_info("[tls_client] "
			"warning: re-defining TLS authentication parameters for %s\n",
			addr_str);
	}
	tls_client_param_unref(oldcfg);
	return 0;
}

int net_tls_client_clear(lua_State *L)
{
	/* One parameter: address -> convert it to a struct sockaddr. */
	if (lua_gettop(L) != 1 || !lua_isstring(L, 1))
		lua_error_p(L, "net.tls_client_clear() requires one parameter (\"address\")");
	const char *addr_str = lua_tostring(L, 1);
	char buf[INET6_ADDRSTRLEN + 1];
	uint16_t port = 853;
	const struct sockaddr *addr = NULL;
	if (kr_straddr_split(addr_str, buf, &port) == kr_ok())
		addr = kr_straddr_socket(buf, port, NULL);
	if (!addr)
		lua_error_p(L, "invalid IP address");
	/* Do the actual removal. */
	struct network *net = &the_worker->engine->net;
	int r = tls_client_param_remove(net->tls_client_params, addr);
	free_const(addr);
	lua_error_maybe(L, r);
	lua_pushboolean(L, true);
	return 1;
}

static int net_tls_padding(lua_State *L)
{
	struct kr_context *ctx = &the_worker->engine->resolver;

	/* Only return current padding. */
	if (lua_gettop(L) == 0) {
		if (ctx->tls_padding < 0) {
			lua_pushboolean(L, true);
			return 1;
		} else if (ctx->tls_padding == 0) {
			lua_pushboolean(L, false);
			return 1;
		}
		lua_pushinteger(L, ctx->tls_padding);
		return 1;
	}

	const char *errstr = "net.tls_padding parameter has to be true, false,"
				" or a number between <0, " STR(MAX_TLS_PADDING) ">";
	if (lua_gettop(L) != 1)
		lua_error_p(L, "%s", errstr);
	if (lua_isboolean(L, 1)) {
		bool x = lua_toboolean(L, 1);
		if (x) {
			ctx->tls_padding = -1;
		} else {
			ctx->tls_padding = 0;
		}
	} else if (lua_isnumber(L, 1)) {
		int padding = lua_tointeger(L, 1);
		if ((padding < 0) || (padding > MAX_TLS_PADDING))
			lua_error_p(L, "%s", errstr);
		ctx->tls_padding = padding;
	} else {
		lua_error_p(L, "%s", errstr);
	}
	lua_pushboolean(L, true);
	return 1;
}

/** Shorter salt can't contain much entropy. */
#define net_tls_sticket_MIN_SECRET_LEN 32

static int net_tls_sticket_secret_string(lua_State *L)
{
	struct network *net = &the_worker->engine->net;

	size_t secret_len;
	const char *secret;

	if (lua_gettop(L) == 0) {
		/* Zero-length secret, implying random key. */
		secret_len = 0;
		secret = NULL;
	} else {
		if (lua_gettop(L) != 1 || !lua_isstring(L, 1)) {
			lua_error_p(L,
				"net.tls_sticket_secret takes one parameter: (\"secret string\")");
		}
		secret = lua_tolstring(L, 1, &secret_len);
		if (secret_len < net_tls_sticket_MIN_SECRET_LEN || !secret) {
			lua_error_p(L, "net.tls_sticket_secret - the secret is shorter than "
					STR(net_tls_sticket_MIN_SECRET_LEN) " bytes");
		}
	}

	tls_session_ticket_ctx_destroy(net->tls_session_ticket_ctx);
	net->tls_session_ticket_ctx =
		tls_session_ticket_ctx_create(net->loop, secret, secret_len);
	if (net->tls_session_ticket_ctx == NULL) {
		lua_error_p(L,
			"net.tls_sticket_secret_string - can't create session ticket context");
	}

	lua_pushboolean(L, true);
	return 1;
}

static int net_tls_sticket_secret_file(lua_State *L)
{
	if (lua_gettop(L) != 1 || !lua_isstring(L, 1)) {
		lua_error_p(L,
			"net.tls_sticket_secret_file takes one parameter: (\"file name\")");
	}

	const char *file_name = lua_tostring(L, 1);
	if (strlen(file_name) == 0)
		lua_error_p(L, "net.tls_sticket_secret_file - empty file name");

	FILE *fp = fopen(file_name, "r");
	if (fp == NULL) {
		lua_error_p(L, "net.tls_sticket_secret_file - can't open file '%s': %s",
				file_name, strerror(errno));
	}

	char secret_buf[TLS_SESSION_TICKET_SECRET_MAX_LEN];
	const size_t secret_len = fread(secret_buf, 1, sizeof(secret_buf), fp);
	int err = ferror(fp);
	if (err) {
		lua_error_p(L,
			"net.tls_sticket_secret_file - error reading from file '%s': %s",
			file_name, strerror(err));
	}
	if (secret_len < net_tls_sticket_MIN_SECRET_LEN) {
		lua_error_p(L,
			"net.tls_sticket_secret_file - file '%s' is shorter than "
				STR(net_tls_sticket_MIN_SECRET_LEN) " bytes",
			file_name);
	}
	fclose(fp);

	struct network *net = &the_worker->engine->net;

	tls_session_ticket_ctx_destroy(net->tls_session_ticket_ctx);
	net->tls_session_ticket_ctx =
		tls_session_ticket_ctx_create(net->loop, secret_buf, secret_len);
	if (net->tls_session_ticket_ctx == NULL) {
		lua_error_p(L,
			"net.tls_sticket_secret_file - can't create session ticket context");
	}
	lua_pushboolean(L, true);
	return 1;
}

static int net_outgoing(lua_State *L, int family)
{
	union inaddr *addr;
	if (family == AF_INET)
		addr = (union inaddr*)&the_worker->out_addr4;
	else
		addr = (union inaddr*)&the_worker->out_addr6;

	if (lua_gettop(L) == 0) { /* Return the current value. */
		if (addr->ip.sa_family == AF_UNSPEC) {
			lua_pushnil(L);
			return 1;
		}
		if (addr->ip.sa_family != family) {
			assert(false);
			lua_error_p(L, "bad address family");
		}
		char addr_buf[INET6_ADDRSTRLEN];
		int err;
		if (family == AF_INET)
			err = uv_ip4_name(&addr->ip4, addr_buf, sizeof(addr_buf));
		else
			err = uv_ip6_name(&addr->ip6, addr_buf, sizeof(addr_buf));
		lua_error_maybe(L, err);
		lua_pushstring(L, addr_buf);
		return 1;
	}

	if ((lua_gettop(L) != 1) || (!lua_isstring(L, 1) && !lua_isnil(L, 1)))
		lua_error_p(L, "net.outgoing_vX takes one address string parameter or nil");

	if (lua_isnil(L, 1)) {
		addr->ip.sa_family = AF_UNSPEC;
		return 1;
	}

	const char *addr_str = lua_tostring(L, 1);
	int err;
	if (family == AF_INET)
		err = uv_ip4_addr(addr_str, 0, &addr->ip4);
	else
		err = uv_ip6_addr(addr_str, 0, &addr->ip6);
	if (err)
		lua_error_p(L, "net.outgoing_vX: failed to parse the address");
	lua_pushboolean(L, true);
	return 1;
}

static int net_outgoing_v4(lua_State *L) { return net_outgoing(L, AF_INET); }
static int net_outgoing_v6(lua_State *L) { return net_outgoing(L, AF_INET6); }

static int net_update_timeout(lua_State *L, uint64_t *timeout, const char *name)
{
	/* Only return current idle timeout. */
	if (lua_gettop(L) == 0) {
		lua_pushinteger(L, *timeout);
		return 1;
	}

	if ((lua_gettop(L) != 1))
		lua_error_p(L, "%s takes one parameter: (\"idle timeout\")", name);

	if (lua_isnumber(L, 1)) {
		int idle_timeout = lua_tointeger(L, 1);
		if (idle_timeout <= 0)
			lua_error_p(L, "%s parameter has to be positive number", name);
		*timeout = idle_timeout;
	} else {
		lua_error_p(L, "%s parameter has to be positive number", name);
	}
	lua_pushboolean(L, true);
	return 1;
}

static int net_tcp_in_idle(lua_State *L)
{
	struct network *net = &the_worker->engine->net;
	return net_update_timeout(L, &net->tcp.in_idle_timeout, "net.tcp_in_idle");
}

static int net_tls_handshake_timeout(lua_State *L)
{
	struct network *net = &the_worker->engine->net;
	return net_update_timeout(L, &net->tcp.tls_handshake_timeout, "net.tls_handshake_timeout");
}

static int net_bpf_set(lua_State *L)
{
	if (lua_gettop(L) != 1 || !lua_isnumber(L, 1)) {
		lua_error_p(L, "net.bpf_set(fd) takes one parameter:"
				" the open file descriptor of a loaded BPF program");
	}

#if __linux__

	int progfd = lua_tointeger(L, 1);
	if (progfd == 0) {
		/* conversion error despite that fact
		 * that lua_isnumber(L, 1) has returned true.
		 * Real or stdin? */
		lua_error_p(L, "failed to convert parameter");
	}
	lua_pop(L, 1);

	if (network_set_bpf(&the_worker->engine->net, progfd) == 0) {
		lua_error_p(L, "failed to attach BPF program to some networks: %s",
				kr_strerror(errno));
	}

	lua_pushboolean(L, 1);
	return 1;

#endif
	lua_error_p(L, "BPF is not supported on this operating system");
}

static int net_bpf_clear(lua_State *L)
{
	if (lua_gettop(L) != 0)
		lua_error_p(L, "net.bpf_clear() does not take any parameters");

#if __linux__

	network_clear_bpf(&the_worker->engine->net);

	lua_pushboolean(L, 1);
	return 1;

#endif
	lua_error_p(L, "BPF is not supported on this operating system");
}

static int net_register_endpoint_kind(lua_State *L)
{
	const int param_count = lua_gettop(L);
	if (param_count != 1 && param_count != 2)
		lua_error_p(L, "expected one or two parameters");
	if (!lua_isstring(L, 1)) {
		lua_error_p(L, "incorrect kind '%s'", lua_tostring(L, 1));
	}
	size_t kind_len;
	const char *kind = lua_tolstring(L, 1, &kind_len);
	struct network *net = &the_worker->engine->net;

	/* Unregistering */
	if (param_count == 1) {
		void *val;
		if (trie_del(net->endpoint_kinds, kind, kind_len, &val) == KNOT_EOK) {
			const int fun_id = (char *)val - (char *)NULL;
			luaL_unref(L, LUA_REGISTRYINDEX, fun_id);
			return 0;
		}
		lua_error_p(L, "attempt to unregister unknown kind '%s'\n", kind);
	} /* else */

	/* Registering */
	assert(param_count == 2);
	if (!lua_isfunction(L, 2)) {
		lua_error_p(L, "second parameter: expected function but got %s\n",
				lua_typename(L, lua_type(L, 2)));
	}
	const int fun_id = luaL_ref(L, LUA_REGISTRYINDEX);
		/* ^^ The function is on top of the stack, incidentally. */
	void **pp = trie_get_ins(net->endpoint_kinds, kind, kind_len);
	if (!pp) lua_error_maybe(L, kr_error(ENOMEM));
	if (*pp != NULL || !strcasecmp(kind, "dns") || !strcasecmp(kind, "tls"))
		lua_error_p(L, "attempt to register known kind '%s'\n", kind);
	*pp = (char *)NULL + fun_id;
	/* We don't attempt to engage correspoinding endpoints now.
	 * That's the job for network_engage_endpoints() later. */
	return 0;
}

int kr_bindings_net(lua_State *L)
{
	static const luaL_Reg lib[] = {
		{ "list",         net_list },
		{ "listen",       net_listen },
		{ "close",        net_close },
		{ "interfaces",   net_interfaces },
		{ "bufsize",      net_bufsize },
		{ "tcp_pipeline", net_pipeline },
		{ "tls",          net_tls },
		{ "tls_server",   net_tls },
		{ "tls_client",   net_tls_client },
		{ "tls_client_clear", net_tls_client_clear },
		{ "tls_padding",  net_tls_padding },
		{ "tls_sticket_secret", net_tls_sticket_secret_string },
		{ "tls_sticket_secret_file", net_tls_sticket_secret_file },
		{ "outgoing_v4",  net_outgoing_v4 },
		{ "outgoing_v6",  net_outgoing_v6 },
		{ "tcp_in_idle",  net_tcp_in_idle },
		{ "tls_handshake_timeout",  net_tls_handshake_timeout },
		{ "bpf_set",      net_bpf_set },
		{ "bpf_clear",    net_bpf_clear },
		{ "register_endpoint_kind", net_register_endpoint_kind },
		{ "doh_headers_in", net_doh_headers_in },
		{ NULL, NULL }
	};
	luaL_register(L, "net", lib);
	return 1;
}

