/*  Copyright (C) 2015-2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "daemon/bindings/impl.h"

#include "contrib/base64.h"
#include "daemon/network.h"
#include "daemon/tls.h"
#include "daemon/worker.h"

#include <stdlib.h>

/** Append 'addr = {port = int, udp = bool, tcp = bool}' */
static int net_list_add(const char *key, void *val, void *ext)
{
	lua_State *L = (lua_State *)ext;
	endpoint_array_t *ep_array = val;
	lua_newtable(L);
	for (size_t i = ep_array->len; i--;) {
		struct endpoint *ep = ep_array->at[i];
		lua_pushinteger(L, ep->port);
		lua_setfield(L, -2, "port");
		lua_pushboolean(L, ep->flags & NET_UDP);
		lua_setfield(L, -2, "udp");
		lua_pushboolean(L, ep->flags & NET_TCP);
		lua_setfield(L, -2, "tcp");
		lua_pushboolean(L, ep->flags & NET_TLS);
		lua_setfield(L, -2, "tls");
	}
	lua_setfield(L, -2, key);
	return kr_ok();
}

/** List active endpoints. */
static int net_list(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	lua_newtable(L);
	map_walk(&engine->net.endpoints, net_list_add, L);
	return 1;
}

/** Listen on an address list represented by the top of lua stack. */
static int net_listen_addrs(lua_State *L, int port, int flags)
{
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
		struct engine *engine = engine_luaget(L);
		int ret = network_listen(&engine->net, str, port, flags);
		if (ret != 0) {
			kr_log_info("[system] bind to '%s@%d' %s\n",
					str, port, kr_strerror(ret));
		}
		return ret == 0;
	}

	/* Last case: table where all entries are added recursively. */
	if (!lua_istable(L, -1))
		lua_error_p(L, "bad type for address");
	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (net_listen_addrs(L, port, flags) == 0)
			return 0;
		lua_pop(L, 1);
	}
	return 1;
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
	if (n > 1 && lua_isnumber(L, 2)) {
		port = lua_tointeger(L, 2);
	}

	bool tls = (port == KR_DNS_TLS_PORT);
	if (n > 2 && lua_istable(L, 3)) {
		tls = table_get_flag(L, 3, "tls", tls);
	}
	int flags = tls ? (NET_TCP|NET_TLS) : (NET_TCP|NET_UDP);

	/* Now focus on the first argument. */
	lua_pop(L, n - 1);
	int res = net_listen_addrs(L, port, flags);
	lua_pushboolean(L, res);
	return res;
}

/** Close endpoint. */
static int net_close(lua_State *L)
{
	/* Check parameters */
	int n = lua_gettop(L);
	if (n < 2)
		lua_error_p(L, "expected 'close(string addr, number port)'");

	/* Open resolution context cache */
	struct engine *engine = engine_luaget(L);
	int ret = network_close(&engine->net, lua_tostring(L, 1), lua_tointeger(L, 2));
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
		lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
		lua_setfield(L, -2, "addr");

		/* Hardware address. */
		char *p = buf;
		memset(buf, 0, sizeof(buf));
		for (unsigned k = 0; k < sizeof(iface.phys_addr); ++k) {
			sprintf(p, "%s%.2x", k > 0 ? ":" : "", iface.phys_addr[k] & 0xff);
			p += 3;
		}
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
	struct engine *engine = engine_luaget(L);
	knot_rrset_t *opt_rr = engine->resolver.opt_rr;
	if (!lua_isnumber(L, 1)) {
		lua_pushinteger(L, knot_edns_get_payload(opt_rr));
		return 1;
	}
	int bufsize = lua_tointeger(L, 1);
	if (bufsize < 512 || bufsize > UINT16_MAX)
		lua_error_p(L, "bufsize must be within <512, " STR(UINT16_MAX) ">");
	knot_edns_set_payload(opt_rr, (uint16_t) bufsize);
	return 0;
}

/** Set TCP pipelining size. */
static int net_pipeline(lua_State *L)
{
	struct worker_ctx *worker = wrk_luaget(L);
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
	struct engine *engine = engine_luaget(L);
	if (!engine) {
		return 0;
	}
	struct network *net = &engine->net;
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
			int err = base64_encode(e->pins.at[i], TLS_SHA256_RAW_LEN,
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
	struct network *net = &engine_luaget(L)->net;
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

	tls_client_param_t *e = tls_client_param_new();
	if (!e)
		lua_error_p(L, "out of memory or something like that :-/");
	/* Shortcut for cleanup actions needed from now on. */
	#define ERROR(...) do { \
		free(e); \
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
		e->hostname = h;
	}
	lua_pop(L, 1);

	/* .ca_file - it can be a list of paths, contrary to the name. */
	bool has_ca_file = false;
	lua_getfield(L, 1, "ca_file");
	if (!lua_isnil(L, -1)) {
		if (!e->hostname)
			ERROR("missing hostname but specifying ca_file");
		lua_listify(L);
		array_init(e->ca_files); /*< placate apparently confused scan-build */
		if (array_reserve(e->ca_files, lua_objlen(L, -1)) != 0) /*< optim. */
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
					e->credentials, ca_file, GNUTLS_X509_FMT_PEM);
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
			if (!ca_file || array_push(e->ca_files, ca_file) < 0)
				ERROR("%s", kr_strerror(ENOMEM));
		}
		/* Sort the strings for easier comparison later. */
		if (e->ca_files.len) {
			qsort(&e->ca_files.at[0], e->ca_files.len,
				sizeof(e->ca_files.at[0]), strcmp_p);
		}
	}
	lua_pop(L, 1);

	/* .pin_sha256 */
	lua_getfield(L, 1, "pin_sha256");
	if (!lua_isnil(L, -1)) {
		if (has_ca_file)
			ERROR("mixing pin_sha256 with ca_file is not supported");
		lua_listify(L);
		array_init(e->pins); /*< placate apparently confused scan-build */
		if (array_reserve(e->pins, lua_objlen(L, -1)) != 0) /*< optim. */
			ERROR("%s", kr_strerror(ENOMEM));
		/* Iterate over table at the top of the stack. */
		for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
			const char *pin = lua_tostring(L, -1);
			if (!pin)
				ERROR("pin_sha256 is not a string");
			uint8_t *pin_raw = malloc(TLS_SHA256_RAW_LEN);
			/* Push the string early to simplify error processing. */
			if (!pin_raw || array_push(e->pins, pin_raw) < 0) {
				assert(false);
				free(pin_raw);
				ERROR("%s", kr_strerror(ENOMEM));
			}
			int ret = base64_decode((const uint8_t *)pin, strlen(pin),
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
		if (e->pins.len) {
			qsort(&e->pins.at[0], e->pins.len,
				sizeof(e->pins.at[0]), cmp_sha256);
		}
	}
	lua_pop(L, 1);

	/* .insecure */
	lua_getfield(L, 1, "insecure");
	if (lua_isnil(L, -1)) {
		if (!e->hostname && !e->pins.len)
			ERROR("no way to authenticate and not set as insecure");
	} else if (lua_isboolean(L, -1) && lua_toboolean(L, -1)) {
		e->insecure = true;
		if (has_ca_file || e->pins.len)
			ERROR("set as insecure but provided authentication config");
	} else {
		ERROR("incorrect value in the 'insecure' field");
	}
	lua_pop(L, 1);

	/* Init CAs from system trust store, if needed. */
	if (!e->insecure && !e->pins.len && !has_ca_file) {
		int ret = gnutls_certificate_set_x509_system_trust(e->credentials);
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
	addr_str = kr_straddr_split(addr_str, buf, &port);
	/* Add e into the C map, saving the original into e0. */
	const struct sockaddr *addr = kr_straddr_socket(addr_str, port);
	if (!addr)
		lua_error_p(L, "address '%s' could not be converted", addr_str);
	tls_client_param_t **e0p = tls_client_param_getptr(
			&net->tls_client_params, addr, true);
	free_const(addr);
	if (!e0p)
		lua_error_p(L, "internal error when extending tls_client_params map");
	tls_client_param_t *e0 = *e0p;
	*e0p = e;
	/* If there was no original entry, it's easy! */
	if (!e0)
		return 0;

	/* Check for equality (e vs. e0), and print a warning if not equal.*/
	const bool ok_h = (!e->hostname && !e0->hostname)
		|| (e->hostname && e0->hostname && strcmp(e->hostname, e0->hostname) == 0);
	bool ok_ca = e->ca_files.len == e0->ca_files.len;
	for (int i = 0; ok_ca && i < e->ca_files.len; ++i)
		ok_ca = strcmp(e->ca_files.at[i], e0->ca_files.at[i]) == 0;
	bool ok_pins = e->pins.len == e0->pins.len;
	for (int i = 0; ok_pins && i < e->pins.len; ++i)
		ok_ca = memcmp(e->pins.at[i], e0->pins.at[i], TLS_SHA256_RAW_LEN) == 0;
	if (!(ok_h && ok_ca && ok_pins && e->insecure == e0->insecure)) {
		kr_log_info("[tls_client] "
			"warning: re-defining TLS authentication parameters for %s\n",
			addr_str);
	}
	tls_client_param_unref(e0);
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
	addr_str = kr_straddr_split(addr_str, buf, &port);
	const struct sockaddr *addr = kr_straddr_socket(addr_str, port);
	if (!addr)
		lua_error_p(L, "invalid IP address");
	/* Do the actual removal. */
	struct network *net = &engine_luaget(L)->net;
	int r = tls_client_param_remove(net->tls_client_params, addr);
	free_const(addr);
	lua_error_maybe(L, r);
	lua_pushboolean(L, true);
	return 1;
}

static int net_tls_padding(lua_State *L)
{
	struct engine *engine = engine_luaget(L);

	/* Only return current padding. */
	if (lua_gettop(L) == 0) {
		if (engine->resolver.tls_padding < 0) {
			lua_pushboolean(L, true);
			return 1;
		} else if (engine->resolver.tls_padding == 0) {
			lua_pushboolean(L, false);
			return 1;
		}
		lua_pushinteger(L, engine->resolver.tls_padding);
		return 1;
	}

	const char *errstr = "net.tls_padding parameter has to be true, false,"
				" or a number between <0, " STR(MAX_TLS_PADDING) ">";
	if (lua_gettop(L) != 1)
		lua_error_p(L, "%s", errstr);
	if (lua_isboolean(L, 1)) {
		bool x = lua_toboolean(L, 1);
		if (x) {
			engine->resolver.tls_padding = -1;
		} else {
			engine->resolver.tls_padding = 0;
		}
	} else if (lua_isnumber(L, 1)) {
		int padding = lua_tointeger(L, 1);
		if ((padding < 0) || (padding > MAX_TLS_PADDING))
			lua_error_p(L, "%s", errstr);
		engine->resolver.tls_padding = padding;
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
	struct network *net = &engine_luaget(L)->net;

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

	struct network *net = &engine_luaget(L)->net;

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
	struct worker_ctx *worker = wrk_luaget(L);
	union inaddr *addr;
	if (family == AF_INET)
		addr = (union inaddr*)&worker->out_addr4;
	else
		addr = (union inaddr*)&worker->out_addr6;

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
	struct engine *engine = engine_luaget(L);
	struct network *net = &engine->net;

	return net_update_timeout(L, &net->tcp.in_idle_timeout, "net.tcp_in_idle");
}

static int net_tls_handshake_timeout(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	struct network *net = &engine->net;

	return net_update_timeout(L, &net->tcp.tls_handshake_timeout, "net.tls_handshake_timeout");
}

static int net_bpf_set(lua_State *L)
{
	struct engine *engine = engine_luaget(L);
	struct network *net = &engine->net;

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

	if (network_set_bpf(net, progfd) == 0) {
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
	struct engine *engine = engine_luaget(L);
	struct network *net = &engine->net;

	if (lua_gettop(L) != 0)
		lua_error_p(L, "net.bpf_clear() does not take any parameters");

#if __linux__

	network_clear_bpf(net);

	lua_pushboolean(L, 1);
	return 1;

#endif
	lua_error_p(L, "BPF is not supported on this operating system");
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
		{ NULL, NULL }
	};
	register_lib(L, "net", lib);
	return 1;
}

