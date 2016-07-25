/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <ccan/json/json.h>
#include <ctype.h>
#include <libknot/rrtype/opt-cookie.h>
#include <libknot/db/db_lmdb.h>
#include <stdlib.h>
#include <string.h>

#include "lib/cookies/alg_containers.h"
#include "modules/cookies/cookiectl.h"

#define NAME_CLIENT_ENABLED "client_enabled"
#define NAME_CLIENT_SECRET "client_secret"
#define NAME_CLIENT_COOKIE_ALG "client_cookie_alg"
#define NAME_AVAILABLE_CLIENT_COOKIE_ALGS "available_client_cookie_algs"

#define NAME_SERVER_ENABLED "server_enabled"
#define NAME_SERVER_SECRET "server_secret"
#define NAME_SERVER_COOKIE_ALG "server_cookie_alg"
#define NAME_AVAILABLE_SERVER_COOKIE_ALGS "available_server_cookie_algs"

/**
 * @brief Initialises cookie control context.
 * @param ctx cookie control context
 */
static void kr_cookie_ctx_init(struct kr_cookie_ctx *ctx)
{
	if (!ctx) {
		return;
	}

	memset(ctx, 0, sizeof(*ctx));

	ctx->clnt.current.alg_id = ctx->clnt.recent.alg_id = -1;
	ctx->srvr.current.alg_id = ctx->srvr.recent.alg_id = -1;
}

/**
 * @brief Sets boolean value according to content of JSON node.
 * @param enabled boolean value to be set
 * @patam node JSON node holding the value
 * @return true if proper value has been set, false on error
 */
static bool apply_enabled(bool *enabled, const JsonNode *node)
{
	assert(enabled && node);

	if (node->tag == JSON_BOOL) {
		*enabled = node->bool_;
		return true;
	}

	return false;
}

/**
 * @brief Creates a cookie secret structure.
 * @param size size of the actual secret
 * @param zero set to true if value should be cleared
 * @return pointer to new structure, NULL on failure or if @size is zero
 */
static struct kr_cookie_secret *new_cookie_secret(size_t size, bool zero)
{
	if (size == 0) {
		return NULL;
	}

	struct kr_cookie_secret *sq = malloc(sizeof(*sq) + size);
	if (!sq) {
		return NULL;
	}

	sq->size = size;
	if (zero) {
		memset(sq->data, 0, size);
	}
	return sq;
}

/**
 * @brief Clone a cookie secret.
 * @param sec secret to be cloned
 * @return pointer to new structure, NULL on failure or if @size is zero
 */
static struct kr_cookie_secret *clone_cookie_secret(const struct kr_cookie_secret *sec)
{
	if (!sec || sec->size == 0) {
		return NULL;
	}

	struct kr_cookie_secret *sq = malloc(sizeof(*sq) + sec->size);
	if (!sq) {
		return NULL;
	}

	sq->size = sec->size;
	memcpy(sq->data, sec->data, sq->size);
	return sq;
}

static int hexchar2val(int d)
{
	if (('0' <= d) && (d <= '9')) {
		return d - '0';
	} else if (('a' <= d) && (d <= 'f')) {
		return d - 'a' + 0x0a;
	} else {
		return -1;
	}
}

static int hexval2char(int i)
{
	if ((0 <= i) && (i <= 9)) {
		return i + '0';
	} if ((0x0a <= i) && (i <= 0x0f)) {
		return i - 0x0a + 'A';
	} else {
		return -1;
	}
}

/**
 * @brief Converts string containing two-digit hexadecimal number into int.
 * @param hexstr hexadecimal string
 * @return -1 on error, value from 0 to 255 else.
 */
static int hexbyte2int(const char *hexstr)
{
	if (!hexstr) {
		return -1;
	}

	int dhi = tolower(hexstr[0]);
	if (!isxdigit(dhi)) {
		/* Exit also on empty string. */
		return -1;
	}
	int dlo = tolower(hexstr[1]);
	if (!isxdigit(dlo)) {
		return -1;
	}

	dhi = hexchar2val(dhi);
	assert(dhi != -1);
	dlo = hexchar2val(dlo);
	assert(dlo != -1);

	return (dhi << 4) | dlo;
}

/**
 * @brief Writes two hexadecimal digits (two byes) into given memory location.
 * @param tgt target location
 * @param i number from 0 to 255
 * @return 0 on success, -1 on failure
 */
static int int2hexbyte(char *tgt, int i)
{
	if (!tgt || i < 0x00 || i > 0xff) {
		return -1;
	}

	int ilo = hexval2char(i & 0x0f);
	assert(ilo != -1);
	int ihi = hexval2char((i >> 4) & 0x0f);
	assert(ihi != -1);

	tgt[0] = ihi;
	tgt[1] = ilo;

	return 0;
}

/**
 * @brief Reads a string containing hexadecimal values.
 * @note String must consist of hexadecimal digits only and must have even
 *       non-zero length.
 */
static struct kr_cookie_secret *new_sq_from_hexstr(const JsonNode *node)
{
	assert(node && node->tag == JSON_STRING);

	size_t len = strlen(node->string_);
	if ((len % 2) != 0) {
		return NULL;
	}

	struct kr_cookie_secret *sq = new_cookie_secret(len / 2, false);
	if (!sq) {
		return NULL;
	}

	const char *hexstr = node->string_;
	uint8_t *data = sq->data;
	for (size_t i = 0; i < len; i += 2) {
		int num = hexbyte2int(hexstr + i);
		if (num == -1) {
			free(sq);
			return NULL;
		}
		assert(0x00 <= num && num <= 0xff);
		*data = num;
		++data;
	}

	return sq;
}

/**
 * @brief Sets secret value according to content onto shallow copy.
 * @param sec newly created secret
 * @patam node JSON node holding the value
 * @return true if proper value has been set, false on error
 */
static bool apply_secret_shallow(struct kr_cookie_secret **sec,
                                 const JsonNode *node)
{
	assert(sec && node);

	struct kr_cookie_secret *sq = NULL;

	switch (node->tag) {
	case JSON_STRING:
		free(sq); /* Delete values that may have bee set previously. */
		sq = new_sq_from_hexstr(node);
		break;
	default:
		break;
	}

	if (!sq) {
		return false;
	}

	/* Overwrite data. */
	*sec = sq;

	return true;
}

/**
 * @brief Sets hash function value according to content of JSON node.
 * @param alg_id algorithm identifier to be set
 * @patam node JSON node holding the value
 * @param table lookup table with algorithm names
 * @return true if proper value has been set, false on error
 */
static bool apply_hash_func(int *alg_id, const JsonNode *node,
                            const knot_lookup_t table[])
{
	assert(alg_id && node && table);

	if (node->tag == JSON_STRING) {
		const knot_lookup_t *lookup = knot_lookup_by_name(table,
		                                                  node->string_);
		if (!lookup) {
			return false;
		}
		*alg_id = lookup->id;
		return true;
	}

	return false;
}

/**
 * @brief Applies configuration onto a shallow cookie configuration structure
 *        copy.
 */
static bool apply_configuration_shallow(struct kr_cookie_ctx *cntrl,
                                        const JsonNode *node)
{
	assert(cntrl && node);

	if (!node->key) {
		/* All top most nodes must have names. */
		return false;
	}

	if (strcmp(node->key, NAME_CLIENT_ENABLED) == 0) {
		return apply_enabled(&cntrl->clnt.enabled, node);
	} else if (strcmp(node->key, NAME_CLIENT_SECRET) == 0) {
		return apply_secret_shallow(&cntrl->clnt.current.secr, node);
	} else  if (strcmp(node->key, NAME_CLIENT_COOKIE_ALG) == 0) {
		return apply_hash_func(&cntrl->clnt.current.alg_id, node,
		                       kr_cc_alg_names);
	} else if (strcmp(node->key, NAME_SERVER_ENABLED) == 0) {
		return apply_enabled(&cntrl->srvr.enabled, node);
	} else if (strcmp(node->key, NAME_SERVER_SECRET) == 0) {
		return apply_secret_shallow(&cntrl->srvr.current.secr, node);
	} else if (strcmp(node->key, NAME_SERVER_COOKIE_ALG) == 0) {
		return apply_hash_func(&cntrl->srvr.current.alg_id, node,
		                       kr_sc_alg_names);
	}

	return false;
}

/**
 * @brief Creates a new string from secret quantity.
 * @param sq secret quantity
 * @return newly allocated string or NULL on error
 */
static char *new_hexstr_from_sq(const struct kr_cookie_secret *sq)
{
	if (!sq) {
		return NULL;
	}

	char *new_str = malloc((sq->size * 2) + 1);
	if (!new_str) {
		return NULL;
	}

	char *tgt = new_str;
	for (size_t i = 0; i < sq->size; ++i) {
		if (0 != int2hexbyte(tgt, sq->data[i])) {
			free(new_str);
			return NULL;
		}
		tgt += 2;
	}

	*tgt = '\0';
	return new_str;
}

static bool read_secret(JsonNode *root, const char *node_name,
                        const struct kr_cookie_secret *secret)
{
	assert(root && node_name && secret);

	char *secret_str = new_hexstr_from_sq(secret);
	if (!secret_str) {
		return false;
	}

	JsonNode *str_node = json_mkstring(secret_str);
	if (!str_node) {
		free(secret_str);
		return false;
	}

	json_append_member(root, node_name, str_node);

	free(secret_str);
	return true;
}

static bool read_available_hashes(JsonNode *root, const char *root_name,
                                  const knot_lookup_t table[])
{
	assert(root && root_name && table);

	JsonNode *array = json_mkarray();
	if (!array) {
		return false;
	}

	const knot_lookup_t *aux_ptr = table;
	while (aux_ptr && (aux_ptr->id >= 0) && aux_ptr->name) {
		JsonNode *element = json_mkstring(aux_ptr->name);
		if (!element) {
			goto fail;
		}
		json_append_element(array, element);
		++aux_ptr;
	}

	json_append_member(root, root_name, array);

	return true;

fail:
	if (array) {
		json_delete(array);
	}
	return false;
}

static bool modified_in_shallow(const struct kr_cookie_comp *running,
                                const struct kr_cookie_comp *shallow)
{
	assert(running && shallow && running->secr && running->alg_id >= 0);

	bool ret = false;

	if (shallow->alg_id >= 0) {
		if (running->alg_id != shallow->alg_id) {
			return true;
		}
	}


	if (shallow->secr) {
		assert(shallow->secr->size > 0);
		if (running->secr->size != shallow->secr->size ||
		    0 != memcmp(running->secr->data, shallow->secr->data,
		                running->secr->size)) {
			return true;
		}
	}

	return false;
}

static void apply_settings_from_copy(struct kr_cookie_settings *running,
                                     struct kr_cookie_settings *shallow)
{
	free(running->recent.secr); /* Delete old secret. */
	running->recent = running->current; /* Current becomes recent. */

	if (shallow->current.secr) {
		/* Use new secret. */
		running->current.secr = shallow->current.secr;
		shallow->current.secr = NULL; /* Must be zeroed. */
	} else {
		/* Create a copy of secret but store it into recent. */
		running->current.secr = running->recent.secr;
		running->recent.secr = clone_cookie_secret(running->current.secr);
		if (!running->recent.secr) {
			/* Properly invalidate recent. */
			running->recent.alg_id = -1;
		}
	}

	if (shallow->current.alg_id >= 0) {
		running->current.alg_id = shallow->current.alg_id;
	}
}

static void apply_ctx_from_copy(struct kr_cookie_ctx *running,
                                struct kr_cookie_ctx *shallow)
{
	assert(running && shallow);

	if (modified_in_shallow(&running->clnt.current, &shallow->clnt.current)) {
		apply_settings_from_copy(&running->clnt, &shallow->clnt);
		/* Shallow will be deleted after this function call. */
	}

	if (modified_in_shallow(&running->srvr.current, &shallow->srvr.current)) {
		apply_settings_from_copy(&running->srvr, &shallow->srvr);
		/* Shallow will be deleted after this function call. */
	}

	/* Direct application. */
	running->clnt.enabled = shallow->clnt.enabled;
	running->srvr.enabled = shallow->srvr.enabled;
}

bool config_apply(struct kr_cookie_ctx *ctx, const char *args)
{
	if (!ctx) {
		return false;
	}

	if (!args || !strlen(args)) {
		return true;
	}

	/* Basically, copy only `enabled` values. */
	struct kr_cookie_ctx shallow_copy;
	kr_cookie_ctx_init(&shallow_copy);
	shallow_copy.clnt.enabled = ctx->clnt.enabled;
	shallow_copy.srvr.enabled = ctx->srvr.enabled;

	bool success = true;

	if (!args || !strlen(args)) {
		return success;
	}

	JsonNode *node;
	JsonNode *root_node = json_decode(args);
	json_foreach (node, root_node) {
		success = apply_configuration_shallow(&shallow_copy, node);
		if (!success) {
			break;
		}
	}
	json_delete(root_node);

	if (success) {
		apply_ctx_from_copy(ctx, &shallow_copy);
	}

	/* Clean possible residues of newly allocated data. */
	free(shallow_copy.clnt.current.secr);
	assert(!shallow_copy.clnt.recent.secr);
	free(shallow_copy.srvr.current.secr);
	assert(!shallow_copy.srvr.recent.secr);

	return success;
}

char *config_read(struct kr_cookie_ctx *ctx)
{
	if (!ctx) {
		return NULL;
	}

	const knot_lookup_t *lookup;
	char *result;
	JsonNode *root_node = json_mkobject();
	if (!root_node) {
		return NULL;
	}

	json_append_member(root_node, NAME_CLIENT_ENABLED,
	                   json_mkbool(ctx->clnt.enabled));

	read_secret(root_node, NAME_CLIENT_SECRET, ctx->clnt.current.secr);

	lookup = knot_lookup_by_id(kr_cc_alg_names, ctx->clnt.current.alg_id);
	if (lookup) {
		json_append_member(root_node, NAME_CLIENT_COOKIE_ALG,
		                   json_mkstring(lookup->name));
	}

	read_available_hashes(root_node, NAME_AVAILABLE_CLIENT_COOKIE_ALGS,
	                      kr_cc_alg_names);

	json_append_member(root_node, NAME_SERVER_ENABLED,
	                   json_mkbool(ctx->srvr.enabled));

	read_secret(root_node, NAME_SERVER_SECRET, ctx->srvr.current.secr);

	lookup = knot_lookup_by_id(kr_sc_alg_names, ctx->srvr.current.alg_id);
	if (lookup) {
		json_append_member(root_node, NAME_SERVER_COOKIE_ALG,
		                   json_mkstring(lookup->name));
	}

	read_available_hashes(root_node, NAME_AVAILABLE_SERVER_COOKIE_ALGS,
	                      kr_sc_alg_names);

	result = json_encode(root_node);
	json_delete(root_node);
	return result;
}

int config_init(struct kr_cookie_ctx *ctx)
{
	if (!ctx) {
		return kr_error(EINVAL);
	}

	kr_cookie_ctx_init(ctx);

	struct kr_cookie_secret *cs = new_cookie_secret(KNOT_OPT_COOKIE_CLNT,
	                                                true);
	struct kr_cookie_secret *ss = new_cookie_secret(KNOT_OPT_COOKIE_CLNT,
	                                                true);
	if (!cs || !ss) {
		free(cs);
		free(ss);
		return kr_error(ENOMEM);
	}

	const knot_lookup_t *clookup = knot_lookup_by_name(kr_cc_alg_names,
	                                                   "FNV-64");
	const knot_lookup_t *slookup = knot_lookup_by_name(kr_sc_alg_names,
	                                                   "FNV-64");
	if (!clookup || !slookup) {
		free(cs);
		free(ss);
		return kr_error(ENOKEY);
	}

	ctx->clnt.current.secr = cs;
	ctx->clnt.current.alg_id = clookup->id;

	ctx->srvr.current.secr = ss;
	ctx->srvr.current.alg_id = slookup->id;

	return kr_ok();
}

void config_deinit(struct kr_cookie_ctx *ctx)
{
	if (!ctx) {
		return;
	}

	ctx->clnt.enabled = false;

	free(ctx->clnt.recent.secr);
	ctx->clnt.recent.secr = NULL;

	free(ctx->clnt.current.secr);
	ctx->clnt.current.secr = NULL;

	ctx->srvr.enabled = false;

	free(ctx->srvr.recent.secr);
	ctx->srvr.recent.secr = NULL;

	free(ctx->srvr.current.secr);
	ctx->srvr.current.secr = NULL;
}
