/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

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
 * @brief Check whether node holds proper 'enabled' value.
 * @patam node JSON node holding the value
 * @return true if value OK
 */
static bool enabled_ok(const JsonNode *node)
{
	if (!kr_assume(node))
		return false;

	return node->tag == JSON_BOOL;
}

/**
 * @brief Check whether node holds proper 'secret' value.
 * @patam node JSON node holding the value
 * @return true if value OK
 */
static bool secret_ok(const JsonNode *node)
{
	if (!kr_assume(node))
		return false;

	if (node->tag != JSON_STRING) {
		return false;
	}

	const char *hexstr = node->string_;

	size_t len = strlen(hexstr);
	if ((len % 2) != 0) {
		return false;
	}
	/* A check for minimal required length could also be performed. */

	for (size_t i = 0; i < len; ++i) {
		if (!isxdigit(tolower(hexstr[i]))) {
			return false;
		}
	}

	return true;
}

/**
 * @brief Find hash function with given name.
 * @param node JSON node holding the value
 * @param table lookup table with algorithm names
 * @return pointer to table entry or NULL on error if does not exist
 */
static const knot_lookup_t *hash_func_lookup(const JsonNode *node,
                                             const knot_lookup_t table[])
{
	if (!node || node->tag != JSON_STRING) {
		return NULL;
	}

	return knot_lookup_by_name(table, node->string_);
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
	} else if ((0x0a <= i) && (i <= 0x0f)) {
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
	if (!kr_assume(dhi != -1))
		return -1;
	dlo = hexchar2val(dlo);
	if (!kr_assume(dlo != -1))
		return -1;

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
	if (!kr_assume(ilo != -1))
		return -1;
	int ihi = hexval2char((i >> 4) & 0x0f);
	if (!kr_assume(ihi != -1))
		return -1;

	tgt[0] = ihi;
	tgt[1] = ilo;

	return 0;
}

/**
 * @brief Reads a string containing hexadecimal values.
 * @note String must consist of hexadecimal digits only and must have even
 *       non-zero length.
 */
static struct kr_cookie_secret *new_sq_from_hexstr(const char *hexstr)
{
	if (!hexstr) {
		return NULL;
	}

	size_t len = strlen(hexstr);
	if ((len % 2) != 0) {
		return NULL;
	}

	struct kr_cookie_secret *sq = new_cookie_secret(len / 2, false);
	if (!sq) {
		return NULL;
	}

	uint8_t *data = sq->data;
	for (size_t i = 0; i < len; i += 2) {
		int num = hexbyte2int(hexstr + i);
		if (num == -1) {
			free(sq);
			return NULL;
		}
		if (!kr_assume(0x00 <= num && num <= 0xff)) {
			free(sq);
			return NULL;
		}
		*data = num;
		++data;
	}

	return sq;
}

/**
 * @brief Creates new secret.
 * @patam node JSON node holding the secret value
 * @return pointer to newly allocated secret, NULL on error
 */
static struct kr_cookie_secret *create_secret(const JsonNode *node)
{
	if (!node) {
		return NULL;
	}

	if (node->tag != JSON_STRING) {
		return NULL;
	}

	return new_sq_from_hexstr(node->string_);
}

/**
 * @brief Check whether configuration node contains valid values.
 */
static bool configuration_node_ok(const JsonNode *node)
{
	if (!kr_assume(node))
		return false;

	if (!node->key) {
		/* All top most nodes must have names. */
		return false;
	}

	if (strcmp(node->key, NAME_CLIENT_ENABLED) == 0) {
		return enabled_ok(node);
	} else if (strcmp(node->key, NAME_CLIENT_SECRET) == 0) {
		return secret_ok(node);
	} else  if (strcmp(node->key, NAME_CLIENT_COOKIE_ALG) == 0) {
		return hash_func_lookup(node, kr_cc_alg_names) != NULL;
	} else if (strcmp(node->key, NAME_SERVER_ENABLED) == 0) {
		return enabled_ok(node);
	} else if (strcmp(node->key, NAME_SERVER_SECRET) == 0) {
		return secret_ok(node);
	} else if (strcmp(node->key, NAME_SERVER_COOKIE_ALG) == 0) {
		return hash_func_lookup(node, kr_sc_alg_names) != NULL;
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
	if (!kr_assume(root && node_name && secret))
		return false;

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
	if (!kr_assume(root && root_name && table))
		return false;

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

/**
 * @brief Check whether new settings are different from the old ones.
 */
static bool is_modified(const struct kr_cookie_comp *running,
                        struct kr_cookie_secret *secr,
                        const knot_lookup_t *alg_lookup)
{
	if (!kr_assume(running))
		return false;

	if (alg_lookup && alg_lookup->id >= 0) {
		if (running->alg_id != alg_lookup->id) {
			return true;
		}
	}

	if (secr) {
		if (!kr_assume(secr->size > 0))
			return false;
		if (running->secr->size != secr->size ||
		    0 != memcmp(running->secr->data, secr->data,
		                running->secr->size)) {
			return true;
		}
	}

	return false;
}

/**
 * @brief Returns newly allocated secret via pointer argument.
 */
static bool obtain_secret(JsonNode *root_node, struct kr_cookie_secret **secret,
                          const char *name)
{
	if (!kr_assume(secret && name))
		return false;

	const JsonNode *node;
	if ((node = json_find_member(root_node, name)) != NULL) {
		*secret = create_secret(node);
		if (!*secret) {
			return false;
		}
	}

	return true;
}

/**
 * @brief Updates the current configuration and moves current to recent.
 */
static void update_running(struct kr_cookie_settings *running,
                           struct kr_cookie_secret **secret,
                           const knot_lookup_t *alg_lookup)
{
	if (!kr_assume(running && secret) || !kr_assume(*secret || alg_lookup))
		return;

	running->recent.alg_id = -1;
	free(running->recent.secr);
	running->recent.secr = NULL;

	running->recent.alg_id = running->current.alg_id;
	if (alg_lookup) {
		if (!kr_assume(alg_lookup->id >= 0))
			return;
		running->current.alg_id = alg_lookup->id;
	}

	if (*secret) {
		running->recent.secr = running->current.secr;
		running->current.secr = *secret;
		*secret = NULL;
	} else {
		running->recent.secr = clone_cookie_secret(running->current.secr);
	}
}

/**
 * @brief Applies modification onto client/server running configuration.
 * @note The @a secret is going to be consumed.
 * @param secret pointer to new secret
 * @param alg_lookup new algorithm
 * @param enabled JSON node holding boolean value
 */
static void apply_changes(struct kr_cookie_settings *running,
                          struct kr_cookie_secret **secret,
                          const knot_lookup_t *alg_lookup,
                          const JsonNode *enabled)
{
	if (!kr_assume(running && secret))
		return;

	if (is_modified(&running->current, *secret, alg_lookup)) {
		update_running(running, secret, alg_lookup);
	}

	if (enabled) {
		(void)!kr_assume(enabled->tag == JSON_BOOL);
		running->enabled = enabled->bool_;
	}
}

/**
 * @brief Applies configuration.
 *
 * @note The function must be called after the input values have been checked
 *       for validity. Only first found values are applied.
 *
 * @param ctx cookie configuration context
 * @param root_node JSON root node
 * @return true if changes were applied
 */
static bool config_apply_json(struct kr_cookie_ctx *ctx, JsonNode *root_node)
{
	if (!kr_assume(ctx && root_node))
		return;

	/*
	 * These must be allocated before actual change. Allocation failure
	 * should not leave configuration in inconsistent state.
	 */
	struct kr_cookie_secret *new_clnt_secret = NULL;
	struct kr_cookie_secret *new_srvr_secret = NULL;
	if (!obtain_secret(root_node, &new_clnt_secret, NAME_CLIENT_SECRET)) {
		return false;
	}
	if (!obtain_secret(root_node, &new_srvr_secret, NAME_SERVER_SECRET)) {
		free(new_clnt_secret);
		return false;
	}

	/* Algorithm pointers. */
	const knot_lookup_t *clnt_lookup = hash_func_lookup(json_find_member(root_node, NAME_CLIENT_COOKIE_ALG), kr_cc_alg_names);
	const knot_lookup_t *srvr_lookup = hash_func_lookup(json_find_member(root_node, NAME_SERVER_COOKIE_ALG), kr_sc_alg_names);

	const JsonNode *clnt_enabled_node = json_find_member(root_node, NAME_CLIENT_ENABLED);
	const JsonNode *srvr_enabled_node = json_find_member(root_node, NAME_SERVER_ENABLED);

	apply_changes(&ctx->clnt, &new_clnt_secret, clnt_lookup, clnt_enabled_node);
	apply_changes(&ctx->srvr, &new_srvr_secret, srvr_lookup, srvr_enabled_node);

	/*
	 * Allocated secrets should be already consumed. There is no need to
	 * free them.
	 */

	return true;
}

bool config_apply(struct kr_cookie_ctx *ctx, const char *args)
{
	if (!ctx) {
		return false;
	}

	if (!args || !strlen(args)) {
		return true;
	}

	if (!args || !strlen(args)) {
		return true;
	}

	bool success = false;

	/* Check whether all supplied data are valid. */
	JsonNode *root_node = json_decode(args);
	if (!root_node) {
		return false;
	}
	JsonNode *node;
	json_foreach (node, root_node) {
		success = configuration_node_ok(node);
		if (!success) {
			break;
		}
	}

	/* Apply configuration if values seem to be OK. */
	if (success) {
		success = config_apply_json(ctx, root_node);
	}

	json_delete(root_node);

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
		return kr_error(ENOENT);
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
