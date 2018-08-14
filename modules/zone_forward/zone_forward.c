#include "lib/module.h"
#include "lib/resolve.h"
#include "lib/utils.h"
#include <ccan/json/json.h>
#include <libknot/rdata.h>
#include <libknot/rrtype/opt.h>

/**
 * Module inserts synthetic zone cut for forwarded zones.
 *
 * Needs to run before iterate, otherwise query minimization works incorrectly.
 *
 * TODO:
 *
 * - How to control if DNSSEC should be enabled or disabled.
 * - How to configure port number for the zone cut.
 * - How to disable cache just for queries for the forwarded zone.
 * - How the config should look like.
 * - How to make it scale for thousands of zones.
 * - Should this be part of policy module.
 */

#define LOG(fmt, args...) kr_log_info("[     ][zfwd]   " fmt "\n", ##args)

struct zone_forward_ctx {
	knot_dname_t *zone;
	struct sockaddr *server;
};

KR_EXPORT
int zone_forward_init(struct kr_module *module)
{
	struct zone_forward_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return kr_error(KNOT_ENOMEM);
	}

	module->data = ctx;

	return kr_ok();
}

KR_EXPORT
int zone_forward_deinit(struct kr_module *module)
{
	struct zone_forward_ctx *ctx = module->data;

	knot_dname_free(&ctx->zone, NULL);
	free(ctx->server);

	free(ctx);

	return kr_ok();
}

static char *zone_forward_config(void *env, struct kr_module *module, const char *json)
{
	struct zone_forward_ctx *ctx = module->data;

	if (!json) {
		return NULL;
	}

	JsonNode *root = json_decode(json);
	if (!root) {
		return NULL;
	}

	if (root->tag != JSON_OBJECT) {
		json_delete(root);
		return NULL;
	}

	JsonNode *node = NULL;
	json_foreach(node, root) {
		if (node->tag != JSON_STRING) {
			continue;
		}

		if (strcmp(node->key, "zone") == 0) {
			knot_dname_t *zone = knot_dname_from_str_alloc(node->string_);
			if (zone) {
				knot_dname_free(&ctx->zone, NULL);
				ctx->zone = zone;
			}
		} else if (strcmp(node->key, "ip") == 0) {
			struct sockaddr *sock = kr_straddr_socket(node->string_, 0);
			if (sock) {
				free(ctx->server);
				ctx->server = sock;
			}
		}
	}

	json_delete(root);
	return NULL;
}

static void inject_zone_cut(struct kr_zonecut *cut, const struct zone_forward_ctx *ctx)
{
	char cut_str[256] = {0};
	knot_dname_to_str(cut_str, ctx->zone, sizeof(cut_str));
	char addr_str[256] = {0};
	size_t addr_size = sizeof(addr_str);
	kr_inaddr_str(ctx->server, addr_str, &addr_size);
	LOG("injecting zone cut for '%s' to '%s'", cut_str, addr_str);

	const size_t rdlen = kr_inaddr_len(ctx->server);
	const uint8_t *data = (uint8_t *)kr_inaddr(ctx->server);

	size_t size = knot_rdata_array_size(rdlen);
	uint8_t rdata[size];
	memset(rdata, 0, sizeof(rdata));
	knot_rdata_init(rdata, rdlen, data, 0);

	kr_zonecut_init(cut, ctx->zone, cut->pool);
	kr_zonecut_add(cut, (const uint8_t *)"", rdata);
}

static int produce(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_module *mod = ctx->api->data;
	struct zone_forward_ctx *fwd = mod->data;

	if (!fwd->server || !fwd->zone) {
		return ctx->state;
	}

	struct kr_query *cur = ctx->req->current_query;
	if (!trie_empty(cur->zone_cut.nsset) || !knot_dname_in(fwd->zone, cur->sname)) {
		return ctx->state;
	}

	inject_zone_cut(&cur->zone_cut, fwd);

	cur->flags.NO_CACHE = true;
	cur->flags.DNSSEC_WANT = false;
	cur->flags.KEEP_CUT = true;

	return ctx->state;
}

KR_EXPORT
struct kr_prop *zone_forward_props(void)
{
	static struct kr_prop props[] = {
		{ zone_forward_config, "config", "Configure zone forward." },
		{ NULL },
	};

	return props;
}

KR_EXPORT
const kr_layer_api_t *zone_forward_layer(struct kr_module *module)
{
	static kr_layer_api_t layer = {
		.produce = produce,
	};

	layer.data = module;

	return &layer;
}

KR_MODULE_EXPORT(zone_forward);
