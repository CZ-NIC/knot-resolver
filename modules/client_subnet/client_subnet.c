
#include <arpa/inet.h>

#include <maxminddb.h>
#include <libknot/descriptor.h>

#include "lib/client_subnet.h"
#include "lib/module.h"
#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/utils.h"

#define MSG(type, fmt...) kr_log_##type ("[module client subnet]: " fmt)

typedef struct kr_ecs data_t;

/** Fill kr_query::client_subnet appropriately (a data_t instance). */
static int begin(knot_layer_t *ctx, void *module_param)
{
	(void)module_param;
	struct kr_module *module = ctx->api->data;
	MMDB_s *mmdb = module->data;
	if (!mmdb->filename) /* DB not loaded successfully; go without ECS. */
		return kr_ok();
	// FIXME: TMP DEBUG
	//kr_log_info("[module client_subnet]: db %s\n", mmdb->filename);

	struct kr_request *req = ctx->data;
	struct kr_query *qry = req->current_query;
	assert(!qry->parent && !qry->ecs);
	//kr_log_info("[module client_subnet]: qry %s\n", qry->sname);

	if (qry->sclass != KNOT_CLASS_IN)
		return kr_ok();

	data_t *data = mm_alloc(&req->pool, sizeof(data_t));
	qry->ecs = data;

	/* TODO: the RFC requires in 12.1 that we should avoid ECS on public suffixes
	 * https://publicsuffix.org but we only check very roughly (number of labels).
	 * Perhaps use some library, e.g. http://stricaud.github.io/faup/ */
	if (knot_dname_labels(qry->sname, NULL) <= 1) {
		data->loc_len = 0;
		return kr_ok();
	}

	/* Determine ecs_addr: the address to look up in DB. */
	const struct sockaddr *ecs_addr = NULL;
	struct sockaddr_storage ecs_addr_storage;
       	uint8_t *ecs_wire = req->qsource.opt == NULL ? NULL :
		knot_edns_get_option(req->qsource.opt, KNOT_EDNS_OPTION_CLIENT_SUBNET);
	data->is_explicit = ecs_wire != NULL; /* explicit ECS request */
	if (data->is_explicit) {
		uint8_t *ecs_data = knot_edns_opt_get_data(ecs_wire);
		uint16_t ecs_len = knot_edns_opt_get_length(ecs_wire);
		int err = knot_edns_client_subnet_parse(&data->query_ecs, ecs_data, ecs_len);
		if (err == KNOT_EOK)
			err = knot_edns_client_subnet_get_addr(&ecs_addr_storage, &data->query_ecs);
		if (err != KNOT_EOK || data->query_ecs.scope_len != 0) {
			MSG(debug, "request with malformed client subnet or family\n");
			knot_wire_set_rcode(req->answer->wire, KNOT_RCODE_FORMERR);
			qry->ecs = NULL;
			mm_free(&req->pool, data);
			return KNOT_STATE_FAIL | KNOT_STATE_DONE;
		}
		ecs_addr = (struct sockaddr *)&ecs_addr_storage;
	} else {
		/* We take the full client's address, but that shouldn't matter
		 * for privacy as we only use the location code inferred from it. */
		ecs_addr = req->qsource.addr;
	}

	/* Explicit /0 special case. */
	if (data->is_explicit && data->query_ecs.source_len == 0) {
		data->loc_len = 1;
		data->loc[0] = '0';
		return kr_ok();
	}

	/* Now try to find a corresponding DB entry and fill data->loc*. */
	int err;
	MMDB_lookup_result_s lookup_result = MMDB_lookup_sockaddr(mmdb, ecs_addr, &err);
	if (err != MMDB_SUCCESS)
		goto err_db;
	if (!lookup_result.found_entry)
		goto err_not_found;
	MMDB_entry_data_s entry;
	err = MMDB_get_value(&lookup_result.entry, &entry, "country", "iso_code", NULL);
	if (err != MMDB_SUCCESS)
		goto err_db;
		/* The ISO code is supposed to be two characters. */
	if (!entry.has_data || entry.type != MMDB_DATA_TYPE_UTF8_STRING || entry.data_size != 2)
		goto err_not_found;
	data->loc_len = entry.data_size;
	memcpy(data->loc, entry.utf8_string, data->loc_len);

	/* Esure data->query_ecs contains correct address, source_len, and also
	 * scope_len for answer. We take the prefix lengths from the database. */
	if (!data->is_explicit) {
		knot_edns_client_subnet_set_addr(&data->query_ecs,
						 (struct sockaddr_storage *)ecs_addr);
			/* ^ not very efficient way but should be OK */
		data->query_ecs.source_len = lookup_result.netmask;
	}
	data->query_ecs.scope_len = lookup_result.netmask;

	return kr_ok();

err_db:
	MSG(error, "GEO DB failure: %s\n", MMDB_strerror(err));
	qry->ecs = NULL;
	mm_free(&req->pool, data);
	return kr_ok(); /* Go without ECS. */

err_not_found:;
	char addr_str[INET6_ADDRSTRLEN];
	if (NULL == inet_ntop(ecs_addr->sa_family, ecs_addr->sa_data,
				addr_str, sizeof(addr_str)))
	{
		addr_str[0] = '\0';
	}
	MSG(debug, "location of client's address not found: '%s'\n", addr_str);
	qry->ecs = NULL;
	mm_free(&req->pool, data);
	return kr_ok(); /* Go without ECS. */

#if 0
	assert(!qry->ecs);
	/* Only consider ECS for original request, not sub-queries. */
	if (qry->parent)
		return ctx->state;


	if (ctx->state & (KNOT_STATE_FAIL|KNOT_STATE_DONE))
		return ctx->state; /* Already resolved/failed */
	if (qry->ns.addr[0].ip.sa_family != AF_UNSPEC)
		return ctx->state; /* Only lookup before asking a query */

	return ctx->state;
#endif
}



/* Only uninteresting stuff till the end of the file. */

static int load(struct kr_module *module, const char *db_path)
{
	MMDB_s *mmdb = module->data;
	assert(mmdb);
	int err = MMDB_open(db_path, 0/*defaults*/, mmdb);
	if (!err) {
		kr_log_info("[module client_subnet]: geo DB loaded succesfully\n");
		return kr_ok();
	}
	mmdb->filename = NULL;
	kr_log_error("[module client_subnet]: failed to open the database\n");
	return kr_error(999/*TODO: no suitable code?*/);
}

static void unload(struct kr_module *module)
{
	MMDB_s *mmdb = module->data;
	if (!mmdb->filename)
		return;
	MMDB_close(mmdb);
	mmdb->filename = NULL;
}

/** Module implementation. */
KR_EXPORT
const knot_layer_api_t *client_subnet_layer(struct kr_module *module)
{
	static knot_layer_api_t _layer = {
		.begin = begin,
		.data = NULL,
	};

	_layer.data = module;
	return &_layer;
}

KR_EXPORT
int client_subnet_init(struct kr_module *module)
{
	module->data = malloc(sizeof(struct MMDB_s));
	/* ->filename == NULL iff no DB is open */
	((MMDB_s *)module->data)->filename = NULL;
	return module->data != NULL ? kr_ok() : kr_error(ENOMEM);
}

KR_EXPORT
int client_subnet_deinit(struct kr_module *module)
{
	free(module->data);
       	module->data = NULL;
	return kr_ok();
}

KR_EXPORT
int client_subnet_config(struct kr_module *module, const char *db_path)
{
	unload(module);
	return load(module, db_path);
}

KR_MODULE_EXPORT(client_subnet)

