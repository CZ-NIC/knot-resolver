#include <stdio.h>
#include <uv.h>

#include <libknot/processing/requestor.h>
#include <libknot/dnssec/random.h>
#include <libknot/rrtype/aaaa.h>
#include <libknot/descriptor.h>
#include "lib/resolve.h"
#include "lib/defines.h"
#include "lib/layer/iterate.h"
#include "lib/layer/static.h"
#include "lib/layer/stats.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[reslv] " fmt, ## __VA_ARGS__)

/* Defines */
#define ITER_LIMIT 50

/* \brief Root hint descriptor. */
struct hint_info {
	const knot_dname_t *name;
	const char *addr;
};

/* Initialize with SBELT name servers. */
#define U8(x) (const uint8_t *)(x)
#define HINT_COUNT 13
static const struct hint_info SBELT[HINT_COUNT] = {
        { U8("\x01""a""\x0c""root-servers""\x03""net"), "198.41.0.4" },
        { U8("\x01""b""\x0c""root-servers""\x03""net"), "192.228.79.201" },
        { U8("\x01""c""\x0c""root-servers""\x03""net"), "192.33.4.12" },
        { U8("\x01""d""\x0c""root-servers""\x03""net"), "199.7.91.13" },
        { U8("\x01""e""\x0c""root-servers""\x03""net"), "192.203.230.10" },
        { U8("\x01""f""\x0c""root-servers""\x03""net"), "192.5.5.241" },
        { U8("\x01""g""\x0c""root-servers""\x03""net"), "192.112.36.4" },
        { U8("\x01""h""\x0c""root-servers""\x03""net"), "128.63.2.53" },
        { U8("\x01""i""\x0c""root-servers""\x03""net"), "192.36.148.17" },
        { U8("\x01""j""\x0c""root-servers""\x03""net"), "192.58.128.30" },
        { U8("\x01""k""\x0c""root-servers""\x03""net"), "193.0.14.129" },
        { U8("\x01""l""\x0c""root-servers""\x03""net"), "199.7.83.42" },
        { U8("\x01""m""\x0c""root-servers""\x03""net"), "202.12.27.33" }
};

static int rrset_to_addr(struct sockaddr_storage *ss, const knot_rrset_t *rr)
{
	/* Retrieve an address from glue record. */
	switch(rr->type) {
	case KNOT_RRTYPE_A:
		knot_a_addr(&rr->rrs, 0, (struct sockaddr_in *)ss);
		break;
	case KNOT_RRTYPE_AAAA:
		knot_aaaa_addr(&rr->rrs, 0, (struct sockaddr_in6 *)ss);
		break;
	default:
		return KNOT_EINVAL;
	}

	sockaddr_port_set((struct sockaddr_storage *)ss, 53);
	return KNOT_EOK;
}

/*! \brief Synthetise root nameserver from SBELT.
 *  TODO: SBELT should be shared (but extendable) singleton variable
 */
static int fetch_root_hint(struct sockaddr_storage *ns_addr, struct kr_zonecut *zonecut, struct kr_context* ctx)
{
	const unsigned hint_id = knot_random_uint16_t() % HINT_COUNT;
	const struct hint_info *hint = &SBELT[hint_id];

	/* Create nameserver descriptor. */
	struct kr_ns *root_ns = kr_ns_get(&zonecut->nslist, hint->name, ctx->dp_map.pool);
	if (root_ns == NULL) {
		return KNOT_ENOMEM;
	}

	/* Plan root servers update. */
	struct kr_query *qry = kr_rplan_push(&ctx->rplan, (const knot_dname_t*)"", KNOT_CLASS_IN, KNOT_RRTYPE_NS);
	if (qry != NULL) {
		qry->flags  = RESOLVE_DELEG;
	}

	return KNOT_EOK;
}

/*! \brief Fetch address record for nameserver. */
static int fetch_ns_addr(struct sockaddr_storage *ns_addr, const struct kr_ns *ns, struct kr_context* ctx)
{
	int ret = KNOT_EOK;
	knot_rrset_t cached_reply;
	knot_rrset_init(&cached_reply, ns->name, KNOT_RRTYPE_A, KNOT_CLASS_IN);

	struct kr_txn *txn = kr_context_txn_acquire(ctx, KR_CACHE_RDONLY);

	/* Fetch nameserver address from cache. */
	if (kr_cache_query(txn, &cached_reply) != 0) {
		cached_reply.type = KNOT_RRTYPE_AAAA;
		if (kr_cache_query(txn, &cached_reply) != 0) {
			ret = KNOT_ENOENT; /* Not found. */
		}
	}

	/* Update nameserver address if found. */
	if (ret != KNOT_ENOENT) {
		ret = rrset_to_addr(ns_addr, &cached_reply);
		knot_rdataset_clear(&cached_reply.rrs, ctx->pool);
	} else {
		/* Set root server address from SBELT. */
		const struct hint_info *hint = NULL;
		for (unsigned i = 0; i < HINT_COUNT; ++i) {
			if (knot_dname_is_equal(SBELT[i].name, ns->name)) {
				hint = &SBELT[i];
				break;
			}
		}

		/* Set static address. */
		if (hint != NULL) {
			ret = sockaddr_set(ns_addr, AF_INET, hint->addr, 53);
		}
	}

	kr_context_txn_release(txn);

	return ret;
}

static void iterate(struct knot_requestor *requestor, struct kr_context* ctx)
{
	int ret = KNOT_EOK;
	struct timeval timeout = { KR_CONN_RTT_MAX / 1000, 0 };
	const struct kr_query *next = kr_rplan_next(&ctx->rplan);
	assert(next);

	/* Find closest delegation point. */
	ctx->zone_cut = kr_zonecut_find(&ctx->dp_map, next->sname);

	char name_str[KNOT_DNAME_MAXLEN], dp_str[KNOT_DNAME_MAXLEN], ns_str[KNOT_DNAME_MAXLEN];
	knot_dname_to_str(name_str, next->sname, sizeof(name_str));
	knot_dname_to_str(dp_str, ctx->zone_cut->name, sizeof(dp_str));

	/* Fetch current best nameserver. */
	struct sockaddr_storage ns_addr;
	struct kr_ns *ns = kr_ns_first(&ctx->zone_cut->nslist);
	if (ns == NULL) {
		/* Fetch static nameserver from SBELT. */
		ret = fetch_root_hint(&ns_addr, ctx->zone_cut, ctx);
		if (ret != KNOT_EOK) {
			ctx->state = KNOT_NS_PROC_FAIL;
			return;
		}
		ns = kr_ns_first(&ctx->zone_cut->nslist);
		knot_dname_to_str(ns_str, ns->name, sizeof(ns_str));
		DEBUG_MSG("set sbelt root nameserver '%s'\n", ns_str);
		return;
	} else {
		/* Retrieve address. */
		knot_dname_to_str(ns_str, ns->name, sizeof(ns_str));
		ret = fetch_ns_addr(&ns_addr, ns, ctx);
		if (ret != KNOT_EOK) {
			DEBUG_MSG("retrieve 'A/AAAA %s' from cache failed\n", ns_str);
			kr_ns_del(&ctx->zone_cut->nslist, ns, ctx->dp_map.pool);
			return;
		}
	}

	DEBUG_MSG("resolve '%s' auth '%s' nameserver '%s'\n", name_str, dp_str, ns_str);

	/* Update context. */
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, requestor->mm);
	ctx->current_ns = ns;
	ctx->query = query;
	ctx->resolved_qry = NULL;

	/* Resolve. */
	struct knot_request *tx = knot_request_make(requestor->mm,
	                         (struct sockaddr *)&ns_addr,
	                         NULL, query, 0);
	knot_requestor_enqueue(requestor, tx);
	ret = knot_requestor_exec(requestor, &timeout);
	if (ret != KNOT_EOK) {
		/* Resolution failed, invalidate current resolver. */
		DEBUG_MSG("resolve '%s' with nameserver '%s'\n", name_str, ns_str);
		kr_ns_del(&ctx->zone_cut->nslist, ns, ctx->dp_map.pool);
	} else {
		/* Resolution success, commit intermediate results. */
		kr_context_txn_commit(ctx);
	}

	/* Pop resolved query. */
	if (ctx->resolved_qry) {
		kr_rplan_pop(&ctx->rplan, ctx->resolved_qry);
		ctx->resolved_qry = NULL;
	}

	/* Continue resolution if has more queries planned. */
	if (kr_rplan_next(&ctx->rplan) == NULL) {
		ctx->state = KNOT_NS_PROC_DONE;
	} else {
		ctx->state = KNOT_NS_PROC_MORE;
	}
}

int kr_resolve(struct kr_context* ctx, struct kr_result* result,
               const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	if (ctx == NULL || result == NULL || qname == NULL) {
		return -1;
	}

	/* Initialize context. */
	ctx->state = KNOT_NS_PROC_MORE;
	kr_rplan_push(&ctx->rplan, qname, qclass, qtype);
	kr_result_init(ctx, result);

	struct kr_layer_param param;
	param.ctx = ctx;
	param.result = result;

	/* Initialize requestor and overlay. */
	struct knot_requestor requestor;
	knot_requestor_init(&requestor, ctx->pool);
	knot_requestor_overlay(&requestor, LAYER_STATIC, &param);
	knot_requestor_overlay(&requestor, LAYER_ITERATE, &param);
	knot_requestor_overlay(&requestor, LAYER_STATS, &param);
	unsigned iter_count = 0;
	while(ctx->state & (KNOT_NS_PROC_MORE|KNOT_NS_PROC_FULL)) {
		iterate(&requestor, ctx);
		if (++iter_count > ITER_LIMIT) {
			DEBUG_MSG("iteration limit %d reached => SERVFAIL\n", ITER_LIMIT);
			ctx->state = KNOT_NS_PROC_FAIL;
		}
	}

	/* Clean up. */
	knot_requestor_clear(&requestor);

	/* Set RCODE on internal failure. */
	if (ctx->state != KNOT_NS_PROC_DONE) {
		knot_wire_set_rcode(result->ans->wire, KNOT_RCODE_SERVFAIL);
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}
