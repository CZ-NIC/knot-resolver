#include <string.h>
#include <sys/time.h>

#include <libknot/internal/sockaddr.h>
#include "lib/context.h"
#include "lib/rplan.h"

int kr_context_init(struct kr_context *ctx, mm_ctx_t *mm)
{
	memset(ctx, 0, sizeof(struct kr_context));

	ctx->pool = mm;

	kr_rplan_init(&ctx->rplan, mm);
	kr_delegmap_init(&ctx->dp_map, mm);

	ctx->cache = kr_cache_open("/tmp/kresolved", 0, mm);
	if (ctx->cache == NULL) {
		fprintf(stderr, "Cache directory '/tmp/kresolved' not exists, exitting.\n");
		assert(ctx->cache);
	}

	return 0;
}

int kr_context_reset(struct kr_context *ctx)
{
	/* Finalize transactions. */
	int ret = kr_context_txn_commit(ctx);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ctx->state = 0;
	ctx->resolved_qry = NULL;
	ctx->current_ns = NULL;
	ctx->query = NULL;
	ctx->txn.read = NULL;
	ctx->txn.write = NULL;
	kr_rplan_clear(&ctx->rplan);

	return KNOT_EOK;
}

int kr_context_deinit(struct kr_context *ctx)
{
	kr_delegmap_deinit(&ctx->dp_map);
	kr_cache_close(ctx->cache);

	return KNOT_EOK;
}

struct kr_txn *kr_context_txn_acquire(struct kr_context *ctx, unsigned flags)
{
	struct kr_txn **txn = &ctx->txn.write;
	if (flags & KR_CACHE_RDONLY) {
		txn = &ctx->txn.read;
	}

	if (*txn != NULL) {
		return *txn;
	}

	return *txn = kr_cache_txn_begin(ctx->cache, NULL, flags, ctx->pool);
}

void kr_context_txn_release(struct kr_txn *txn)
{
	/*! \note Transactions are reused and commited on checkpoints only. */
}

int kr_context_txn_commit(struct kr_context *ctx)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	if (ctx->txn.write) {
		ret = kr_cache_txn_commit(ctx->txn.write);
	}
	if (ctx->txn.read) {
		kr_cache_txn_abort(ctx->txn.read);
	}

	ctx->txn.read = ctx->txn.write = NULL;
	return ret;
}

int kr_result_init(struct kr_context *ctx, struct kr_result *result)
{
	memset(result, 0, sizeof(struct kr_result));

	/* Initialize answer packet. */
	knot_pkt_t *ans = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, ctx->pool);
	if (ans == NULL) {
		return -1;
	}

	struct kr_query *qry = kr_rplan_next(&ctx->rplan);
	if (qry == NULL) {
		knot_pkt_free(&ans);
		return -1;
	}

	knot_pkt_put_question(ans, qry->sname, qry->sclass, qry->stype);
	knot_wire_set_rcode(ans->wire, KNOT_RCODE_SERVFAIL);
	knot_wire_set_qr(ans->wire);

	result->ans = ans;

	return 0;
}

int kr_result_deinit(struct kr_result *result)
{
	knot_pkt_free(&result->ans);

	return 0;
}
