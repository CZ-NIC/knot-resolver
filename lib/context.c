#include <string.h>

#include <libknot/errcode.h>
#include <libknot/internal/sockaddr.h>
#include "lib/context.h"
#include "lib/rplan.h"

int kr_context_init(struct kr_context *ctx, mm_ctx_t *mm)
{
	memset(ctx, 0, sizeof(struct kr_context));

	ctx->pool = mm;

	ctx->cache = kr_cache_open("/tmp/kresolved", mm);
	if (ctx->cache == NULL) {
		fprintf(stderr, "Cache directory '/tmp/kresolved' not exists, exitting.\n");
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int kr_context_deinit(struct kr_context *ctx)
{
	kr_cache_close(ctx->cache);

	return KNOT_EOK;
}
