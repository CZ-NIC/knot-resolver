#include <string.h>

#include "context.h"

int kresolve_ctx_init(struct kresolve_ctx *ctx, mm_ctx_t *mm)
{
	memset(ctx, 0, sizeof(struct kresolve_ctx));
	ctx->mm = mm;
	return 0;
}

int kresolve_ctx_close(struct kresolve_ctx *ctx)
{
	/* free requestor, pending queries. */
	return -1;
}
