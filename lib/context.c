#include <string.h>
#include <sys/time.h>

#include <common/sockaddr.h>
#include "context.h"

/*! \brief Initialize NS descriptor. */
static struct kr_ns *init_ns(mm_ctx_t *mm, const knot_dname_t *name,
                             const struct sockaddr *addr, unsigned closeness)
{
	struct kr_ns *ns = mm_alloc(mm, sizeof(struct kr_ns));
	if (ns == NULL) {
		return NULL;
	}

	memset(ns, 0, sizeof(struct kr_ns));
	ns->name = knot_dname_copy(name, mm);
	if (ns->name == NULL) {
		mm_free(mm, ns);
		return NULL;
	}

	memcpy(&ns->addr, addr, sockaddr_len(addr));
	ns->closeness = closeness;

	return ns;
}

/*! \brief Insert NS before an item. */
static void insert_ns(struct kr_ns *cur, struct kr_ns *inserted)
{
	insert_node((node_t *)inserted, (node_t *)cur);
	rem_node((node_t *)cur);
	insert_node((node_t *)cur, (node_t *)inserted);
}

/*! \brief Remove NS descriptor. */
static void remove_ns(mm_ctx_t *mm, struct kr_ns *ns)
{
	mm_free(mm, ns->name);
	mm_free(mm, ns);
}

int kr_context_init(struct kr_context *ctx, mm_ctx_t *mm)
{
	memset(ctx, 0, sizeof(struct kr_context));

	ctx->mm = mm;
	init_list(&ctx->slist);

	return 0;
}

int kr_context_close(struct kr_context *ctx)
{
	/* TODO: free slist, pending queries. */
	return -1;
}

int kr_result_init(struct kr_context *ctx, struct kr_result *result)
{
	memset(result, 0, sizeof(struct kr_result));

	knot_pkt_t *ans = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, ctx->mm);
	if (ans == NULL) {
		return -1;
	}

	knot_pkt_put_question(ans, ctx->sname, ctx->sclass, ctx->stype);
	knot_wire_set_rcode(ans->wire, KNOT_RCODE_SERVFAIL);
	knot_wire_set_qr(ans->wire);

	result->ans = ans;
	result->cname = ctx->sname;
	gettimeofday(&result->t_start, NULL);

	return 0;
}

int kr_result_clear(struct kr_result *result)
{
	knot_pkt_free(&result->ans);

	return 0;
}

int kr_slist_add(struct kr_context *ctx, const knot_dname_t *name, const struct sockaddr *addr)
{
	/* Closeness is represented by a number of common labels. */
	int closeness = knot_dname_matched_labels(name, ctx->sname);

	struct kr_ns *ns = init_ns(ctx->mm, name, addr, closeness);
	if (ns == NULL) {
		return -1;
	}

	struct kr_ns *iter = NULL;
	WALK_LIST(iter, ctx->slist) {
		if (iter->closeness < closeness) {
			insert_ns(iter, ns);
			return 0;
		}
	}

	/* No closer match found. */
	add_tail(&ctx->slist, (node_t *)ns);
	return 0;
}

struct kr_ns *kr_slist_top(struct kr_context *ctx)
{
	if (EMPTY_LIST(ctx->slist)) {
		return NULL;
	}

	return (struct kr_ns *)HEAD(ctx->slist);
}

int kr_slist_pop(struct kr_context *ctx)
{
	struct kr_ns *top = kr_slist_top(ctx);
	if (top) {
		return -1;
	}

	rem_node((node_t *)top);
	remove_ns(ctx->mm, top);
	return 0;
}
