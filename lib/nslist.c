#include "lib/nslist.h"
#include "lib/context.h"


/* TODO: debug, remove */
#ifndef NDEBUG
static void print_slist(struct kr_context *ctx)
{
	char *sname = knot_dname_to_str(ctx->sname);
	printf("SLIST(%s): \n", sname);
	free(sname);
	struct kr_ns *ns = NULL;
	WALK_LIST(ns, ctx->slist) {
		char *strname = knot_dname_to_str(ns->name);
		char addr_str[SOCKADDR_STRLEN];
		sockaddr_tostr(&ns->addr, addr_str, sizeof(addr_str));
		printf("[%d] %s:%s ", ns->closeness, strname, addr_str);
		free(strname);
	}
	printf("\n");
}
#endif

/*! \brief Initialize NS descriptor. */
static struct kr_ns *init_ns(mm_ctx_t *mm, const knot_dname_t *name,
                             const struct sockaddr *addr)
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

	return ns;
}


/*! \brief Insert before an item. */
static void insert_before(struct kr_ns *cur, struct kr_ns *inserted)
{
	insert_node((node_t *)inserted, (node_t *)cur);
	rem_node((node_t *)cur);
	insert_node((node_t *)cur, (node_t *)inserted);
}

/*! \brief Calculate closeness (# of common labels with sname). */
static unsigned closeness_score(const knot_dname_t *sname, const knot_dname_t *zone)
{
	/* Longer or non-equal names of the same length can't contain delegations. */
	if (sname && (knot_dname_is_sub(sname, zone) || knot_dname_is_equal(zone, sname))) {
		return KNOT_DNAME_MAXLABELS - knot_dname_matched_labels(zone, sname);
	}

	return KNOT_DNAME_MAXLABELS + 1; /* N/A */
}

/* \brief (Re)insert name server to SLIST. */
static void insert_ns(struct kr_context *ctx, struct kr_ns *ns)
{
	struct kr_ns *it = NULL;
	WALK_LIST(it, ctx->slist) {
		if (it->closeness > ns->closeness) {
			insert_before(it, ns);
			return;
		}
	}

	/* No closer match found. */
	add_tail(&ctx->slist, (node_t *)ns);
}

/*! \brief Remove NS descriptor. */
static void remove_ns(mm_ctx_t *mm, struct kr_ns *ns)
{
	rem_node((node_t *)ns);
	mm_free(mm, ns->name);
	mm_free(mm, ns);
}

int kr_slist_init(struct kr_context *ctx)
{
	init_list(&ctx->slist);

	return 0;
}

int kr_slist_clear(struct kr_context *ctx)
{
	while(kr_slist_pop(ctx) == 0)
		;

	return 0;
}

int kr_slist_add(struct kr_context *ctx, const knot_dname_t *name, const struct sockaddr *addr)
{
	struct kr_ns *ns = init_ns(ctx->pool, name, addr);
	if (ns == NULL) {
		return -1;
	}

	insert_ns(ctx, ns);

	return 0;
}

struct kr_ns *kr_slist_top(struct kr_context *ctx)
{
	if (EMPTY_LIST(ctx->slist)) {
		return NULL;
	}

	return (struct kr_ns *)HEAD(ctx->slist);
}

int kr_slist_sort(struct kr_context *ctx)
{
	list_t copy = ctx->slist;
	init_list(&ctx->slist);

	/* Recalculate closeness and reinsert. */
	struct kr_ns *it = NULL, *next = NULL;
	WALK_LIST_DELSAFE(it, next, copy) {
		it->closeness = closeness_score(ctx->sname, it->name);
		insert_ns(ctx, it);
	}

	return 0;
}

int kr_slist_pop(struct kr_context *ctx)
{
	struct kr_ns *top = kr_slist_top(ctx);
	if (top == NULL) {
		return -1;
	}


	remove_ns(ctx->pool, top);

	return 0;
}