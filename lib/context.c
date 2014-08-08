#include <string.h>
#include <sys/time.h>

#include <common/sockaddr.h>
#include "context.h"

/* \brief Root hint descriptor. */
struct hint_info {
	const char *name;
	const char *addr;
	const char *zone;
};

/* Initialize with SBELT name servers. */
#define HINT_COUNT 13
static const struct hint_info SBELT[HINT_COUNT] = {
        { "a.root-servers.net.", "198.41.0.4", "." },
        { "b.root-servers.net.", "192.228.79.201", "." },
        { "c.root-servers.net.", "192.33.4.12", "." },
        { "d.root-servers.net.", "199.7.91.13", "." },
        { "e.root-servers.net.", "192.203.230.10", "." },
        { "f.root-servers.net.", "192.5.5.241", "." },
        { "g.root-servers.net.", "192.112.36.4", "." },
        { "h.root-servers.net.", "128.63.2.53", "." },
        { "i.root-servers.net.", "192.36.148.17", "." },
        { "j.root-servers.net.", "192.58.128.30", "." },
        { "k.root-servers.net.", "193.0.14.129", "." },
        { "l.root-servers.net.", "199.7.83.42", "." },
        { "m.root-servers.net.", "202.12.27.33", "." }
};

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

int kr_context_init(struct kr_context *ctx, mm_ctx_t *mm)
{
	memset(ctx, 0, sizeof(struct kr_context));

	ctx->pool = mm;
	init_list(&ctx->slist);
	kr_context_reset(ctx);

	return 0;
}

int kr_context_reset(struct kr_context *ctx)
{
	while(kr_slist_pop(ctx) == 0);

	kr_slist_init(ctx);

	return 0;
}

int kr_context_deinit(struct kr_context *ctx)
{
	/* TODO: free slist, pending queries. */
	return -1;
}

int kr_result_init(struct kr_context *ctx, struct kr_result *result)
{
	memset(result, 0, sizeof(struct kr_result));

	knot_pkt_t *ans = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, ctx->pool);
	if (ans == NULL) {
		return -1;
	}

	knot_pkt_put_question(ans, ctx->sname, ctx->sclass, ctx->stype);
	knot_wire_set_rcode(ans->wire, KNOT_RCODE_SERVFAIL);
	knot_wire_set_qr(ans->wire);

	result->ans = ans;
	gettimeofday(&result->t_start, NULL);

	return 0;
}

int kr_result_deinit(struct kr_result *result)
{
	knot_pkt_free(&result->ans);

	return 0;
}

int kr_slist_init(struct kr_context *ctx)
{
	int ret = 0;
	struct sockaddr_storage ss;
	for (unsigned i = 0; i < HINT_COUNT; ++i) {
		ret = sockaddr_set(&ss, AF_INET, SBELT[i].addr, 53);
		assert(ret == 0);
		kr_slist_add(ctx, knot_dname_from_str(SBELT[i].zone),
		             (struct sockaddr *)&ss);
	}

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
