/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <sys/fcntl.h>

#include <libknot/internal/mempool.h>
#include <libknot/processing/requestor.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/descriptor.h>
#include <libknot/internal/net.h>
#include <dnssec/random.h>

#include "lib/rplan.h"
#include "lib/resolve.h"
#include "lib/layer/itercache.h"
#include "lib/layer/iterate.h"

#define DEBUG_MSG(fmt...) QRDEBUG(kr_rplan_current(rplan), "resl",  fmt)

/** Invalidate current NS/addr pair. */
static int invalidate_ns(struct kr_rplan *rplan, struct kr_query *qry)
{
	uint8_t *addr = kr_nsrep_inaddr(qry->ns.addr);
	size_t addr_len = kr_nsrep_inaddr_len(qry->ns.addr);
	knot_rdata_t rdata[knot_rdata_array_size(addr_len)];
	knot_rdata_init(rdata, addr_len, addr, 0);
	return kr_zonecut_del(&qry->zone_cut, qry->ns.name, rdata);
}

static int ns_resolve_addr(struct kr_query *qry, struct kr_request *param)
{
	struct kr_rplan *rplan = &param->rplan;
	if (kr_rplan_satisfies(qry, qry->ns.name, KNOT_CLASS_IN, KNOT_RRTYPE_A) ||
	    kr_rplan_satisfies(qry, qry->ns.name, KNOT_CLASS_IN, KNOT_RRTYPE_AAAA) ||
	    qry->flags & QUERY_AWAIT_ADDR) {
		DEBUG_MSG("=> dependency loop, bailing out\n");
		kr_rplan_pop(rplan, qry);
		return KNOT_STATE_PRODUCE;
	}

	(void) kr_rplan_push(rplan, qry, qry->ns.name, KNOT_CLASS_IN, KNOT_RRTYPE_AAAA);
	(void) kr_rplan_push(rplan, qry, qry->ns.name, KNOT_CLASS_IN, KNOT_RRTYPE_A);
	qry->flags |= QUERY_AWAIT_ADDR;
	return KNOT_STATE_PRODUCE;
}

static void prepare_layers(struct kr_request *param)
{
	struct kr_context *ctx = param->ctx;
	for (size_t i = 0; i < ctx->modules->len; ++i) {
		struct kr_module *mod = &ctx->modules->at[i];
		if (mod->layer) {
			knot_overlay_add(&param->overlay, mod->layer(), param);
		}
	}
}

static int connected(struct sockaddr *addr, int proto, struct timeval *timeout)
{
	unsigned flags = (proto == SOCK_STREAM) ? O_NONBLOCK : 0;
	int fd = net_connected_socket(proto, (struct sockaddr_storage *)addr, NULL, flags);
	if (fd < 0) {
		return kr_error(ECONNREFUSED);
	}

	/* Workaround for timeout, as we have no control over
	 * connect() time limit in blocking mode. */
	if (proto == SOCK_STREAM) {
		fd_set set;
		FD_ZERO(&set);
		FD_SET(fd, &set);
		int ret = select(fd + 1, NULL, &set, NULL, timeout);
		if (ret == 0) {
			close(fd);
			return kr_error(ETIMEDOUT);
		}
		if (ret < 0) {
			close(fd);
			return kr_error(ECONNREFUSED);
		}
		fcntl(fd, F_SETFL, 0);
	}

	return fd;
}

static int sendrecv(struct sockaddr *addr, int proto, const knot_pkt_t *query, knot_pkt_t *resp)
{
	struct timeval timeout = { KR_CONN_RTT_MAX / 1000, 0 };
	auto_close int fd = connected(addr, proto, &timeout);
	if (fd < 0) {
		return fd;
	}

	/* Send packet */
	int ret = 0;
	if (proto == SOCK_STREAM) {
		ret = tcp_send_msg(fd, query->wire, query->size, &timeout);
	} else {
		ret = udp_send_msg(fd, query->wire, query->size, NULL);
	}
	if (ret != query->size) {
		return kr_error(EIO);
	}

	/* Receive it */
	if (proto == SOCK_STREAM) {
		ret = tcp_recv_msg(fd, resp->wire, resp->max_size, &timeout);
	} else {
		ret = udp_recv_msg(fd, resp->wire, resp->max_size, &timeout);
	}
	if (ret <= 0) {
		return kr_error(ETIMEDOUT);
	}

	/* Parse and return */
	resp->size = ret;
	if (knot_pkt_parse(resp, 0) != 0) {
		return kr_error(EBADMSG);
	}

	return kr_ok();
}

int kr_resolve(struct kr_context* ctx, knot_pkt_t *answer,
               const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	if (ctx == NULL || answer == NULL || qname == NULL) {
		return kr_error(EINVAL);
	}

	/* Create memory pool */
	mm_ctx_t pool;
	mm_ctx_mempool(&pool, MM_DEFAULT_BLKSIZE);
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MIN_PKTSIZE, &pool);
	knot_pkt_t *resp = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, &pool);
	if (!query || !resp) {
		mp_delete(pool.ctx);
		return kr_error(ENOMEM);
	}

	/* Initialize context. */
	struct kr_request request;
	request.pool = pool;
	kr_resolve_begin(&request, ctx, answer);
#ifndef NDEBUG
	struct kr_rplan *rplan = &request.rplan; /* for DEBUG_MSG */
#endif

	/* Resolve query, iteratively */
	int proto = 0;
	struct sockaddr *addr = NULL;
	unsigned iter_count = 0;
	int state = kr_resolve_query(&request, qname, qclass, qtype);
	while (state == KNOT_STATE_PRODUCE) {
		/* Hardlimit on iterative queries */
		if (++iter_count > ITER_LIMIT) {
			DEBUG_MSG("iteration limit %d reached\n", ITER_LIMIT);
			state = KNOT_STATE_FAIL;
			break;
		}
		/* Produce next query or finish */
		state = kr_resolve_produce(&request, &addr, &proto, query);
		while (state == KNOT_STATE_CONSUME) {
			/* Get answer from nameserver and consume it */
			int ret = sendrecv(addr, proto, query, resp);
			if (ret != 0) {
				DEBUG_MSG("sendrecv: %s\n", kr_strerror(ret));
				resp->size = 0;
			}
			state = kr_resolve_consume(&request, resp);
			knot_pkt_clear(resp);
		}
		knot_pkt_clear(query);
	}

	/* Cleanup */
	kr_resolve_finish(&request, state);
	mp_delete(pool.ctx);
	return state == KNOT_STATE_DONE ? 0 : kr_error(EIO);
}


int kr_resolve_begin(struct kr_request *request, struct kr_context *ctx, knot_pkt_t *answer)
{
	/* Initialize request */
	kr_rplan_init(&request->rplan, ctx, &request->pool);
	knot_overlay_init(&request->overlay, &request->pool);
	request->ctx = ctx;
	request->answer = answer;
	prepare_layers(request);

	/* Expect first query */
	return KNOT_STATE_CONSUME;
}

int kr_resolve_query(struct kr_request *request, const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	struct kr_rplan *rplan = &request->rplan;
	struct kr_query *qry = kr_rplan_push(rplan, NULL, qname, qclass, qtype);
	if (!qry) {
		return KNOT_STATE_FAIL;
	}

	/* Create answer packet */
	knot_pkt_t *answer = request->answer;
	knot_wire_set_qr(answer->wire);
	knot_wire_clear_aa(answer->wire);
	knot_wire_set_ra(answer->wire);
	knot_wire_set_rcode(answer->wire, KNOT_RCODE_NOERROR);

	/* Expect answer */
	return KNOT_STATE_PRODUCE;
}

int kr_resolve_consume(struct kr_request *request, knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);

	/* Empty resolution plan, push packet as the new query */
	if (kr_rplan_empty(&request->rplan)) {
		const knot_dname_t *qname = knot_pkt_qname(packet);
		uint16_t qclass = knot_pkt_qclass(packet);
		uint16_t qtype = knot_pkt_qtype(packet);
		return kr_resolve_query(request, qname, qclass, qtype);
	}

	/* Different processing for network error */
	int state = KNOT_STATE_FAIL;
	if (!packet || packet->size == 0) {
		/* Network error, retry over TCP. */
		if (!(qry->flags & QUERY_TCP)) {
			/** @todo This should just penalize UDP and elect next best. */
			DEBUG_MSG("=> ns unreachable, retrying over TCP\n");
			qry->flags |= QUERY_TCP;
			return KNOT_STATE_CONSUME; /* Try again */
		}
	} else {
		state = knot_overlay_consume(&request->overlay, packet);
	}

	/* Resolution failed, invalidate current NS and reset to UDP. */
	if (state == KNOT_STATE_FAIL) {
		DEBUG_MSG("=> resolution failed, invalidating\n");
		if (invalidate_ns(rplan, qry) == 0) {
			qry->flags &= ~QUERY_TCP;
		}
	}

	/* Pop query if resolved. */
	if (qry->flags & QUERY_RESOLVED) {
		kr_rplan_pop(rplan, qry);

	}

	knot_overlay_reset(&request->overlay);
	return kr_rplan_empty(&request->rplan) ? KNOT_STATE_DONE : KNOT_STATE_PRODUCE;
}

int kr_resolve_produce(struct kr_request *request, struct sockaddr **dst, int *type, knot_pkt_t *packet)
{
	struct kr_rplan *rplan = &request->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	
	/* No query left for resolution */
	if (kr_rplan_empty(rplan)) {
		return KNOT_STATE_FAIL;
	}

#ifndef NDEBUG
	char name_str[KNOT_DNAME_MAXLEN], type_str[16];
	knot_dname_to_str(name_str, qry->sname, sizeof(name_str));
	knot_rrtype_to_string(qry->stype, type_str, sizeof(type_str));
	DEBUG_MSG("query '%s %s'\n", type_str, name_str);
#endif

	/* Resolve current query and produce dependent or finish */
	int state = knot_overlay_produce(&request->overlay, packet);
	switch(state) {
	case KNOT_STATE_FAIL: return state; break;
	case KNOT_STATE_CONSUME: break;
	default: /* Current query is done */
		knot_overlay_reset(&request->overlay);
		kr_rplan_pop(rplan, qry);
		return kr_rplan_empty(rplan) ? KNOT_STATE_DONE : KNOT_STATE_PRODUCE;
	}

	/* Elect best nameserver candidate */
	kr_nsrep_elect(&qry->ns, &qry->zone_cut.nsset);
	if (qry->ns.score < KR_NS_VALID) {
		DEBUG_MSG("=> no valid NS left\n");
		knot_overlay_reset(&request->overlay);
		kr_rplan_pop(rplan, qry);
		return KNOT_STATE_PRODUCE;
	} else {
		if (qry->ns.addr.ip.sa_family == AF_UNSPEC) {
			DEBUG_MSG("=> ns missing A/AAAA, fetching\n");
			knot_overlay_reset(&request->overlay);
			return ns_resolve_addr(qry, request);
		}
	}

#ifndef NDEBUG
	char qname_str[KNOT_DNAME_MAXLEN], zonecut_str[KNOT_DNAME_MAXLEN], ns_str[SOCKADDR_STRLEN];
	knot_dname_to_str(qname_str, knot_pkt_qname(packet), sizeof(qname_str));
	struct sockaddr *addr = &qry->ns.addr.ip;
	inet_ntop(addr->sa_family, kr_nsrep_inaddr(qry->ns.addr), ns_str, sizeof(ns_str));
	knot_dname_to_str(zonecut_str, qry->zone_cut.name, sizeof(zonecut_str));
	DEBUG_MSG("=> querying: '%s' zone cut: '%s' m12n: '%s'\n", ns_str, zonecut_str, qname_str);
#endif

	/* Issue dependent query to this address */
	*dst = &qry->ns.addr.ip;
	*type = (qry->flags & QUERY_TCP) ? SOCK_STREAM : SOCK_DGRAM;
	return state;
}

int kr_resolve_finish(struct kr_request *request, int state)
{
	struct kr_rplan *rplan = &request->rplan;
	DEBUG_MSG("finished: %d, mempool: %zu B\n", state, (size_t) mp_total_size(request->pool.ctx));

	/* Resolution success, commit cache transaction. */
	if (state == KNOT_STATE_DONE) {
		kr_rplan_txn_commit(rplan);
	} else {
		/* Error during procesing, internal failure */
		knot_pkt_t *answer = request->answer;
		if (knot_wire_get_rcode(answer->wire) == KNOT_RCODE_NOERROR) {
			knot_wire_set_rcode(answer->wire, KNOT_RCODE_SERVFAIL);
		}
	}

	/* Clean up. */
	knot_overlay_reset(&request->overlay);
	knot_overlay_deinit(&request->overlay);
	kr_rplan_deinit(&request->rplan);
	return KNOT_STATE_DONE;
}
