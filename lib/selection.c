#include <libknot/dname.h>

#include "lib/selection.h"
#include "lib/selection_forward.h"
#include "lib/selection_iter.h"
#include "lib/generic/pack.h"
#include "lib/generic/trie.h"
#include "lib/rplan.h"
#include "lib/cache/api.h"
#include "lib/resolve.h"

#include "daemon/worker.h"
#include "daemon/tls.h"

#include "lib/utils.h"

#define VERBOSE_MSG(qry, ...) QRVERBOSE((qry), "slct", __VA_ARGS__)

/** @internal Macro to set address structure. */
#define ADDR_SET(sa, family, addr, len, port) do {\
		memcpy(&sa ## _addr, (addr), (len)); \
		sa ## _family = (family); \
	sa ## _port = htons(port); \
} while (0)

#define DEFAULT_TIMEOUT 800
#define MAX_TIMEOUT 10000
#define MAX_BACKOFF 5
#define MINIMAL_TIMEOUT_ADDITION 20

/* After TCP_TIMEOUT_THRESHOLD timeouts one transport, we'll switch to TCP. */
#define TCP_TIMEOUT_THRESHOLD 2
/* If the expected RTT is over TCP_RTT_THRESHOLD we switch to TCP instead. */
#define TCP_RTT_THRESHOLD 2000

/* Define ε for ε-greedy algorithm (see select_transport)
 * as ε=EPSILON_NOMIN/EPSILON_DENOM */
#define EPSILON_NOMIN 1
#define EPSILON_DENOM 20

/* Simple cache interface follows */

static knot_db_val_t cache_key(const uint8_t *ip, size_t len)
{
	// CACHE_KEY_DEF: '\0' + 'S' + raw IP
	const size_t key_len = len + 2;
	uint8_t *key_data = malloc(key_len);
	key_data[0] = '\0';
	key_data[1] = 'S';
	memcpy(key_data + 2, ip, len);
	knot_db_val_t key = {
		.len = key_len,
		.data = key_data,
	};
	return key;
}

/* First value of timeout will be calculated as SRTT+4*DEFAULT_TIMEOUT
 * by calc_timeout(), so it'll be equal to DEFAULT_TIMEOUT. */
static const struct rtt_state default_rtt_state = { .srtt = 0,
						    .variance =
							    DEFAULT_TIMEOUT / 4,
						    .consecutive_timeouts = 0,
						    .dead_since = 0 };

struct rtt_state get_rtt_state(const uint8_t *ip, size_t len,
			       struct kr_cache *cache)
{
	struct rtt_state state;
	knot_db_val_t value;
	knot_db_t *db = cache->db;
	struct kr_cdb_stats *stats = &cache->stats;

	knot_db_val_t key = cache_key(ip, len);

	if (cache->api->read(db, stats, &key, &value, 1)) {
		state = default_rtt_state;
	} else if (value.len != sizeof(struct rtt_state)) {
		assert(false); // shouldn't happen but let's be more robust
		state = default_rtt_state;
	} else {
		state = *(struct rtt_state *)value.data;
	}

	free(key.data);
	return state;
}

int put_rtt_state(const uint8_t *ip, size_t len, struct rtt_state state,
		  struct kr_cache *cache)
{
	knot_db_t *db = cache->db;
	struct kr_cdb_stats *stats = &cache->stats;

	knot_db_val_t key = cache_key(ip, len);
	knot_db_val_t value = { .len = sizeof(struct rtt_state),
				.data = &state };

	int ret = cache->api->write(db, stats, &key, &value, 1);
	cache->api->commit(db, stats);

	free(key.data);
	return ret;
}

void bytes_to_ip(uint8_t *bytes, size_t len, union inaddr *dst)
{
	switch (len) {
	case sizeof(struct in_addr):
		ADDR_SET(dst->ip4.sin, AF_INET, bytes, len, 0);
		break;
	case sizeof(struct in6_addr):
		ADDR_SET(dst->ip6.sin6, AF_INET6, bytes, len, 0);
		break;
	default:
		assert(0);
	}
}

uint8_t *ip_to_bytes(const union inaddr *src, size_t len)
{
	switch (len) {
	case sizeof(struct in_addr):
		return (uint8_t *)&src->ip4.sin_addr;
	case sizeof(struct in6_addr):
		return (uint8_t *)&src->ip6.sin6_addr;
	default:
		assert(0);
	}
}

static bool no_rtt_info(struct rtt_state s)
{
	return s.srtt == 0 && s.consecutive_timeouts == 0;
}

static unsigned back_off_timeout(uint32_t to, int pow)
{
	if (pow > MAX_BACKOFF) {
		to *= 1 << MAX_BACKOFF;
	} else {
		to *= (1 << pow);
	}
	if (to > MAX_TIMEOUT) {
		to = MAX_TIMEOUT;
	}
	return to;
}

/* This is verbatim (minus the default timeout value and minimal variance)
 * RFC6298, sec. 2. */
static unsigned calc_timeout(struct rtt_state state)
{
	int32_t timeout =
		state.srtt + MAX(4 * state.variance, MINIMAL_TIMEOUT_ADDITION);
	return back_off_timeout(timeout, state.consecutive_timeouts);
}

/* This is verbatim RFC6298, sec. 2. */
static struct rtt_state calc_rtt_state(struct rtt_state old, unsigned new_rtt)
{
	if (no_rtt_info(old)) {
		return (struct rtt_state){ new_rtt, new_rtt / 2, 0 };
	}

	struct rtt_state ret;

	ret.srtt = (int32_t)(0.75 * old.srtt + 0.25 * new_rtt);
	ret.variance = (int32_t)(0.875 * old.variance +
				 0.125 * abs(old.srtt - (int32_t)new_rtt));
	ret.consecutive_timeouts = 0;

	return ret;
}

/**
 * @internal Invalidate addresses which should be considered dead
 */
static void invalidate_dead_upstream(struct address_state *state,
				     unsigned int retry_timeout)
{
	struct rtt_state *rs = &state->rtt_state;
	if (rs->consecutive_timeouts >= KR_NS_TIMEOUT_ROW_DEAD) {
		uint64_t now = kr_now();
		if (now < rs->dead_since) {
			// broken continuity of timestamp (reboot, different machine, etc.)
			*rs = default_rtt_state;
		} else if (now < rs->dead_since + retry_timeout) {
			// period when we don't want to use the address
			state->generation = -1;
		} else {
			assert(now >= rs->dead_since + retry_timeout);
			// we allow to retry the server now
			// TODO: perhaps tweak *rs?
		}
	}
}

/**
 * @internal Check if IP address is TLS capable.
 *
 * @p req has to have the selection_context properly initiazed.
 */
static void check_tls_capable(struct address_state *address_state,
			      struct kr_request *req, struct sockaddr *address)
{
	address_state->tls_capable =
		req->selection_context.is_tls_capable ?
			      req->selection_context.is_tls_capable(address) :
			      false;
}

#if 0
/* TODO: uncomment these once we actually use the information it collects. */
/**
 * Check if there is a existing TCP connection to this address.
 * 
 * @p req has to have the selection_context properly initiazed.
 */
void check_tcp_connections(struct address_state *address_state, struct kr_request *req, struct sockaddr *address) {
	address_state->tcp_connected = req->selection_context.is_tcp_connected ? req->selection_context.is_tcp_connected(address) : false;
	address_state->tcp_waiting = req->selection_context.is_tcp_waiting ? req->selection_context.is_tcp_waiting(address) : false;
}
#endif

/**
 * @internal Invalidate address if the respective IP version is disabled.
 */
static void check_network_settings(struct address_state *address_state,
				   size_t address_len, bool no_ipv4, bool no_ipv6)
{
	if (no_ipv4 && address_len == sizeof(struct in_addr)) {
		address_state->generation = -1;
	}
	if (no_ipv6 && address_len == sizeof(struct in6_addr)) {
		address_state->generation = -1;
	}
}

void update_address_state(struct address_state *state, uint8_t *address,
			  size_t address_len, struct kr_query *qry)
{
	union inaddr tmp_address;
	bytes_to_ip(address, address_len, &tmp_address);
	check_tls_capable(state, qry->request, &tmp_address.ip);
	/* TODO: uncomment this once we actually use the information it collects
	check_tcp_connections(address_state, qry->request, &tmp_address.ip);
	*/
	check_network_settings(state, address_len, qry->flags.NO_IPV4,
			       qry->flags.NO_IPV6);
	state->rtt_state =
		get_rtt_state(address, address_len, &qry->request->ctx->cache);
	invalidate_dead_upstream(
		state, qry->request->ctx->cache_rtt_tout_retry_interval);
#ifdef SELECTION_CHOICE_LOGGING
	// This is sometimes useful for debugging, but usually too verbose
	WITH_VERBOSE(qry)
	{
		const char *ns_str = kr_straddr(&tmp_address.ip);
		VERBOSE_MSG(qry, "rtt of %s is %d, variance is %d\n", ns_str,
			    state->rtt_state.srtt, state->rtt_state.variance);
	}
#endif
}

static int cmp_choices(const void *a, const void *b)
{
	struct choice *a_ = (struct choice *)a;
	struct choice *b_ = (struct choice *)b;

	int diff;
	/* Address with no RTT information is better than address
	 * with some information. */
	if ((diff = no_rtt_info(b_->address_state->rtt_state) -
		    no_rtt_info(a_->address_state->rtt_state))) {
		return diff;
	}
	/* Address with less errors is better. */
	if ((diff = a_->address_state->error_count -
		    b_->address_state->error_count)) {
		return diff;
	}
	/* Address with smaller expected timeout is better. */
	if ((diff = calc_timeout(a_->address_state->rtt_state) -
		    calc_timeout(b_->address_state->rtt_state))) {
		return diff;
	}
	return 0;
}

/* Fisher-Yates shuffle of the choices */
static void shuffle_choices(struct choice choices[], int choices_len)
{
	struct choice tmp;
	for (int i = choices_len - 1; i > 0; i--) {
		int j = kr_rand_bytes(1) % (i + 1);
		tmp = choices[i];
		choices[i] = choices[j];
		choices[j] = tmp;
	}
}

/* Performs the actual selection (currently variation on epsilon-greedy). */
struct kr_transport *select_transport(struct choice choices[], int choices_len,
				      struct to_resolve unresolved[],
				      int unresolved_len, int timeouts,
				      struct knot_mm *mempool, bool tcp,
				      size_t *choice_index)
{
	if (!choices_len && !unresolved_len) {
		/* There is nothing to choose from */
		return NULL;
	}

	struct kr_transport *transport =
		mm_alloc(mempool, sizeof(struct kr_transport));
	memset(transport, 0, sizeof(struct kr_transport));

	int choice = 0;
	if (kr_rand_coin(EPSILON_NOMIN, EPSILON_DENOM) || choices_len == 0) {
		/* "EXPLORE":
		 * randomly choose some option
		 * (including resolution of some new name). */
		int index = kr_rand_bytes(1) % (choices_len + unresolved_len);
		if (index < unresolved_len) {
			// We will resolve a new NS name
			*transport = (struct kr_transport){
				.protocol = unresolved[index].type,
				.ns_name = unresolved[index].name
			};
			return transport;
		} else {
			choice = index - unresolved_len;
		}
	} else {
		/* "EXPLOIT":
		 * choose a resolved address which seems best right now. */
		shuffle_choices(choices, choices_len);
		/* If there are some addresses with no rtt_info we try them
		 * first (see cmp_choices). So unknown servers are chosen
		 * *before* the best know server. This ensures that every option
		 * is tried before going back to some that was tried before. */
		qsort(choices, choices_len, sizeof(struct choice), cmp_choices);
		choice = 0;
	}

	struct choice *chosen = &choices[choice];

	/* Don't try the same server again when there are other choices to be explored */
	if (chosen->address_state->error_count && unresolved_len) {
		int index = kr_rand_bytes(1) % unresolved_len;
		*transport = (struct kr_transport){
			.ns_name = unresolved[index].name,
			.protocol = unresolved[index].type,
		};
		return transport;
	}

	unsigned timeout;
	if (no_rtt_info(chosen->address_state->rtt_state)) {
		/* Exponential back-off when retrying after timeout and choosing
		 * an unknown server. */
		timeout = back_off_timeout(DEFAULT_TIMEOUT, timeouts);
	} else {
		timeout = calc_timeout(chosen->address_state->rtt_state);
	}

	enum kr_transport_protocol protocol;
	if (chosen->address_state->tls_capable) {
		protocol = KR_TRANSPORT_TLS;
	} else if (tcp ||
		   chosen->address_state->errors[KR_SELECTION_QUERY_TIMEOUT] >= TCP_TIMEOUT_THRESHOLD ||
		   timeout > TCP_RTT_THRESHOLD) {
		protocol = KR_TRANSPORT_TCP;
	} else {
		protocol = KR_TRANSPORT_UDP;
	}

	*transport = (struct kr_transport){
		.ns_name = chosen->address_state->ns_name,
		.protocol = protocol,
		.timeout = timeout,
		.safe_mode =
			chosen->address_state->errors[KR_SELECTION_FORMERROR],
	};

	int port;
	if (!(port = chosen->port)) {
		switch (transport->protocol) {
		case KR_TRANSPORT_TLS:
			port = KR_DNS_TLS_PORT;
			break;
		case KR_TRANSPORT_UDP:
		case KR_TRANSPORT_TCP:
			port = KR_DNS_PORT;
			break;
		default:
			assert(0);
			break;
		}
	}

	switch (chosen->address_len) {
	case sizeof(struct in_addr):
		ADDR_SET(transport->address.ip4.sin, AF_INET, chosen->address,
			 chosen->address_len, port);
		transport->address_len = chosen->address_len;
		break;
	case sizeof(struct in6_addr):
		ADDR_SET(transport->address.ip6.sin6, AF_INET6, chosen->address,
			 chosen->address_len, port);
		transport->address_len = chosen->address_len;
		break;
	default:
		assert(0);
		break;
	}

	if (choice_index) {
		*choice_index = chosen->address_state->choice_array_index;
	}

	return transport;
}

void update_rtt(struct kr_query *qry, struct address_state *addr_state,
		const struct kr_transport *transport, unsigned rtt)
{
	if (!transport || !addr_state) {
		/* Answers from cache have NULL transport, ignore them. */
		return;
	}

	struct kr_cache *cache = &qry->request->ctx->cache;

	uint8_t *address =
		ip_to_bytes(&transport->address, transport->address_len);
	/* This construct is a bit racy since the global state may change
	 * between calls to `get_rtt_state` and `put_rtt_state`  but we don't
	 * care that much since it is rare and we only risk slightly suboptimal
	 * transport choice. */
	struct rtt_state cur_rtt_state =
		get_rtt_state(address, transport->address_len, cache);
	struct rtt_state new_rtt_state = calc_rtt_state(cur_rtt_state, rtt);
	put_rtt_state(address, transport->address_len, new_rtt_state, cache);

	WITH_VERBOSE(qry)
	{
	KR_DNAME_GET_STR(ns_name, transport->ns_name);
	KR_DNAME_GET_STR(zonecut_str, qry->zone_cut.name);
	const char *ns_str = kr_straddr(&transport->address.ip);

	VERBOSE_MSG(
		qry,
		"=> id: '%05u' updating: '%s'@'%s' zone cut: '%s' with rtt %u to srtt: %d and variance: %d \n",
		qry->id, ns_name, ns_str ? ns_str : "", zonecut_str,
		rtt, new_rtt_state.srtt, new_rtt_state.variance);
	}
}

static void cache_timeout(const struct kr_transport *transport,
			  struct address_state *addr_state, struct kr_cache *cache)
{
	if (transport->deduplicated) {
		/* Transport was chosen by a different query, that one will
		 * cache the result. */
		return;
	}

	uint8_t *address =
		ip_to_bytes(&transport->address, transport->address_len);
	struct rtt_state old_state = addr_state->rtt_state;
	struct rtt_state cur_state =
		get_rtt_state(address, transport->address_len, cache);

	/* We could lose some update from some other process by doing this,
	 * but at least timeout count can't blow up. */
	if (cur_state.consecutive_timeouts == old_state.consecutive_timeouts) {
		if (++cur_state.consecutive_timeouts >=
		    KR_NS_TIMEOUT_ROW_DEAD) {
			cur_state.dead_since = kr_now();
		}
		put_rtt_state(address, transport->address_len, cur_state,
			      cache);
	} else {
		/* `get_rtt_state` opens a cache transaction, we have to end it. */
		kr_cache_commit(cache);
	}
}

void error(struct kr_query *qry, struct address_state *addr_state,
	   const struct kr_transport *transport,
	   enum kr_selection_error sel_error)
{
	if (!transport || !addr_state) {
		/* Answers from cache have NULL transport, ignore them. */
		return;
	}

	if (sel_error >= KR_SELECTION_NUMBER_OF_ERRORS) {
		assert(0);
	}

	if (sel_error == KR_SELECTION_QUERY_TIMEOUT) {
		qry->server_selection.local_state->timeouts++;
		// Make sure the query was chosen by this query
		if (!transport->deduplicated) {
			cache_timeout(transport, addr_state,
				      &qry->request->ctx->cache);
		}
	}

	if (sel_error == KR_SELECTION_TRUNCATED &&
	    transport->protocol == KR_TRANSPORT_UDP) {
		/* Don't punish the server that told us to switch to TCP. */
		qry->server_selection.local_state->truncated = true;
	} else {
		if (sel_error == KR_SELECTION_TRUNCATED) {
			/* TRUNCATED over TCP/TLS, upstream is broken. */
			addr_state->unrecoverable_errors++;
		}

		if (UNRECOVERABLE_ERRORS[sel_error]) {
			addr_state->unrecoverable_errors++;
		}

		if (sel_error == KR_SELECTION_FORMERROR && transport->safe_mode) {
			addr_state->unrecoverable_errors++;
		}

		addr_state->errors[sel_error]++;
		addr_state->error_count++;
	}
	
	WITH_VERBOSE(qry)
	{
	KR_DNAME_GET_STR(ns_name, transport->ns_name);
	KR_DNAME_GET_STR(zonecut_str, qry->zone_cut.name);
	const char *ns_str = kr_straddr(&transport->address.ip);

	VERBOSE_MSG(
		qry,
		"=> id: '%05u' noting selection error: '%s'@'%s' zone cut: '%s' error no.:%d\n",
		qry->id, ns_name, ns_str ? ns_str : "", zonecut_str,
		sel_error);
	}
}

void kr_server_selection_init(struct kr_query *qry)
{
	struct knot_mm *mempool = &qry->request->pool;
	if (qry->flags.FORWARD || qry->flags.STUB) {
		qry->server_selection = (struct kr_server_selection){
			.initialized = true,
			.choose_transport = forward_choose_transport,
			.update_rtt = forward_update_rtt,
			.error = forward_error,
			.local_state =
				mm_alloc(mempool, sizeof(struct local_state)),
		};
		memset(qry->server_selection.local_state, 0,
		       sizeof(struct local_state));
		forward_local_state_alloc(
			mempool, &qry->server_selection.local_state->private,
			qry->request);
	} else {
		qry->server_selection = (struct kr_server_selection){
			.initialized = true,
			.choose_transport = iter_choose_transport,
			.update_rtt = iter_update_rtt,
			.error = iter_error,
			.local_state =
				mm_alloc(mempool, sizeof(struct local_state)),
		};
		memset(qry->server_selection.local_state, 0,
		       sizeof(struct local_state));
		iter_local_state_alloc(
			mempool, &qry->server_selection.local_state->private);
	}
}

int kr_forward_add_target(struct kr_request *req, const struct sockaddr *sock)
{
	if (!req->selection_context.forwarding_targets.at) {
		return kr_error(EINVAL);
	}

	union inaddr address;

	switch (sock->sa_family) {
	case AF_INET:
		if (req->options.NO_IPV4)
			return kr_error(EINVAL);
		address.ip4 = *(const struct sockaddr_in *)sock;
		break;
	case AF_INET6:
		if (req->options.NO_IPV6)
			return kr_error(EINVAL);
		address.ip6 = *(const struct sockaddr_in6 *)sock;
		break;
	default:
		return kr_error(EINVAL);
	}

	array_push_mm(req->selection_context.forwarding_targets, address,
		      kr_memreserve, &req->pool);
	return kr_ok();
}
