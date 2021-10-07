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

#define VERBOSE_MSG(qry, ...) QRVERBOSE((qry), SELECTION, __VA_ARGS__)

#define DEFAULT_TIMEOUT 400
#define MAX_TIMEOUT 10000
#define EXPLORE_TIMEOUT_COEFFICIENT 2
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

static const char *kr_selection_error_str(enum kr_selection_error err) {
	switch (err) {
	#define X(ENAME) case KR_SELECTION_ ## ENAME: return #ENAME
		X(OK);
		X(QUERY_TIMEOUT);
		X(TLS_HANDSHAKE_FAILED);
		X(TCP_CONNECT_FAILED);
		X(TCP_CONNECT_TIMEOUT);
		X(REFUSED);
		X(SERVFAIL);
		X(FORMERR);
		X(FORMERR_EDNS);
		X(NOTIMPL);
		X(OTHER_RCODE);
		X(MALFORMED);
		X(MISMATCHED);
		X(TRUNCATED);
		X(DNSSEC_ERROR);
		X(LAME_DELEGATION);
		X(BAD_CNAME);
		case KR_SELECTION_NUMBER_OF_ERRORS: break; // not a valid code
	#undef X
	}
	kr_assert(false); // we want to define all; compiler helps by -Wswitch (no default:)
	return NULL;
}


/* Simple detection of IPv6 being broken.
 *
 * We follow all IPv6 timeouts and successes.  Consider it broken iff we've had
 * timeouts on several different IPv6 prefixes since the last IPv6 success.
 * Note: unlike the rtt_state, this happens only per-process (for simplicity).
 *
 * ## NO6_PREFIX_* choice
 *   For our practical use we choose primarily based on root and typical TLD servers.
 *   Looking at *.{root,gtld}-servers.net, we have 7/26 AAAAs in 2001:500:00**::
 *   but adding one more byte makes these completely unique, so we choose /48.
 *   As distribution to ASs seems to be on shorter prefixes (RIPE: /32 -- /24?),
 *   we wait for several distinct prefixes.
 */

#define NO6_PREFIX_COUNT 6
#define NO6_PREFIX_BYTES (48/8)
static struct {
	int len_used;
	uint8_t addr_prefixes[NO6_PREFIX_COUNT][NO6_PREFIX_BYTES];
} no6_est = { .len_used = 0 };

static inline bool no6_is_bad(void)
{
	return no6_est.len_used == NO6_PREFIX_COUNT;
}

static void no6_timeouted(const struct kr_query *qry, const uint8_t *addr)
{
	if (no6_is_bad()) { // we can't get worse
		VERBOSE_MSG(qry, "NO6: timeouted, but bad already\n");
		return;
	}
	// If we have the address already, do nothing.
	for (int i = 0; i < no6_est.len_used; ++i) {
		if (memcmp(addr, no6_est.addr_prefixes[i], NO6_PREFIX_BYTES) == 0) {
			VERBOSE_MSG(qry, "NO6: timeouted, repeated prefix, timeouts %d/%d\n",
					no6_est.len_used, (int)NO6_PREFIX_COUNT);
			return;
		}
	}
	// Append!
	memcpy(no6_est.addr_prefixes[no6_est.len_used++], addr, NO6_PREFIX_BYTES);
	VERBOSE_MSG(qry, "NO6: timeouted, appended, timeouts %d/%d\n",
			no6_est.len_used, (int)NO6_PREFIX_COUNT);
}

static inline void no6_success(const struct kr_query *qry)
{
	if (no6_est.len_used) {
		VERBOSE_MSG(qry, "NO6: success, zeroing %d/%d\n",
				no6_est.len_used, (int)NO6_PREFIX_COUNT);
	}
	no6_est.len_used = 0;
}


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

/* First value of timeout will be calculated as SRTT+4*VARIANCE
 * by calc_timeout(), so it'll be equal to DEFAULT_TIMEOUT. */
static const struct rtt_state default_rtt_state = { .srtt = 0,
						    .variance = DEFAULT_TIMEOUT / 4,
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
	} else if (kr_fails_assert(value.len == sizeof(struct rtt_state))) {
		// shouldn't happen but let's be more robust
		state = default_rtt_state;
	} else { // memcpy is safe for unaligned case (on non-x86)
		memcpy(&state, value.data, sizeof(state));
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

void bytes_to_ip(uint8_t *bytes, size_t len, uint16_t port, union inaddr *dst)
{
	switch (len) {
	case sizeof(struct in_addr):
		dst->ip4.sin_family = AF_INET;
		memcpy(&dst->ip4.sin_addr, bytes, len);
		dst->ip4.sin_port = htons(port);
		break;
	case sizeof(struct in6_addr):
		memset(&dst->ip6, 0, sizeof(dst->ip6)); // avoid uninit surprises
		dst->ip6.sin6_family = AF_INET6;
		memcpy(&dst->ip6.sin6_addr, bytes, len);
		dst->ip6.sin6_port = htons(port);
		break;
	default:
		kr_assert(false);
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
		kr_assert(false);
		return NULL;
	}
}

static bool no_rtt_info(struct rtt_state s)
{
	return s.srtt == 0 && s.consecutive_timeouts == 0;
}

static unsigned back_off_timeout(uint32_t to, int pow)
{
	pow = MIN(pow, MAX_BACKOFF);
	to <<= pow;
	return MIN(to, MAX_TIMEOUT);
}

/* This is verbatim (minus the default timeout value and minimal variance)
 * RFC6298, sec. 2. */
static unsigned calc_timeout(struct rtt_state state)
{
	int32_t timeout = state.srtt + MAX(4 * state.variance, MINIMAL_TIMEOUT_ADDITION);
	return back_off_timeout(timeout, state.consecutive_timeouts);
}

/* This is verbatim RFC6298, sec. 2. */
static struct rtt_state calc_rtt_state(struct rtt_state old, unsigned new_rtt)
{
	if (no_rtt_info(old)) {
		return (struct rtt_state){ new_rtt, new_rtt / 2, 0 };
	}

	struct rtt_state ret = { 0 };
	ret.variance = (3 * old.variance + abs(old.srtt - (int32_t)new_rtt)
			+ 2/*rounding*/) / 4;
	ret.srtt = (7 * old.srtt + new_rtt + 4/*rounding*/) / 8;

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
			kr_assert(now >= rs->dead_since + retry_timeout);
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

void update_address_state(struct address_state *state, union inaddr *address,
			  size_t address_len, struct kr_query *qry)
{
	check_tls_capable(state, qry->request, &address->ip);
	/* TODO: uncomment this once we actually use the information it collects
	check_tcp_connections(address_state, qry->request, &address->ip);
	*/
	check_network_settings(state, address_len, qry->flags.NO_IPV4,
			       qry->flags.NO_IPV6);
	state->rtt_state =
		get_rtt_state(ip_to_bytes(address, address_len),
		              address_len, &qry->request->ctx->cache);
	invalidate_dead_upstream(
		state, qry->request->ctx->cache_rtt_tout_retry_interval);
#ifdef SELECTION_CHOICE_LOGGING
	// This is sometimes useful for debugging, but usually too verbose
	if (kr_log_is_debug_qry(SELECTION, qry)) {
		const char *ns_str = kr_straddr(&address->ip);
		VERBOSE_MSG(qry, "rtt of %s is %d, variance is %d\n", ns_str,
			    state->rtt_state.srtt, state->rtt_state.variance);
	}
#endif
}

static int cmp_choices(const void *a, const void *b)
{
	const struct choice *a_ = a;
	const struct choice *b_ = b;

	int diff;
	/* Prefer IPv4 if IPv6 appears to be generally broken. */
	diff = (int)a_->address_len - (int)b_->address_len;
	if (diff && no6_is_bad()) {
		return diff;
	}
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

/* Adjust choice from `unresolved` in case of NO6 (broken IPv6). */
static struct kr_transport unresolved_adjust(struct to_resolve unresolved[],
					     int unresolved_len, int index)
{
	if (unresolved[index].type != KR_TRANSPORT_RESOLVE_AAAA || !no6_is_bad())
		goto finish;
	/* AAAA is detected as bad; let's choose randomly from others, if there are any. */
	int aaaa_count = 0;
	for (int i = 0; i < unresolved_len; ++i)
		aaaa_count += (unresolved[i].type == KR_TRANSPORT_RESOLVE_AAAA);
	if (aaaa_count == unresolved_len)
		goto finish;
	/* Chosen index within non-AAAA items. */
	int i_no6 = kr_rand_bytes(1) % (unresolved_len - aaaa_count);
	for (int i = 0; i < unresolved_len; ++i) {
		if (unresolved[i].type == KR_TRANSPORT_RESOLVE_AAAA) {
			//continue
		} else if (i_no6 == 0) {
			index = i;
			break;
		} else {
			--i_no6;
		}
	}
finish:
	return (struct kr_transport){
		.protocol = unresolved[index].type,
		.ns_name = unresolved[index].name
	};
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

	struct kr_transport *transport = mm_calloc(mempool, 1, sizeof(*transport));

	/* Shuffle, so we choose fairly between choices with same attributes. */
	shuffle_choices(choices, choices_len);
	/* If there are some addresses with no rtt_info we try them
	 * first (see cmp_choices). So unknown servers are chosen
	 * *before* the best know server. This ensures that every option
	 * is tried before going back to some that was tried before. */
	qsort(choices, choices_len, sizeof(struct choice), cmp_choices);
	struct choice *best = &choices[0];
	struct choice *chosen;

	const bool explore = choices_len == 0 || kr_rand_coin(EPSILON_NOMIN, EPSILON_DENOM);
	if (explore) {
		/* "EXPLORE":
		 * randomly choose some option
		 * (including resolution of some new name). */
		int index = kr_rand_bytes(1) % (choices_len + unresolved_len);
		if (index < unresolved_len) {
			// We will resolve a new NS name
			*transport = unresolved_adjust(unresolved, unresolved_len, index);
			return transport;
		} else {
			chosen = &choices[index - unresolved_len];
		}
	} else {
		/* "EXPLOIT":
		 * choose a resolved address which seems best right now. */
		chosen = best;
		if (no6_is_bad())
			VERBOSE_MSG(NULL, "NO6: is KO [exploit]\n");
	}

	/* Don't try the same server again when there are other choices to be explored */
	if (chosen->address_state->error_count && unresolved_len) {
		int index = kr_rand_bytes(1) % unresolved_len;
		*transport = unresolved_adjust(unresolved, unresolved_len, index);
		return transport;
	}

	unsigned timeout;
	if (no_rtt_info(chosen->address_state->rtt_state)) {
		/* Exponential back-off when retrying after timeout and choosing
		 * an unknown server. */
		timeout = back_off_timeout(DEFAULT_TIMEOUT, timeouts);
	} else {
		timeout = calc_timeout(chosen->address_state->rtt_state);
		if (explore) {
			/* When trying a random server, we cap the timeout to EXPLORE_TIMEOUT_COEFFICIENT
			 * times the timeout for the best server. This is done so we don't spend
			 * unreasonable amounts of time probing really bad servers while still
			 * checking once in a while for e.g. big network change etc.
			 * We also note this capping was done and don't punish the bad server
			 * further if it fails to answer in the capped timeout. */
			unsigned best_timeout = calc_timeout(best->address_state->rtt_state);
			if (timeout > best_timeout * EXPLORE_TIMEOUT_COEFFICIENT) {
				timeout = best_timeout * EXPLORE_TIMEOUT_COEFFICIENT;
				transport->timeout_capped = true;
			}
		}
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
	};

	int port = chosen->port;
	if (!port) {
		switch (transport->protocol) {
		case KR_TRANSPORT_TLS:
			port = KR_DNS_TLS_PORT;
			break;
		case KR_TRANSPORT_UDP:
		case KR_TRANSPORT_TCP:
			port = KR_DNS_PORT;
			break;
		default:
			kr_assert(false);
			return NULL;
		}
	}

	switch (chosen->address_len)
	{
	case sizeof(struct in_addr):
		transport->address.ip4 = chosen->address.ip4;
		transport->address.ip4.sin_port = htons(port);
		break;
	case sizeof(struct in6_addr):
		transport->address.ip6 = chosen->address.ip6;
		transport->address.ip6.sin6_port = htons(port);
		break;
	default:
		kr_assert(false);
		return NULL;
	}

	transport->address_len = chosen->address_len;

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

	uint8_t *address = ip_to_bytes(&transport->address, transport->address_len);
	/* This construct is a bit racy since the global state may change
	 * between calls to `get_rtt_state` and `put_rtt_state`  but we don't
	 * care that much since it is rare and we only risk slightly suboptimal
	 * transport choice. */
	struct rtt_state cur_rtt_state =
		get_rtt_state(address, transport->address_len, cache);
	struct rtt_state new_rtt_state = calc_rtt_state(cur_rtt_state, rtt);
	put_rtt_state(address, transport->address_len, new_rtt_state, cache);

	if (transport->address_len == sizeof(struct in6_addr))
		no6_success(qry);

	if (kr_log_is_debug_qry(SELECTION, qry)) {
		KR_DNAME_GET_STR(ns_name, transport->ns_name);
		KR_DNAME_GET_STR(zonecut_str, qry->zone_cut.name);
		const char *ns_str = kr_straddr(&transport->address.ip);

		VERBOSE_MSG(
			qry,
			"=> id: '%05u' updating: '%s'@'%s' zone cut: '%s'"
			" with rtt %u to srtt: %d and variance: %d \n",
			qry->id, ns_name, ns_str ? ns_str : "", zonecut_str,
			rtt, new_rtt_state.srtt, new_rtt_state.variance);
	}
}

static void cache_timeout(const struct kr_query *qry, const struct kr_transport *transport,
			  struct address_state *addr_state, struct kr_cache *cache)
{
	if (transport->deduplicated) {
		/* Transport was chosen by a different query, that one will
		 * cache the result. */
		return;
	}

	uint8_t *address = ip_to_bytes(&transport->address, transport->address_len);
	if (transport->address_len == sizeof(struct in6_addr))
		no6_timeouted(qry, address);

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
		put_rtt_state(address, transport->address_len, cur_state, cache);
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

	switch (sel_error) {
	case KR_SELECTION_OK:
		return;
	case KR_SELECTION_TCP_CONNECT_FAILED:
	case KR_SELECTION_TCP_CONNECT_TIMEOUT:
		qry->server_selection.local_state->force_udp = true;
		qry->flags.NO_0X20 = false;
		/* Connection and handshake failures have properties similar
		 * to UDP timeouts, so we handle them (almost) the same way. */
		/* fall-through */
	case KR_SELECTION_TLS_HANDSHAKE_FAILED:
	case KR_SELECTION_QUERY_TIMEOUT:
		qry->server_selection.local_state->timeouts++;
		/* Make sure that the query was chosen by this query and timeout wasn't capped
		 * (see kr_transport::timeout_capped for details). */
		if (!transport->deduplicated && !transport->timeout_capped) {
			cache_timeout(qry, transport, addr_state,
				      &qry->request->ctx->cache);
		}
		break;
	case KR_SELECTION_FORMERR:
		if (qry->flags.NO_EDNS) {
			addr_state->broken = true;
		} else {
			qry->flags.NO_EDNS = true;
		}
		break;
	case KR_SELECTION_FORMERR_EDNS:
		addr_state->broken = true;
		break;
	case KR_SELECTION_MISMATCHED:
		if (qry->flags.NO_0X20 && qry->flags.TCP) {
			addr_state->broken = true;
		} else {
			qry->flags.TCP = true;
			qry->flags.NO_0X20 = true;
		}
		break;
	case KR_SELECTION_TRUNCATED:
		if (transport->protocol == KR_TRANSPORT_UDP) {
			qry->server_selection.local_state->truncated = true;
			/* TC=1 over UDP is not an error, so we compensate. */
			addr_state->error_count--;
		} else {
			addr_state->broken = true;
		}
		break;
	case KR_SELECTION_REFUSED:
	case KR_SELECTION_SERVFAIL:
		if (qry->flags.NO_MINIMIZE && qry->flags.NO_0X20 && qry->flags.TCP) {
			addr_state->broken = true;
		} else if (qry->flags.NO_MINIMIZE) {
			qry->flags.NO_0X20 = true;
			qry->flags.TCP = true;
		} else {
			qry->flags.NO_MINIMIZE = true;
		}
		break;
	case KR_SELECTION_LAME_DELEGATION:
		if (qry->flags.NO_MINIMIZE) {
			/* Lame delegations are weird, they breed more lame delegations on broken
			* zones since trying another server from the same set usualy doesn't help.
			* We force resolution of another NS name in hope of getting somewhere. */
			qry->server_selection.local_state->force_resolve = true;
			addr_state->broken = true;
		} else {
			qry->flags.NO_MINIMIZE = true;
		}
		break;
	case KR_SELECTION_NOTIMPL:
	case KR_SELECTION_OTHER_RCODE:
	case KR_SELECTION_DNSSEC_ERROR:
	case KR_SELECTION_BAD_CNAME:
	case KR_SELECTION_MALFORMED:
		/* These errors are fatal, no point in trying this server again. */
		addr_state->broken = true;
		break;
	default:
		kr_assert(false);
		return;
	}

	addr_state->error_count++;
	addr_state->errors[sel_error]++;

	if (kr_log_is_debug_qry(SELECTION, qry)) {
		KR_DNAME_GET_STR(ns_name, transport->ns_name);
		KR_DNAME_GET_STR(zonecut_str, qry->zone_cut.name);
		const char *ns_str = kr_straddr(&transport->address.ip);
		const char *err_str = kr_selection_error_str(sel_error);

		VERBOSE_MSG(
			qry,
			"=> id: '%05u' noting selection error: '%s'@'%s'"
			" zone cut: '%s' error: %d %s\n",
			qry->id, ns_name, ns_str ? ns_str : "",
			zonecut_str, sel_error, err_str ? err_str : "??");
	}
}

void kr_server_selection_init(struct kr_query *qry)
{
	struct knot_mm *mempool = &qry->request->pool;
	struct local_state *local_state = mm_calloc(mempool, 1, sizeof(*local_state));

	if (qry->flags.FORWARD || qry->flags.STUB) {
		qry->server_selection = (struct kr_server_selection){
			.initialized = true,
			.choose_transport = forward_choose_transport,
			.update_rtt = forward_update_rtt,
			.error = forward_error,
			.local_state = local_state,
		};
		forward_local_state_alloc(
			mempool, &qry->server_selection.local_state->private,
			qry->request);
	} else {
		qry->server_selection = (struct kr_server_selection){
			.initialized = true,
			.choose_transport = iter_choose_transport,
			.update_rtt = iter_update_rtt,
			.error = iter_error,
			.local_state = local_state,
		};
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
