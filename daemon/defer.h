/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdbool.h>
#include "lib/defines.h"
#include "lib/utils.h"
#include "lib/kru.h"

/// Initialize defer, incl. shared memory with KRU, excl. idle.
KR_EXPORT
int defer_init(const char *mmap_file, uint32_t log_period, uint32_t hard_timeout, int cpus);

/// Initialize idle and SIGALRM handler.
int defer_init_idle(uv_loop_t *loop);

/// Deinitialize shared memory.
void defer_deinit(void);

/// Increment KRU counters by the given time.
void defer_charge(uint64_t nsec, union kr_sockaddr *addr, bool stream);

struct kr_request;
/// Set the price-factor; see struct kr_request::qsource.price_factor16
KR_EXPORT
void defer_set_price_factor16(struct kr_request *req, uint32_t price_factor16);

typedef struct {
	bool is_accounting; /// whether currently accounting the time to someone
	bool stream;
	union kr_sockaddr addr; /// request source (to which we account) or AF_UNSPEC if unknown yet
	uint32_t price_factor16; /// see struct kr_request::qsource.price_factor16
	uint64_t stamp; /// monotonic nanoseconds, probably won't wrap
} defer_sample_state_t;
extern defer_sample_state_t defer_sample_state;

extern struct defer *defer;  /// skip sampling/deferring if NULL
extern bool defer_initialized; /// defer_init was called, possibly keeping defer disabled
extern uint64_t defer_uvtime_stamp; /// stamp of the last uv time update

// TODO: reconsider `static inline` cases below

#include <time.h>
static inline uint64_t defer_get_stamp(void)
{
	struct timespec now_ts = {0};
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now_ts);
	uint64_t stamp = now_ts.tv_nsec + 1000*1000*1000 * (uint64_t)now_ts.tv_sec;
	if (defer_uvtime_stamp + 1000*1000 < stamp) {
		defer_uvtime_stamp = stamp;
		uv_update_time(uv_default_loop()); // NOLINT, async-signal-safe
			// on Linux, it just calls clock_gettime(CLOCK_MONOTONIC[_COARSE], ...) and sets value for uv_now (kr_now);
			// libuv probably updates time just once per loop by itself
	}
	return stamp;
}

/// Annotate the work currently being accounted by an IP address.
static inline void defer_sample_addr(const union kr_sockaddr *addr, bool stream)
{
	if (!defer || kr_fails_assert(addr)) return;
	if (!defer_sample_state.is_accounting) return;

	if (defer_sample_state.addr.ip.sa_family != AF_UNSPEC) {
		// TODO: this costs performance, so only in some debug mode?
		if (kr_sockaddr_cmp(&addr->ip, &defer_sample_state.addr.ip) != kr_ok()) {
			char defer_addr[KR_STRADDR_MAXLEN + 1] = { 0 };
			strncpy(defer_addr, kr_straddr(&defer_sample_state.addr.ip), sizeof(defer_addr) - 1);
			kr_log_warning(DEFER, "Sampling address mismatch: %s != %s\n",
				kr_straddr(&addr->ip),
				defer_addr);
			return;
		}
	}

	switch (addr->ip.sa_family) {
	case AF_INET:
		defer_sample_state.addr.ip4 = addr->ip4;
		break;
	case AF_INET6:
		defer_sample_state.addr.ip6 = addr->ip6;
		break;
	default:
		defer_sample_state.addr.ip.sa_family = AF_UNSPEC;
		break;
	}
	defer_sample_state.stream = stream;
	defer_sample_state.price_factor16 = 1 << 16; // meaning *1.0, until more information is known
		// TODO set to the proper value on each invocation of defer_sample_addr
}

/// Internal; start accounting work at specified timestamp.
static inline void defer_sample_start_stamp(uint64_t stamp)
{
	if (!defer) return;
	kr_assert(!defer_sample_state.is_accounting);
	defer_sample_state.stamp = stamp;
	defer_sample_state.addr.ip.sa_family = AF_UNSPEC;
	__sync_synchronize();
	defer_sample_state.is_accounting = true;
}

/// Internal; stop accounting work at specified timestamp and charge the source if applicable.
static inline void defer_sample_stop_stamp(uint64_t stamp)
{
	if (!defer) return;
	kr_assert(defer_sample_state.is_accounting);
	defer_sample_state.is_accounting = false;
	__sync_synchronize();

	if (defer_sample_state.addr.ip.sa_family == AF_UNSPEC) return;

	const uint64_t elapsed = stamp - defer_sample_state.stamp;
	if (elapsed == 0) return;

	// TODO: some queries of internal origin have suspicioiusly high numbers.
	// We won't be really accounting those, but it might suggest some other issue.

	defer_charge(elapsed, &defer_sample_state.addr, defer_sample_state.stream);
}

static inline bool defer_sample_is_accounting(void)
{
	return defer_sample_state.is_accounting;
}

/// Start accounting work; optionally save state of current accounting.
/// Current state can be saved only after having an address assigned.
static inline void defer_sample_start(defer_sample_state_t *prev_state_out) {
	if (!defer) {
		if (prev_state_out) *prev_state_out = (defer_sample_state_t){ 0 }; // just to meet undefined-value check of linter, but never used
		return;
	}
	uint64_t stamp = defer_get_stamp();

	// suspend
	if (prev_state_out) {
		*prev_state_out = defer_sample_state;  // TODO stamp is not needed
		if (defer_sample_state.is_accounting)
			defer_sample_stop_stamp(stamp);
	}

	// start
	defer_sample_start_stamp(stamp);
}

/// Stop accounting and start it again.
static inline void defer_sample_restart(void) {
	if (!defer) return;
	uint64_t stamp = defer_get_stamp();

	// stop
	defer_sample_stop_stamp(stamp);

	// start
	defer_sample_start_stamp(stamp);
}

/// Stop accounting and charge the source if applicable; optionally resume previous accounting.
static inline void defer_sample_stop(defer_sample_state_t *prev_state, bool reuse_last_stamp) {
	if (!defer) return;
	uint64_t stamp = reuse_last_stamp ? defer_sample_state.stamp : defer_get_stamp();

	// stop
	defer_sample_stop_stamp(stamp);

	// resume
	if (prev_state) {
		defer_sample_state.addr = prev_state->addr;
		defer_sample_state.stream = prev_state->stream;
		defer_sample_state.stamp = stamp;
		__sync_synchronize();
		defer_sample_state.is_accounting = prev_state->is_accounting;
	}
}
