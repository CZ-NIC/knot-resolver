#include <stdbool.h>
#include "lib/defines.h"
#include "lib/utils.h"
#include "lib/kru.h"

/// Initialize defer, incl. shared memory with KRU.
int defer_init(uv_loop_t *loop);

/// Deinitialize shared memory.
void defer_deinit(void);

/// Increment KRU counters by the given time.
void defer_account(uint64_t nsec, union kr_sockaddr addr);

typedef struct {
	int8_t is_accounting; /// whether currently accounting the time to someone; should be 0/1
	union kr_sockaddr addr; /// request source (to which we account) or AF_UNSPEC if unknown yet
	uint64_t stamp; /// monotonic nanoseconds, probably won't wrap
} defer_sample_state_t;
extern defer_sample_state_t defer_sample_state;

extern struct defer *defer;  /// skip sampling/deferring if NULL


// TODO: reconsider `static inline` cases below

#include <time.h>
static inline uint64_t get_stamp(void)
{
	struct timespec now_ts = {0};
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now_ts);
	return now_ts.tv_nsec + 1000*1000*1000 * (uint64_t)now_ts.tv_sec;
}

/// Start accounting work, if not doing it already.
static inline void defer_sample_start(void)
{
	if (!defer) return;
	kr_assert(!defer_sample_state.is_accounting);
	++defer_sample_state.is_accounting;
	defer_sample_state.stamp = get_stamp();
	defer_sample_state.addr.ip.sa_family = AF_UNSPEC;
}

/// Annotate the work currently being accounted by an IP address.
static inline void defer_sample_addr(const union kr_sockaddr *addr)
{
	if (!defer || kr_fails_assert(addr)) return;
	if (!defer_sample_state.is_accounting) return;

	if (defer_sample_state.addr.ip.sa_family != AF_UNSPEC) {
		// TODO: this costs performance, so only in some debug mode?
		kr_assert(kr_sockaddr_cmp(&addr->ip, &defer_sample_state.addr.ip) == kr_ok());
		return;
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
}

/// Stop accounting work - and change the source if applicable.
static inline void defer_sample_stop(void)
{
	if (!defer) return;

	if (kr_fails_assert(defer_sample_state.is_accounting > 0)) return; // weird
	if (--defer_sample_state.is_accounting) return;

	const uint64_t elapsed = get_stamp() - defer_sample_state.stamp;

	// we accounted something

	// TODO: some queries of internal origin have suspicioiusly high numbers.
	// We won't be really accounting those, but it might suggest some other issue.

	defer_account(elapsed, defer_sample_state.addr);
}
