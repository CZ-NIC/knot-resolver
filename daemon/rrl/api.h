
#include <stdbool.h>
#include "lib/defines.h"
#include "lib/utils.h"
struct kr_request;

/** Initialize rate-limiting with shared mmapped memory.
 * The existing data are used if another instance is already using the file
 * and it was initialized with the same parameters; it fails on mismatch. */
KR_EXPORT
void kr_rrl_init(const char *mmap_file, size_t capacity, uint32_t instant_limit, uint32_t rate_limit, int tc_limit_perc);

/** Do rate-limiting, during knot_layer_api::begin. */
KR_EXPORT
bool kr_rrl_request_begin(struct kr_request *req);

/** Remove mmapped file data if not used by other processes. */
KR_EXPORT
void kr_rrl_deinit(void);


// TODO: reconsider `static inline` cases below

#define USE_RDTSC  // TODO: determine somehow, probably on runtime
#ifdef USE_RDTSC
#include "x86intrin.h"
#endif

typedef struct {
	uint64_t ns; /// monotonic nanoseconds, probably won't wrap
#ifdef USE_RDTSC
	uint64_t ticks; // TSC ticks, may be desynchronized on different cpus
#endif
} kr_rrl_stamp_t;

typedef struct {
	bool do_sample; /// whether to sample; could be important if _COARSE isn't available
	int8_t is_accounting; /// whether currently accounting the time to someone; should be 0/1
	union kr_sockaddr addr; /// request source (to which we account) or AF_UNSPEC if unknown yet
	kr_rrl_stamp_t stamp; /// timestamp when accounting started
#ifdef USE_RDTSC
	kr_rrl_stamp_t total; /// sum of all accounted timediffs
	uint64_t ns_res; // resolution of ns stamp
#endif
} kr_rrl_sample_state_t;
extern kr_rrl_sample_state_t kr_rrl_sample_state;

#include <time.h>
static inline void get_stamp(kr_rrl_stamp_t *stamp)
{
	/* TODO:
	    * think of strategies for non-Linux
	      - for platforms without _COARSE this might be expensive
	        (~2 syscalls per incoming packet)
	      - FreeBSD defines _COARSE (see their man clock_gettime.2)
	        that looks like it has the same semantics, but they look like all their timers
	        are syscall-free
	    * the design will probably break on Linux kernel if started as tickless/realtime
	*/
#ifndef CLOCK_MONOTONIC_COARSE
	const clockid_t CLOCK_MONOTONIC_COARSE = CLOCK_MONOTONIC;
#endif

	struct timespec now_ts = {0};
	clock_gettime(CLOCK_MONOTONIC_COARSE, &now_ts);

	/* Note: kr_now() call would be similarly cheap and typically more precise,
	 * but it gets updated exactly in moments when we don't want,
	 * so the _COARSE stamp is be much better in this case. */
	stamp->ns = now_ts.tv_nsec + 1000*1000*1000 * (uint64_t)now_ts.tv_sec;
#ifdef USE_RDTSC
	stamp->ticks = _rdtsc();
#endif
}
static inline uint64_t get_stamp_diff_ns(kr_rrl_stamp_t *stamp_end, kr_rrl_stamp_t *stamp_begin) {
	uint64_t ns = stamp_end->ns - stamp_begin->ns;
#ifdef USE_RDTSC
	if (stamp_end->ticks <= stamp_begin->ticks) {
		return ns;
	}
	uint64_t ticks = stamp_end->ticks - stamp_begin->ticks;
	kr_rrl_sample_state.total.ns += ns;
	kr_rrl_sample_state.total.ticks += ticks;
	uint64_t ticks_ns = ticks * ((double)kr_rrl_sample_state.total.ns / kr_rrl_sample_state.total.ticks);

	if (kr_rrl_sample_state.ns_res == 0) {
		struct timespec res = {0};
		clock_getres(CLOCK_MONOTONIC_COARSE, &res);
		kr_rrl_sample_state.ns_res = res.tv_nsec;
		kr_log_notice(DEVEL, "%5.3f ms res\n", kr_rrl_sample_state.ns_res / 1000000.0); // TODO drop
	}
	if ((ns + kr_rrl_sample_state.ns_res >= ticks_ns) && (ticks_ns + kr_rrl_sample_state.ns_res >= ns)) {
		return ticks_ns;
	}
#endif
	return ns;
}

/// Start accounting work, if not doing it already.
static inline void kr_rrl_sample_start(void)
{
	if (!kr_rrl_sample_state.do_sample) return;
	kr_assert(!kr_rrl_sample_state.is_accounting);
	++kr_rrl_sample_state.is_accounting;
	get_stamp(&kr_rrl_sample_state.stamp);
	kr_rrl_sample_state.addr.ip.sa_family = AF_UNSPEC;
}

/// Annotate the work currently being accounted by an IP address.
static inline void kr_rrl_sample_addr(const union kr_sockaddr *addr)
{
	if (!kr_rrl_sample_state.do_sample || kr_fails_assert(addr)) return;
	if (!kr_rrl_sample_state.is_accounting) return;

	if (kr_rrl_sample_state.addr.ip.sa_family != AF_UNSPEC) {
		// TODO: this costs performance, so only in some debug mode?
		kr_assert(kr_sockaddr_cmp(&addr->ip, &kr_rrl_sample_state.addr.ip) == kr_ok());
		return;
	}

	switch (addr->ip.sa_family) {
	case AF_INET:
		kr_rrl_sample_state.addr.ip4 = addr->ip4;
		break;
	case AF_INET6:
		kr_rrl_sample_state.addr.ip6 = addr->ip6;
		break;
	default:
		kr_rrl_sample_state.addr.ip.sa_family = AF_UNSPEC;
		break;
	}
}

/// Stop accounting work - and change the source if applicable.
static inline void kr_rrl_sample_stop(void)
{
	if (!kr_rrl_sample_state.do_sample) return;

	if (kr_fails_assert(kr_rrl_sample_state.is_accounting > 0)) return; // weird
	if (--kr_rrl_sample_state.is_accounting) return;

	kr_rrl_stamp_t stamp;
	get_stamp(&stamp);
	const uint64_t elapsed = get_stamp_diff_ns(&stamp, &kr_rrl_sample_state.stamp);
	const uint64_t elapsed_coarse = stamp.ns - kr_rrl_sample_state.stamp.ns;  // TODO drop
	if ((elapsed < 1000) && !elapsed_coarse) return;

	// we accounted something
	// FIXME: drop the log, add KRU, etc.
	kr_log_notice(DEVEL, "%5.3f ms (%5.3f ms _COARSE) for %s\n", elapsed / 1000000.0, elapsed_coarse / 1000000.0,
			kr_straddr(&kr_rrl_sample_state.addr.ip));
	// TODO: some queries of internal origin have suspicioiusly high numbers.
	// We won't be really accounting those, but it might suggest some other issue.
}
