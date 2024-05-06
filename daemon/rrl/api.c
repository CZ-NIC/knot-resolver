#include <fcntl.h>
#include <sys/mman.h>

#include "daemon/rrl/api.h"
#include "daemon/rrl/kru.h"
#include "lib/utils.h"
#include "lib/resolve.h"


#define RRL_V4_PREFIXES  (uint8_t[])       {  18,  20, 24, 32 }
#define RRL_V4_RATE_MULT (kru_price_t[])   { 768, 256, 32,  1 }

#define RRL_V6_PREFIXES  (uint8_t[])       { 32, 48, 56, 64, 128 }
#define RRL_V6_RATE_MULT (kru_price_t[])   { 64,  4,  3,  2,   1 }

#define RRL_V4_PREFIXES_CNT (sizeof(RRL_V4_PREFIXES) / sizeof(*RRL_V4_PREFIXES))
#define RRL_V6_PREFIXES_CNT (sizeof(RRL_V6_PREFIXES) / sizeof(*RRL_V6_PREFIXES))
#define RRL_MAX_PREFIXES_CNT ((RRL_V4_PREFIXES_CNT > RRL_V6_PREFIXES_CNT) ? RRL_V4_PREFIXES_CNT : RRL_V6_PREFIXES_CNT)

struct rrl {
	size_t capacity;
	uint32_t instant_limit;
	uint32_t rate_limit;
	uint16_t tc_limit;
	bool using_avx2;
	kru_price_t v4_prices[RRL_V4_PREFIXES_CNT];
	kru_price_t v6_prices[RRL_V6_PREFIXES_CNT];
	uint8_t kru[] ALIGNED(64);
};
struct rrl *the_rrl = NULL;
int the_rrl_fd = -1;
char *the_rrl_mmap_file = NULL;

/// return whether we're using optimized variant right now
static bool using_avx2(void)
{
	bool result = (KRU.initialize == KRU_AVX2.initialize);
	kr_require(result || KRU.initialize == KRU_GENERIC.initialize);
	return result;
}

void kr_rrl_init(const char *mmap_file, size_t capacity, uint32_t instant_limit, uint32_t rate_limit, int tc_limit_perc)
{
	int fd = the_rrl_fd = open(mmap_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		kr_log_crit(SYSTEM, "Cannot open file %s containing shared rate-limiting data: %s\n",
				mmap_file, strerror(errno));
		abort();
	}

	the_rrl_mmap_file = malloc(strlen(mmap_file) + 1);
	strcpy(the_rrl_mmap_file, mmap_file);

	size_t capacity_log = 0;
	for (size_t c = capacity - 1; c > 0; c >>= 1) capacity_log++;

	size_t size = offsetof(struct rrl, kru) + KRU.get_size(capacity_log);

	uint16_t tc_limit = (tc_limit_perc == 100 ? -1 : ((uint32_t)tc_limit_perc << 16) / 100);

	// try to acquire write lock; initialize KRU on success
	struct flock fl = {
		.l_type   = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0 };
	if (fcntl(fd, F_SETLK, &fl) != -1) {
		kr_log_info(SYSTEM, "Initializing rate-limiting...\n");
		if (ftruncate(fd, 0) == -1 || ftruncate(fd, size) == -1) {  // get all zeroed
			kr_log_crit(SYSTEM, "Cannot change size of file %s containing shared rate-limiting data: %s\n",
					mmap_file, strerror(errno));
			abort();
		}
		the_rrl = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		kr_require(the_rrl != MAP_FAILED);

		the_rrl->capacity = capacity;
		the_rrl->instant_limit = instant_limit;
		the_rrl->rate_limit = rate_limit;
		the_rrl->tc_limit = tc_limit;
		the_rrl->using_avx2 = using_avx2();

		const kru_price_t base_price = KRU_LIMIT / instant_limit;
		const kru_price_t max_decay = rate_limit > 1000ll * instant_limit ? base_price :
			(uint64_t) base_price * rate_limit / 1000;

		bool succ = KRU.initialize((struct kru *)the_rrl->kru, capacity_log, max_decay);
		kr_require(succ);

		for (size_t i = 0; i < RRL_V4_PREFIXES_CNT; i++) {
			the_rrl->v4_prices[i] = base_price / RRL_V4_RATE_MULT[i];
		}

		for (size_t i = 0; i < RRL_V6_PREFIXES_CNT; i++) {
			the_rrl->v6_prices[i] = base_price / RRL_V6_RATE_MULT[i];
		}

		fl.l_type = F_RDLCK;
		succ = (fcntl(fd, F_SETLK, &fl) != -1);
		kr_require(succ);
		kr_log_info(SYSTEM, "Rate-limiting initialized (%s).\n", (the_rrl->using_avx2 ? "AVX2" : "generic"));

		return;
	}

	// wait for acquiring shared lock; check KRU parameters on success
	fl.l_type = F_RDLCK;
	if (fcntl(fd, F_SETLKW, &fl) != -1) {
		kr_log_info(SYSTEM, "Checking existing RRL data...\n");
		struct stat s;
		bool succ = (fstat(fd, &s) == 0);
		kr_require(succ);
		if (s.st_size != size) goto check_fail;
		the_rrl = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		kr_require(the_rrl != MAP_FAILED);
		if ((the_rrl->capacity != capacity) || (the_rrl->instant_limit != instant_limit) ||
				(the_rrl->rate_limit != rate_limit) || (the_rrl->tc_limit != tc_limit)) goto check_fail;
		if (using_avx2() != the_rrl->using_avx2) goto check_fail;
		kr_log_info(SYSTEM, "Using existing RRL data.\n");

		return;
	}

	kr_require(false);  // we can get here for example if signal interrupt is received during fcntl

check_fail:
	kr_log_crit(SYSTEM, "Another instance of kresd uses rate-limiting with different configuration, cannot share data in %s.", mmap_file);
	abort();
}

void kr_rrl_deinit(void)
{
	if (the_rrl == NULL) return;
	int fd = the_rrl_fd;

	struct flock fl = {
		.l_type   = F_UNLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0 };
	fcntl(fd, F_SETLK, &fl);  // unlock

	fl.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLK, &fl) != -1) {

		/* If the RRL configuration is updated at runtime, manager removes the file
		 * and the new processes create it again while old processes are still using the old data.
		 * Here we keep zero-size file not to accidentally remove the new file instead of the old one.
		 * Still truncating the file will cause currently starting processes waiting for read lock on the same file to fail,
		 * but such processes are not expected to exist. */
		ftruncate(fd, 0);

		fl.l_type = F_UNLCK;
		fcntl(fd, F_SETLK, &fl);
	}

	the_rrl = NULL;
}

bool kr_rrl_request_begin(struct kr_request *req)
{
	if (!req->qsource.addr)
		return false;  // don't consider internal requests
	uint8_t limited = 0;  // 0: not limited, 1: truncated, 2: no answer
	uint16_t max_final_load = 0;
	if (the_rrl) {
		uint8_t key[16] ALIGNED(16) = {0, };
		uint8_t limited_prefix;
		if (req->qsource.addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)req->qsource.addr;
			memcpy(key, &ipv6->sin6_addr, 16);

			limited_prefix = KRU.limited_multi_prefix_or((struct kru *)the_rrl->kru, kr_now(),
					1, key, RRL_V6_PREFIXES, the_rrl->v6_prices, RRL_V6_PREFIXES_CNT, &max_final_load);
		} else {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)req->qsource.addr;
			memcpy(key, &ipv4->sin_addr, 4);  // TODO append port?

			limited_prefix = KRU.limited_multi_prefix_or((struct kru *)the_rrl->kru, kr_now(),
					0, key, RRL_V4_PREFIXES, the_rrl->v4_prices, RRL_V4_PREFIXES_CNT, &max_final_load);
		}
		limited = (limited_prefix ? 2 : (max_final_load > the_rrl->tc_limit ? 1 : 0));
	}
	if (!limited) return false;

	knot_pkt_t *answer = kr_request_ensure_answer(req);
	if (!answer) { // something bad; TODO: perhaps improve recovery from this
		kr_assert(false);
		return true;
	}
	// at this point the packet should be pretty clear

	if (limited == 1) {
		// TC=1.
		knot_wire_set_tc(answer->wire);
		knot_wire_clear_ad(answer->wire);
		req->state = KR_STATE_DONE;
	} else {
		/*
		// Example limiting: REFUSED.
		knot_wire_set_rcode(answer->wire, KNOT_RCODE_REFUSED);
		kr_request_set_extended_error(req, KNOT_EDNS_EDE_OTHER, "YRAA: rate-limited");
		req->state = KR_STATE_DONE;
		*/

		// no answer
		req->options.NO_ANSWER = true;
		req->state = KR_STATE_FAIL;
	}

	return true;
}
