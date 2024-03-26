#include <fcntl.h>
#include <sys/mman.h>

#include "daemon/rrl/api.h"
#include "daemon/rrl/kru.h"
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
	kru_price_t v4_prices[RRL_V4_PREFIXES_CNT];
	kru_price_t v6_prices[RRL_V6_PREFIXES_CNT];
	uint8_t kru[] ALIGNED(64);
};
struct rrl *the_rrl = NULL;

void kr_rrl_init(char *mmap_path, size_t capacity, uint32_t instant_limit, uint32_t rate_limit) {
	int fd = open(mmap_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	kr_require(fd != -1);

	size_t capacity_log = 0;
	for (size_t c = capacity - 1; c > 0; c >>= 1) capacity_log++;

	size_t size = offsetof(struct rrl, kru) + KRU.get_size(capacity_log);

	// try to acquire write lock; initialize KRU on success
	struct flock fl = {
		.l_type   = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0 };
	if (fcntl(fd, F_SETLK, &fl) != -1) {
		kr_log_info(SYSTEM, "Initializing RRL...\n");
		ftruncate(fd, 0);
		ftruncate(fd, size);  // get all zeroed
		the_rrl = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		kr_require(the_rrl != MAP_FAILED);

		the_rrl->capacity = capacity;
		the_rrl->instant_limit = instant_limit;
		the_rrl->rate_limit = rate_limit;

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
		kr_log_info(SYSTEM, "RRL initialized.\n");

		return;
	};

	// wait for acquiring shared lock; check KRU parameters on success
	fl.l_type = F_RDLCK;
	if (fcntl(fd, F_SETLKW, &fl) != -1) {
		kr_log_info(SYSTEM, "Checking existing RRL data...\n");
		struct stat s;
		bool succ = (fstat(fd, &s) == 0);
		kr_require(succ);
		kr_require(s.st_size == size);
		the_rrl = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		kr_require(the_rrl != MAP_FAILED);
		kr_require((the_rrl->capacity == capacity) && (the_rrl->instant_limit == instant_limit) &&
				(the_rrl->rate_limit == rate_limit));
		kr_log_info(SYSTEM, "Using existing RRL data.\n");

		return;
	}

	kr_require(false);  // we can get here for example if signal interrupt is received during fcntl
}

bool kr_rrl_request_begin(struct kr_request *req)
{
	if (!the_rrl) {
		kr_rrl_init("/tmp/kresd-kru", 524288, 20, 5);  // TODO call from elsewhere
	}
	if (!req->qsource.addr)
		return false;  // don't consider internal requests
	bool limited = false;
	if (the_rrl) {
		uint8_t key[16] ALIGNED(16) = {0, };
		uint8_t limited_prefix;
		if (req->qsource.addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)req->qsource.addr;
			memcpy(key, &ipv6->sin6_addr, 16);

			limited_prefix = KRU.limited_multi_prefix_or((struct kru *)the_rrl->kru, kr_now(),
					1, key, RRL_V6_PREFIXES, the_rrl->v6_prices, RRL_V6_PREFIXES_CNT);
		} else {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)req->qsource.addr;
			memcpy(key, &ipv4->sin_addr, 4);  // TODO append port?

			limited_prefix = KRU.limited_multi_prefix_or((struct kru *)the_rrl->kru, kr_now(),
					0, key, RRL_V4_PREFIXES, the_rrl->v4_prices, RRL_V4_PREFIXES_CNT);
		}
		limited = limited_prefix;
	}
	if (!limited) return limited;

	knot_pkt_t *answer = kr_request_ensure_answer(req);
	if (!answer) { // something bad; TODO: perhaps improve recovery from this
		kr_assert(false);
		return limited;
	}
	// at this point the packet should be pretty clear

	// Example limiting: REFUSED.
	knot_wire_set_rcode(answer->wire, KNOT_RCODE_REFUSED);
	kr_request_set_extended_error(req, KNOT_EDNS_EDE_OTHER, "YRAA: rate-limited");

	req->state = KR_STATE_DONE;

	return limited;
}
