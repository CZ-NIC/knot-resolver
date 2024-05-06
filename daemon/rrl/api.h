
#include <stdbool.h>
#include <lib/defines.h>
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
