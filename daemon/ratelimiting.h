#include <stdbool.h>
#include "lib/defines.h"
#include "lib/utils.h"
struct kr_request;

/** Initialize rate-limiting with shared mmapped memory.
 * The existing data are used if another instance is already using the file
 * and it was initialized with the same parameters; it fails on mismatch. */
KR_EXPORT
int ratelimiting_init(const char *mmap_file, size_t capacity, uint32_t instant_limit, uint32_t rate_limit, uint16_t slip);

/** Do rate-limiting, during knot_layer_api::begin. */
KR_EXPORT
bool ratelimiting_request_begin(struct kr_request *req);

/** Remove mmapped file data if not used by other processes. */
KR_EXPORT
void ratelimiting_deinit(void);
