
#include <stdbool.h>
#include <lib/defines.h>
struct kr_request;

/** Do rate-limiting, during knot_layer_api::begin. */
KR_EXPORT
bool kr_rrl_request_begin(struct kr_request *req);
