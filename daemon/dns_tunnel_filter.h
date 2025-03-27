/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

 #include <stdbool.h>
 #include "lib/defines.h"
 #include "lib/utils.h"
 #include "lib/kru.h"
 struct kr_request;
 
 /** Initialize rate-limiting with shared mmapped memory.
  * The existing data are used if another instance is already using the file
  * and it was initialized with the same parameters; it fails on mismatch. */
 KR_EXPORT
 int dns_tunnel_filter_init(const char *mmap_file, size_t capacity, uint32_t instant_limit,
		uint32_t rate_limit, uint16_t slip, uint32_t log_period, bool dry_run);
 
 /** Do rate-limiting, during knot_layer_api::begin. */
 KR_EXPORT
 bool dns_tunnel_filter_request_begin(struct kr_request *req);
 
 /** Remove mmapped file data if not used by other processes. */
 KR_EXPORT
 void dns_tunnel_filter_deinit(void);
 