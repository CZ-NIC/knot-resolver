/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

struct kr_cache_top;

KR_EXPORT
bool kr_cache_top_init(void);

KR_EXPORT
void kr_cache_top_deinit(void);

KR_EXPORT
void kr_cache_top_access_cdb(struct kr_cache_top *top, void *key, size_t len, char *debug_label); // temporal, TODO remove

KR_EXPORT
void kr_cache_top_access(struct kr_cache_top *top, void *key, size_t len, char *debug_label);

KR_EXPORT
uint16_t kr_cache_top_load(void *key, size_t len);
