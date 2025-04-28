/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

struct kr_cache_kru;

KR_EXPORT
bool kr_cache_kru_init(void);

KR_EXPORT
void kr_cache_kru_deinit(void);

KR_EXPORT
void kr_cache_kru_access_cdb(struct kr_cache_kru *kru, void *key, size_t len, char *debug_label); // temporal, TODO remove

KR_EXPORT
void kr_cache_kru_access(struct kr_cache_kru *kru, void *key, size_t len, char *debug_label);

KR_EXPORT
uint16_t kr_cache_kru_load(void *key, size_t len);
