/* Copyright 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

#include <libknot/rrset.h>

enum kr_cache_flag {
	KR_CACHE_NOFLAG = 0,
	KR_CACHE_RDONLY = 1 << 0
};

struct kr_cache;
struct kr_txn;

struct kr_cache *kr_cache_open(const char *handle, unsigned flags, mm_ctx_t *mm);
void kr_cache_close(struct kr_cache *cache);

struct kr_txn *kr_cache_txn_begin(struct kr_cache *cache, struct kr_txn *parent, unsigned flags, mm_ctx_t *mm);
int kr_cache_txn_commit(struct kr_txn *txn);
void kr_cache_txn_abort(struct kr_txn *txn);

int kr_cache_query(struct kr_txn *txn, knot_rrset_t *rr);
int kr_cache_insert(struct kr_txn *txn, const knot_rrset_t *rr, unsigned flags);
int kr_cache_remove(struct kr_txn *txn, const knot_rrset_t *rr);
