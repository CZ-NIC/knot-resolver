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

#include <stdint.h>

#include <libknot/internal/mempattern.h>
#include <libknot/internal/sockaddr.h>

#include "lib/delegpt.h"
#include "lib/rplan.h"
#include "lib/cache.h"

/*! \brief Name resolution result. */
struct kr_result {
	knot_pkt_t *ans;
	unsigned flags;
	struct timeval t_start, t_end;
	unsigned total_rtt;
	unsigned nr_queries;
};

/*! \brief Name resolution context. */
struct kr_context
{
	struct kr_ns *current_ns;
	struct kr_query *resolved_qry;
	const knot_pkt_t *query;
	struct kr_rplan rplan;
	struct kr_delegmap dp_map;
	struct kr_cache *cache;
	struct {
		struct kr_txn *read;
		struct kr_txn *write;
	} txn;
	mm_ctx_t *pool;
	unsigned state;
	unsigned options;
};

int kr_context_init(struct kr_context *ctx, mm_ctx_t *mm);
int kr_context_reset(struct kr_context *ctx);
int kr_context_deinit(struct kr_context *ctx);
struct kr_txn *kr_context_txn_acquire(struct kr_context *ctx, unsigned flags);
void kr_context_txn_release(struct kr_txn *txn);
int kr_context_txn_commit(struct kr_context *ctx);

int kr_result_init(struct kr_context *ctx, struct kr_result *result);
int kr_result_deinit(struct kr_result *result);
