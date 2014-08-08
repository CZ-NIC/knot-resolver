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
#include <libknot/mempattern.h>
#include <libknot/packet/pkt.h>

#warning TODO: this is private define
#include <common/lists.h>
#include <common/sockaddr.h>

/*! \brief Name server information. */
struct kr_ns {
	node_t node;
	knot_dname_t *name;
	struct sockaddr_storage addr;
	unsigned mean_rtt;
	unsigned closeness;
};

/*! \brief Name resolution result. */
struct kr_result {
	const knot_dname_t *cname;
	knot_pkt_t *ans;
	unsigned flags;
	struct timeval t_start, t_end;
	unsigned nr_queries;
};

/*! \brief Name resolution context. */
struct kr_context
{
	const knot_dname_t *sname;
	uint16_t stype;
	uint16_t sclass;
	uint16_t next_id;
	list_t slist;
	mm_ctx_t *pool;
	unsigned state;
	unsigned options;
};

int kr_context_init(struct kr_context *ctx, mm_ctx_t *mm);
int kr_context_reset(struct kr_context *ctx);
int kr_context_deinit(struct kr_context *ctx);

int kr_result_init(struct kr_context *ctx, struct kr_result *result);
int kr_result_deinit(struct kr_result *result);

int kr_slist_init(struct kr_context *ctx);
int kr_slist_add(struct kr_context *ctx, const knot_dname_t *name, const struct sockaddr *addr);
struct kr_ns *kr_slist_top(struct kr_context *ctx);
int kr_slist_sort(struct kr_context *ctx);
int kr_slist_pop(struct kr_context *ctx);