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

#include <libknot/dname.h>
#include <common/lists.h>

enum {
	RESOLVE_QUERY = 0 << 0,
	RESOLVE_DELEG = 1 << 0,
};

struct kr_query {
	node_t node;
	knot_dname_t *sname;
	uint16_t stype;
	uint16_t sclass;
	uint16_t flags;
	void *ext;
};

struct kr_rplan {
	list_t q;
	mm_ctx_t *pool;
};

void kr_rplan_init(struct kr_rplan *rplan, mm_ctx_t *pool);
void kr_rplan_clear(struct kr_rplan *rplan);

struct kr_query *kr_rplan_push(struct kr_rplan *rplan, const knot_dname_t *name, uint16_t cls,
                               uint16_t type);
int kr_rplan_pop(struct kr_rplan *rplan, struct kr_query *qry);
struct kr_query *kr_rplan_next(struct kr_rplan *rplan);

