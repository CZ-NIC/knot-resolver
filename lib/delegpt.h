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

#include <libknot/packet/pkt.h>

#warning TODO: this is private define
#include <common/lists.h>
#include <common/sockaddr.h>
#include <common/trie/hat-trie.h>

/*! \brief Name server flag. */
enum kr_ns_flag {
	DP_LAME = 0,
	DP_RESOLVED
};

struct kr_context;

/*! \brief Name server. */
struct kr_ns {
	node_t node;
	knot_dname_t *name;
	struct sockaddr_storage addr;
	unsigned valid_until;
	unsigned mean_rtt;
	unsigned flags;
};

struct kr_delegmap {
	mm_ctx_t *pool;
	hattrie_t *trie;
};

int kr_delegmap_init(struct kr_delegmap *map, mm_ctx_t *mm);
void kr_delegmap_deinit(struct kr_delegmap *map);
list_t *kr_delegmap_get(struct kr_delegmap *map, const knot_dname_t *name);
list_t *kr_delegmap_find(struct kr_delegmap *map, const knot_dname_t *name);

/* TODO: find out how to do expire/refresh efficiently, maybe a sweep point and
 *       evaluate only DPs with validity before or around the sweep point, then
 *       choose next and move DPs from the other half for next sweep.
 */

struct kr_ns *kr_ns_create(const knot_dname_t *name, mm_ctx_t *mm);
void kr_ns_append(list_t *list, struct kr_ns *ns);
void kr_ns_remove(struct kr_ns *ns, mm_ctx_t *mm);
int kr_ns_resolve(struct kr_ns *ns);
