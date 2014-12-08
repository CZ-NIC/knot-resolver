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
#include <libknot/internal/lists.h>
#include <libknot/internal/sockaddr.h>
#include <libknot/internal/trie/hat-trie.h>

struct kr_context;

/*! \brief Name server. */
struct kr_ns {
	node_t node;
	knot_dname_t *name;
	struct {
		double M, S; /* Mean, Variance S/n */
		unsigned n;
	} stat;
};

struct kr_zonecut {
	list_t nslist;
	knot_dname_t *name;
};

struct kr_zonecut_map {
	mm_ctx_t *pool;
	hattrie_t *trie;
};

int kr_zonecut_init(struct kr_zonecut_map *map, mm_ctx_t *mm);
void kr_zonecut_deinit(struct kr_zonecut_map *map);
struct kr_zonecut *kr_zonecut_get(struct kr_zonecut_map *map, const knot_dname_t *name);
struct kr_zonecut *kr_zonecut_find(struct kr_zonecut_map *map, const knot_dname_t *name);

/* TODO: find out how to do expire/refresh efficiently, maybe a sweep point and
 *       evaluate only DPs with validity before or around the sweep point, then
 *       choose next and move DPs from the other half for next sweep.
 */

struct kr_ns *kr_ns_first(list_t *list);
struct kr_ns *kr_ns_get(list_t *list, const knot_dname_t *name, mm_ctx_t *mm);
struct kr_ns *kr_ns_find(list_t *list, const knot_dname_t *name);
void kr_ns_del(list_t *list, struct kr_ns *ns, mm_ctx_t *mm);
