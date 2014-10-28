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

#include <uv.h>

#include <common/mempattern.h>
#include "lib/resolve.h"

struct worker_ctx {
	struct kr_context resolve;
	mm_ctx_t *pool;
};

void worker_init(struct worker_ctx *worker, mm_ctx_t *mm);
void worker_deinit(struct worker_ctx *worker);
void worker_start(uv_udp_t *req, struct worker_ctx *worker);
void worker_stop(uv_udp_t *req);
