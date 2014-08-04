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

/*! \brief Name resolution result. */
struct kresolve_result {
	/* Nameserver. */
	struct {
		const knot_dname_t *name;
		struct sockaddr_storage addr;
	} ns;
	/* Query */
	const knot_dname_t *qname;
	uint16_t qtype;
	uint16_t qclass;
	/* Result */
	const knot_dname_t *cname;
	uint16_t rcode;
	knot_rrset_t *data[32];
	unsigned count;
	unsigned flags;
};

/*! \brief Name resolution context. */
struct kresolve_ctx {
	mm_ctx_t *mm;
	unsigned state;
	unsigned options;
};

int kresolve_ctx_init(struct kresolve_ctx *ctx, mm_ctx_t *mm);
int kresolve_ctx_close(struct kresolve_ctx *ctx);
