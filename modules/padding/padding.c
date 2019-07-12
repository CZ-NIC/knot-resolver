/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file padding.c
 * @brief TODO
 */

#include <libknot/packet/pkt.h>
#include <libknot/packet/wire.h>
#include <libknot/descriptor.h>
#include <ccan/json/json.h>
#include <contrib/cleanup.h>
#include <arpa/inet.h>
#include <lua.h>

#include "lib/layer/iterate.h"
#include "lib/rplan.h"
#include "lib/module.h"
#include "lib/layer.h"
#include "lib/resolve.h"

/** @internal Compatibility wrapper for Lua < 5.2 */
#if LUA_VERSION_NUM < 502
#define lua_rawlen(L, obj) lua_objlen((L), (obj))
#endif

static int set_for_tls(kr_layer_t *ctx)
{
	struct kr_request *req = ctx->req;
	if (req->qsource.flags.tls) {
            req->options.PADDING_REQUIRED = true;
        }
	return ctx->state;
}

static int add_padding(kr_layer_t *ctx) {
        struct kr_request *request = ctx->req;
        
        if (!request || !request->answer || !request->ctx) {
                assert(false);
                return kr_error(EINVAL);
        }
        if (!request->options.PADDING_REQUIRED) return kr_ok();

        int32_t padding = request->ctx->tls_padding;
        knot_pkt_t *answer = request->answer;
        knot_rrset_t *opt_rr = answer->opt_rr;
        int32_t pad_bytes = -1;

        if (padding == -1) { /* use the default padding policy from libknot */
                pad_bytes =  knot_pkt_default_padding_size(answer, opt_rr);
        }
        if (padding >= 2) {
                int32_t max_pad_bytes = knot_edns_get_payload(opt_rr) - (answer->size + knot_rrset_size(opt_rr));
                pad_bytes = MIN(knot_edns_alignment_size(answer->size, knot_rrset_size(opt_rr), padding),
                                max_pad_bytes);
        }

        if (pad_bytes >= 0) {
                uint8_t zeros[MAX(1, pad_bytes)];
                memset(zeros, 0, sizeof(zeros));
                int r = knot_edns_add_option(opt_rr, KNOT_EDNS_OPTION_PADDING,
                                             pad_bytes, zeros, &answer->mm);
                if (r != KNOT_EOK) {
                        knot_rrset_clear(opt_rr, &answer->mm);
                        return kr_error(r);
                }
        }
        return kr_ok();
}

KR_EXPORT
int padding_init(struct kr_module *module)
{
	static kr_layer_api_t layer = {
		.begin = &set_for_tls,
                .answer_finalize = &add_padding,
                //.finish = &add_padding,
	};
	/* Store module reference */
	layer.data = module;
	module->layer = &layer;

	static const struct kr_prop props[] = {
	    { NULL, NULL, NULL }
	};
	module->props = props;
	return kr_ok();
}

KR_EXPORT
int padding_deinit(struct kr_module *module)
{
	return kr_ok();
}

KR_MODULE_EXPORT(padding)

#undef VERBOSE_MSG
