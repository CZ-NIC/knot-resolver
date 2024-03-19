#include "daemon/rrl/api.h"
#include "daemon/rrl/kru.h"
#include "lib/resolve.h"

struct kru *the_rrl_kru = NULL;

// FIXME: add C API that takes configuration parameters and initializes the KRU;
// it will then get called from the generated Lua config file.

bool kr_rrl_request_begin(struct kr_request *req)
{
	if (!req->qsource.addr)
		return false;  // don't consider internal requests
	const bool limited = true;
	if (!limited && the_rrl_kru) {
		// FIXME: process limiting via KRU.limited*
	}
	if (!limited) return limited;

	knot_pkt_t *answer = kr_request_ensure_answer(req);
	if (!answer) { // something bad; TODO: perhaps improve recovery from this
		kr_assert(false);
		return limited;
	}
	// at this point the packet should be pretty clear

	// Example limiting: REFUSED.
	knot_wire_set_rcode(answer->wire, KNOT_RCODE_REFUSED);
	kr_request_set_extended_error(req, KNOT_EDNS_EDE_OTHER, "YRAA: rate-limited");

	req->state = KR_STATE_DONE;

	return limited;
}
