#include <libknot/descriptor.h>
#include <libknot/rrtype/aaaa.h>

#include "lib/utils.h"

int kr_rrset_to_addr(struct sockaddr_storage *ss, const knot_rrset_t *rr)
{
	/* Retrieve an address from glue record. */
	switch(rr->type) {
	case KNOT_RRTYPE_A:
		knot_a_addr(&rr->rrs, 0, (struct sockaddr_in *)ss);
		break;
	case KNOT_RRTYPE_AAAA:
		knot_aaaa_addr(&rr->rrs, 0, (struct sockaddr_in6 *)ss);
		break;
	default:
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}
