#include <libknot/descriptor.h>
#include <libknot/rrtype/aaaa.h>
#include <assert.h>

#include "lib/utils.h"

int kr_rrset_to_addr(struct sockaddr_storage *ss, const knot_rrset_t *rr)
{
	int ret = KNOT_EOK;

	/* Retrieve an address from glue record. */
	switch(rr->type) {
	case KNOT_RRTYPE_A:
		ret = knot_a_addr(&rr->rrs, 0, (struct sockaddr_in *)ss);
		break;
	case KNOT_RRTYPE_AAAA:
		ret = knot_aaaa_addr(&rr->rrs, 0, (struct sockaddr_in6 *)ss);
		break;
	default:
		return KNOT_EINVAL;
	}

	sockaddr_port_set(ss, KR_DNS_PORT);

	return ret;
}
