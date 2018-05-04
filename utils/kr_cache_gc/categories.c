#include "categories.h"

#include <libknot/libknot.h>

// TODO this is just an example, make this more clever
category_t kr_gc_categorize(gc_record_info_t *info)
{
	category_t res = 60;

	switch (info->rrtype) {
	case KNOT_RRTYPE_NS:
	case KNOT_RRTYPE_DS:
	case KNOT_RRTYPE_DNSKEY:
	case KNOT_RRTYPE_A:
	case KNOT_RRTYPE_AAAA:
		if (info->expires_in > 0) {
			res = 30;
		} else {
			res = 45;
		}
		break;
	}

	return res;
}

