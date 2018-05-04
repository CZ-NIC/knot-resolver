#include "categories.h"

#include <libknot/libknot.h>

static bool rrtype_is_infrastructure(uint16_t r)
{
	switch (r) {
	case KNOT_RRTYPE_NS:
	case KNOT_RRTYPE_DS:
	case KNOT_RRTYPE_DNSKEY:
	case KNOT_RRTYPE_A:
	case KNOT_RRTYPE_AAAA:
		return true;
	default:
		return false;
	}
}

// TODO this is just an example, make this more clever
category_t kr_gc_categorize(gc_record_info_t *info)
{
	category_t res = 60;

	switch (info->no_labels) {
	case 0:
		return 1;
	case 1:
		return 2;
	case 2:
		return (rrtype_is_infrastructure(info->rrtype) ? 3 : 20);
	}

	if (info->entry_size > 300) {
		return 90;
	}

	if (rrtype_is_infrastructure(info->rrtype)) {
		if (info->expires_in > 0) {
			res = 30;
		} else {
			res = 45;
		}
	}

	return res;
}

