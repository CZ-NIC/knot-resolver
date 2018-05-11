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

static int get_random(int to)
{
	return rand() % to;
}

// TODO this is just an example, make this more clever
category_t kr_gc_categorize(gc_record_info_t *info)
{
	category_t res = 60;

	switch (info->no_labels) {
	case 0:
		res = 5;
		break;
	case 1:
		res = 10;
		break;
	case 2:
		res = (rrtype_is_infrastructure(info->rrtype) ? 15 : 20);
		break;
	}

	if (info->entry_size > 300) {
		res += 30;
	}

	if (rrtype_is_infrastructure(info->rrtype)) {
		if (info->expires_in > 0) {
			res = res > 40 ? 40 : res;
		}
	}

	return res + get_random(5);
}

