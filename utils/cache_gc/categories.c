/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "categories.h"

#include <libknot/libknot.h>
#include "lib/utils.h"

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
	// We don't need these to be really unpredictable,
	// but this should be cheap enough not to be noticeable.
	return kr_rand_bytes(1) % to;
}

// TODO this is just an example, make this more clever
category_t kr_gc_categorize(gc_record_info_t * info)
{
	category_t res;

	if (!info->valid)
		return CATEGORIES - 1;

	switch (info->no_labels) {
	case 0:		/* root zone */
		res = 5;
		break;
	case 1:		/* TLD */
		res = 10;
		break;
	default:		/* SLD and below */
		res = (rrtype_is_infrastructure(info->rrtype) ? 15 : 20);
		if (info->entry_size > 300)
			/* Penalty for big answers */
			res += 30;
		break;
	}

	if (info->expires_in <= 0) {
		res += 40;
	}

	return res + get_random(5);
}
