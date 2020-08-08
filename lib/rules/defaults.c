/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/rules/impl.h"
#include "lib/rules/api.h"

int rules_defaults_insert(void)
{
	static const char * names[] = {
		/* RFC1918 Private, local, broadcast, test and special zones
		   Considerations: RFC6761, sec 6.1.
		   https://www.iana.org/assignments/locally-served-dns-zones
		 */
		/* RFC6303 */
		"10.in-addr.arpa.",
		"16.172.in-addr.arpa.",
		"17.172.in-addr.arpa.",
		"18.172.in-addr.arpa.",
		"19.172.in-addr.arpa.",
		"20.172.in-addr.arpa.",
		"21.172.in-addr.arpa.",
		"22.172.in-addr.arpa.",
		"23.172.in-addr.arpa.",
		"24.172.in-addr.arpa.",
		"25.172.in-addr.arpa.",
		"26.172.in-addr.arpa.",
		"27.172.in-addr.arpa.",
		"28.172.in-addr.arpa.",
		"29.172.in-addr.arpa.",
		"30.172.in-addr.arpa.",
		"31.172.in-addr.arpa.",
		"168.192.in-addr.arpa.",
		"0.in-addr.arpa.",
		// localhost_reversed handles 127.in-addr.arpa.
		"254.169.in-addr.arpa.",
		"2.0.192.in-addr.arpa.",
		"100.51.198.in-addr.arpa.",
		"113.0.203.in-addr.arpa.",
		"255.255.255.255.in-addr.arpa.",
		/* RFC7793 */
		"64.100.in-addr.arpa.",
		"65.100.in-addr.arpa.",
		"66.100.in-addr.arpa.",
		"67.100.in-addr.arpa.",
		"68.100.in-addr.arpa.",
		"69.100.in-addr.arpa.",
		"70.100.in-addr.arpa.",
		"71.100.in-addr.arpa.",
		"72.100.in-addr.arpa.",
		"73.100.in-addr.arpa.",
		"74.100.in-addr.arpa.",
		"75.100.in-addr.arpa.",
		"76.100.in-addr.arpa.",
		"77.100.in-addr.arpa.",
		"78.100.in-addr.arpa.",
		"79.100.in-addr.arpa.",
		"80.100.in-addr.arpa.",
		"81.100.in-addr.arpa.",
		"82.100.in-addr.arpa.",
		"83.100.in-addr.arpa.",
		"84.100.in-addr.arpa.",
		"85.100.in-addr.arpa.",
		"86.100.in-addr.arpa.",
		"87.100.in-addr.arpa.",
		"88.100.in-addr.arpa.",
		"89.100.in-addr.arpa.",
		"90.100.in-addr.arpa.",
		"91.100.in-addr.arpa.",
		"92.100.in-addr.arpa.",
		"93.100.in-addr.arpa.",
		"94.100.in-addr.arpa.",
		"95.100.in-addr.arpa.",
		"96.100.in-addr.arpa.",
		"97.100.in-addr.arpa.",
		"98.100.in-addr.arpa.",
		"99.100.in-addr.arpa.",
		"100.100.in-addr.arpa.",
		"101.100.in-addr.arpa.",
		"102.100.in-addr.arpa.",
		"103.100.in-addr.arpa.",
		"104.100.in-addr.arpa.",
		"105.100.in-addr.arpa.",
		"106.100.in-addr.arpa.",
		"107.100.in-addr.arpa.",
		"108.100.in-addr.arpa.",
		"109.100.in-addr.arpa.",
		"110.100.in-addr.arpa.",
		"111.100.in-addr.arpa.",
		"112.100.in-addr.arpa.",
		"113.100.in-addr.arpa.",
		"114.100.in-addr.arpa.",
		"115.100.in-addr.arpa.",
		"116.100.in-addr.arpa.",
		"117.100.in-addr.arpa.",
		"118.100.in-addr.arpa.",
		"119.100.in-addr.arpa.",
		"120.100.in-addr.arpa.",
		"121.100.in-addr.arpa.",
		"122.100.in-addr.arpa.",
		"123.100.in-addr.arpa.",
		"124.100.in-addr.arpa.",
		"125.100.in-addr.arpa.",
		"126.100.in-addr.arpa.",
		"127.100.in-addr.arpa.",
		/* RFC6303 */
		"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
			/* ^ below we inject exact-match PTR over this empty zone */
		"d.f.ip6.arpa.",
		"8.e.f.ip6.arpa.",
		"9.e.f.ip6.arpa.",
		"a.e.f.ip6.arpa.",
		"b.e.f.ip6.arpa.",
		"8.b.d.0.1.0.0.2.ip6.arpa.",
		/* RFC8375 */
		"home.arpa.",

		/* More zones - empty-zone subset from:
		   https://www.iana.org/assignments/special-use-domain-names
		   TODO: perhaps review the list again.
		 */
		"test.",
		"onion.",
		"invalid.",
		"local.", // RFC 8375.4
	};

	const int names_count = sizeof(names) / sizeof(names[0]);
	for (int i = 0; i < names_count; ++i) {
		knot_dname_t name_buf[KNOT_DNAME_MAXLEN];
		const knot_dname_t *dname =
			knot_dname_from_str(name_buf, names[i], sizeof(name_buf));
		int ret = kr_rule_local_data_emptyzone(dname, KR_RULE_TAGS_ALL);
		if (ret) {
			assert(!ret);
			return kr_error(ret);
		}
		/* The double conversion is perhaps a bit wasteful, but it should be rare. */
		/* LATER: add extra info with explanation?  policy module had an ADDITIONAL
		 * record with explanation, but perhaps extended errors are more suitable?
		 * Differentiating the message - perhaps splitting VAL_ZLAT_EMPTY into a few?
		 */
	}

	{
		knot_dname_t name_buf[KNOT_DNAME_MAXLEN];
		knot_rrset_t rr = {
			.owner = knot_dname_from_str(name_buf,
				"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
				sizeof(name_buf)),
			.ttl = RULE_TTL_DEFAULT,
			.type = KNOT_RRTYPE_PTR,
			.rclass = KNOT_CLASS_IN,
			.rrs = { 0 },
			.additional = NULL,
		};
		int ret = knot_rrset_add_rdata(&rr, (const knot_dname_t *)"\x09localhost\0",
						1+9+1, NULL);
		if (!ret) ret = kr_rule_local_data_ins(&rr, NULL, KR_RULE_TAGS_ALL);
		knot_rdataset_clear(&rr.rrs, NULL);
		if (ret) {
			assert(!ret);
			return kr_error(ret);
		}
	}

	return kr_ok();
}

