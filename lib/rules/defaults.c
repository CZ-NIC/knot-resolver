/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/rules/impl.h"
#include "lib/rules/api.h"
#include "lib/utils.h"

#define CHECK_RET(ret) do { \
	if ((ret) < 0) { kr_assert(false); return kr_error((ret)); } \
} while (false)

/** RFC-defined local zones should be quite static,
 * so we use a higher TTL separate from KR_RULE_TTL_DEFAULT. */
#define TTL ((uint32_t)3600)

int rules_defaults_insert(void)
{
	static const struct { enum kr_rule_sub_t rule; const char *name; } names[] = {

	//// https://www.iana.org/assignments/locally-served-dns-zones

		// RFC 6303: sec. 3 explicitly says that they should be empty zones.
		{ KR_RULE_SUB_EMPTY   , "10.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "16.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "17.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "18.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "19.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "20.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "21.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "22.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "23.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "24.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "25.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "26.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "27.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "28.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "29.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "30.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "31.172.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "168.192.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "0.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "127.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "254.169.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "2.0.192.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "100.51.198.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "113.0.203.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "255.255.255.255.in-addr.arpa."},
		// RFC 7793: not explicitly said what to do, but same registry as above
		{ KR_RULE_SUB_EMPTY   , "64.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "65.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "66.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "67.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "68.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "69.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "70.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "71.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "72.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "73.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "74.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "75.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "76.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "77.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "78.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "79.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "80.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "81.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "82.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "83.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "84.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "85.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "86.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "87.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "88.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "89.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "90.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "91.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "92.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "93.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "94.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "95.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "96.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "97.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "98.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "99.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "100.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "101.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "102.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "103.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "104.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "105.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "106.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "107.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "108.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "109.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "110.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "111.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "112.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "113.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "114.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "115.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "116.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "117.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "118.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "119.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "120.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "121.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "122.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "123.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "124.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "125.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "126.100.in-addr.arpa."},
		{ KR_RULE_SUB_EMPTY   , "127.100.in-addr.arpa."},
		// RFC 6303: see 6303 above
		{ KR_RULE_SUB_EMPTY,
			"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."},
		{ KR_RULE_SUB_EMPTY,
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."},
			// ^ below we inject exact-match PTR into this empty zone
		{ KR_RULE_SUB_EMPTY   , "d.f.ip6.arpa."},
		{ KR_RULE_SUB_EMPTY   , "8.e.f.ip6.arpa."},
		{ KR_RULE_SUB_EMPTY   , "9.e.f.ip6.arpa."},
		{ KR_RULE_SUB_EMPTY   , "a.e.f.ip6.arpa."},
		{ KR_RULE_SUB_EMPTY   , "b.e.f.ip6.arpa."},
		{ KR_RULE_SUB_EMPTY   , "8.b.d.0.1.0.0.2.ip6.arpa."},
 		// RFC 8375: sec.4.4 - says same as 6303
		{ KR_RULE_SUB_EMPTY   , "home.arpa."},
 		// RFC 9462: para. just above sec. 4.1 and sec. 6.4;
		//    needs NODATA (at least) on resolver.arpa and _dns.resolver.arpa
		{ KR_RULE_SUB_EMPTY   , "resolver.arpa."},
		{ KR_RULE_SUB_NODATA  , "resolver.arpa."},
		// RFC 9665: sec. 8.4 refers to 6303 for service, sec. 3.1.2 to 6761 for default.service
		{ KR_RULE_SUB_EMPTY   , "service.arpa."},
		{ KR_RULE_SUB_NXDOMAIN, "default.service.arpa."},

	//// https://www.iana.org/assignments/special-use-domain-names

		// RFC 9476: no action  "alt."
		// RFC 9031: sec. 11 refers to 6761
		{ KR_RULE_SUB_NXDOMAIN, "6tisch.arpa."},
		// RFC 9140: sec. 5.6 but doesn't specify; probably 6761
		{ KR_RULE_SUB_NXDOMAIN, "eap-noob.arpa."},
		// RFC 8375: see above  "home.arpa."

		// Now the registry has RFC 6761 repeats of many names from above,
		//  but some new names are mixed in:
		// RFC 8880: sec. 7.2.4: noop for 170.0.0.192.in-addr.arpa. + 171.0.0.192.in-addr.arpa.
		// RFC 8880: sec. 7.1.4: noop for ipv4only.arpa.  but FIXME: DNS64 module

		// RFC 9462: sec. 8.2.4 just says to prevent forwarding
		{ KR_RULE_SUB_EMPTY   , "resolver.arpa."},
		// RFC 9665: "service.arpa." got handled above (it's in both IANA lists)
		// RFC 6761: sec. 6.4.4 says "NXDOMAIN responses"
		{ KR_RULE_SUB_NXDOMAIN, "invalid."},
 		// RFC 6762: sec. 22.1.4
		{ KR_RULE_SUB_NXDOMAIN, "local."},
		// "localhost." is below
		// RFC 7686: sec. 2.4 says "NXDOMAIN"
		{ KR_RULE_SUB_NXDOMAIN, "onion."},
		// RFC 6761: sec. 6.2.4 says "negative responses"
		{ KR_RULE_SUB_NXDOMAIN, "test."},
	};

	const int names_count = sizeof(names) / sizeof(names[0]);
	for (int i = 0; i < names_count; ++i) {
		knot_dname_t name_buf[KNOT_DNAME_MAXLEN];
		const knot_dname_t *dname =
			knot_dname_from_str(name_buf, names[i].name, sizeof(name_buf));
		int ret = kr_rule_local_subtree(dname, names[i].rule,
						TTL, KR_RULE_TAGS_ALL, KR_RULE_OPTS_DEFAULT);
		CHECK_RET(ret);
		/* The double conversion is perhaps a bit wasteful, but it should be rare. */
		/* LATER: add extra info with explanation?  policy module had an ADDITIONAL
		 * record with explanation, but perhaps extended errors are more suitable?
		 * Differentiating the message - perhaps splitting KR_RULE_SUB_EMPTY into a few?
		 */
	}

	knot_dname_t localhost_dname[] = "\x09localhost\0";
	{ // forward localhost
		int ret = kr_rule_local_subtree(localhost_dname, KR_RULE_SUB_REDIRECT,
						TTL, KR_RULE_TAGS_ALL, KR_RULE_OPTS_DEFAULT);
		CHECK_RET(ret);

		knot_rrset_t rr = {
			.owner = localhost_dname,
			.ttl = TTL,
			.rclass = KNOT_CLASS_IN,
			.rrs = { 0 },
			.additional = NULL,
		};
		rr.type = KNOT_RRTYPE_A;
		ret = knot_rrset_add_rdata(&rr, (const uint8_t *)"\x7f\0\0\1", 4, NULL);
		if (!ret) ret = kr_rule_local_data_ins(&rr, NULL,
					KR_RULE_TAGS_ALL, KR_RULE_OPTS_DEFAULT);
		knot_rdataset_clear(&rr.rrs, NULL);
		CHECK_RET(ret);

		rr.type = KNOT_RRTYPE_AAAA;
		ret = knot_rrset_add_rdata(&rr,
				(const uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1",
				16, NULL);
		if (!ret) ret = kr_rule_local_data_ins(&rr, NULL,
					KR_RULE_TAGS_ALL, KR_RULE_OPTS_DEFAULT);
		knot_rdataset_clear(&rr.rrs, NULL);
		CHECK_RET(ret);

		rr.type = KNOT_RRTYPE_NS;
		ret = knot_rrset_add_rdata(&rr, localhost_dname, 1+9+1, NULL);
		if (!ret) ret = kr_rule_local_data_ins(&rr, NULL,
					KR_RULE_TAGS_ALL, KR_RULE_OPTS_DEFAULT);
		knot_rdataset_clear(&rr.rrs, NULL);
		CHECK_RET(ret);
	}

	{ // reverse localhost; LATER: the situation isn't ideal with NXDOMAIN + some exact matches
		knot_rrset_t rr = {
			.owner = localhost_dname,
			.ttl = TTL,
			.type = KNOT_RRTYPE_PTR,
			.rclass = KNOT_CLASS_IN,
			.rrs = { 0 },
			.additional = NULL,
		};
		int ret = knot_rrset_add_rdata(&rr, localhost_dname, 1+9+1, NULL);
		if (!ret) ret = kr_rule_local_data_ins(&rr, NULL,
					KR_RULE_TAGS_ALL, KR_RULE_OPTS_DEFAULT);

		knot_dname_t name_buf[KNOT_DNAME_MAXLEN];
		rr.owner = knot_dname_from_str(name_buf,
				"1.0.0.127.in-addr.arpa.",
				sizeof(name_buf));
		if (!ret) ret = kr_rule_local_data_ins(&rr, NULL,
					KR_RULE_TAGS_ALL, KR_RULE_OPTS_DEFAULT);

		rr.owner = knot_dname_from_str(name_buf,
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
			sizeof(name_buf));
		if (!ret) ret = kr_rule_local_data_ins(&rr, NULL,
					KR_RULE_TAGS_ALL, KR_RULE_OPTS_DEFAULT);

		knot_rdataset_clear(&rr.rrs, NULL);
		CHECK_RET(ret);
	}

	return kr_ok();
}

