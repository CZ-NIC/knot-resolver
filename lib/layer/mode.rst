.. SPDX-License-Identifier: GPL-3.0-or-later

.. function:: mode(['strict' | 'normal' | 'permissive'])

   :param: New checking level specified as string (*optional*).
   :return: Current checking level.

   Get or change resolver strictness checking level.

   By default, resolver runs in *normal* mode. There are possibly many small adjustments
   hidden behind the mode settings, but the main idea is that in *permissive* mode, the resolver
   tries to resolve a name with as few lookups as possible, while in *strict* mode it spends much
   more effort resolving and checking referral path. However, if majority of the traffic is covered
   by DNSSEC, some of the strict checking actions are counter-productive.

   .. csv-table::
    :header: "Glue type", "Modes when it is accepted",   "Example glue [#example_glue]_"

    "mandatory glue",     "strict, normal, permissive",  "ns1.example.org"
    "in-bailiwick glue",  "normal, permissive",          "ns1.example2.org"
    "any glue records",   "permissive",                  "ns1.example3.net"

   .. [#example_glue] The examples show glue records acceptable from servers
        authoritative for `org` zone when delegating to `example.org` zone.
        Unacceptable or missing glue records trigger resolution of names listed
        in NS records before following respective delegation.
