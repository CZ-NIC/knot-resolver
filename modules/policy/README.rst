.. _mod-policy:

Query policies
--------------

This module can block, rewrite, or alter inbound queries based on user-defined policies.

Each policy *rule* has two parts: a *filter* and an *action*. A *filter* selects which queries will be affected by the policy, and *action* which modifies queries matching the associated filter. Typically a rule is defined as follows: ``filter(action(action parameters), filter parameters)``. For example, a filter can be ``suffix`` which matches queries whose suffix part is in specified set, and one of possible actions is ``DENY``, which denies resolution. These are combined together into ``policy.suffix(policy.DENY, {todname('badguy.example.')})``. The rule is effective when it is added into rule table using ``policy.add()``, please see `Policy examples`_.

By default, if no rule applies to a query, built-in rules for `special-use <https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml>`_ and `locally-served <http://www.iana.org/assignments/locally-served-dns-zone>`_ domain names are applied. These built-in rules can be overriden using action ``PASS``, see `Policy examples`_ below.


Filters
^^^^^^^
A *filter* selects which queries will be affected by specified *action*. There are several policy filters available in the ``policy.`` table:

* ``all(action)``
  - always applies the action
* ``pattern(action, pattern)``
  - applies the action if QNAME matches a `regular expression <http://lua-users.org/wiki/PatternsTutorial>`_
* ``suffix(action, table)``
  - applies the action if QNAME suffix matches one of suffixes in the table (useful for "is domain in zone" rules),
  uses `Aho-Corasick`_ string matching algorithm `from CloudFlare <https://github.com/cloudflare/lua-aho-corasick>`_ (BSD 3-clause)
* :any:`policy.suffix_common`
* ``rpz``
  - implements a subset of RPZ_ in zonefile format.  See below for details: :any:`policy.rpz`.
* custom filter function

Actions
^^^^^^^
An *action* is function which modifies DNS query. There are several actions available in the ``policy.`` table:

* ``PASS`` - let the query pass through; it's useful to make exceptions before wider rules
* ``DENY`` - reply NXDOMAIN authoritatively
* ``DENY_MSG(msg)`` - reply NXDOMAIN authoritatively and add explanatory message to additional section
* ``DROP`` - terminate query resolution and return SERVFAIL to the requestor
* ``TC`` - set TC=1 if the request came through UDP, forcing client to retry with TCP
* ``FORWARD(ip)`` - resolve a query via forwarding to an IP while validating and caching locally;
* ``TLS_FORWARD({{ip, authentication}})`` - resolve a query via TLS connection forwarding to an IP while validating and caching locally;
  the parameter can be a single IP (string) or a lua list of up to four IPs.
* ``STUB(ip)`` - similar to ``FORWARD(ip)`` but *without* attempting DNSSEC validation.
  Each request may be either answered from cache or simply sent to one of the IPs with proxying back the answer.
* ``MIRROR(ip)`` - mirror query to given IP and continue solving it (useful for partial snooping); it's a chain action
* ``REROUTE({{subnet,target}, ...})`` - reroute addresses in response matching given subnet to given target, e.g. ``{'192.0.2.0/24', '127.0.0.0'}`` will rewrite '192.0.2.55' to '127.0.0.55', see :ref:`renumber module <mod-renumber>` for more information.
* ``QTRACE`` - pretty-print DNS response packets into the log for the query and its sub-queries.  It's useful for debugging weird DNS servers.  It's a chain action.
* ``FLAGS(set, clear)`` - set and/or clear some flags for the query.  There can be multiple flags to set/clear.  You can just pass a single flag name (string) or a set of names.  It's a chain action.

Most actions stop the policy matching on the query, but "chain actions" allow to keep trying to match other rules, until a non-chain action is triggered.

Also, it is possible to write your own action (i.e. Lua function). It is possible to implement complex heuristics, e.g. to deflect `Slow drip DNS attacks <https://secure64.com/water-torture-slow-drip-dns-ddos-attack>`_ or gray-list resolution of misbehaving zones.

.. warning:: The policy module currently only looks at whole DNS requests.  The rules won't be re-applied e.g. when following CNAMEs.

.. note:: The module (and ``kres``) expects domain names in wire format, not textual representation. So each label in name is prefixed with its length, e.g. "example.com" equals to ``"\7example\3com"``. You can use convenience function ``todname('example.com')`` for automatic conversion.

Forwarding over TLS protocol (DNS-over-TLS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Policy `TLS_FORWARD` allows you to forward queries using `Transport Layer Security`_ protocol, which hides the content of your queries from an attacker observing the network traffic. Further details about this protocol can be found in :rfc:`7858` and `IETF draft dprive-dtls-and-tls-profiles`_.

Queries affected by `TLS_FORWARD` policy will always be resolved over TLS connection. Knot Resolver does not implement fallback to non-TLS connection, so if TLS connection cannot be established or authenticated according to the configuration, the resolution will fail.

To test this feature you need to either :ref:`configure Knot Resolver as DNS-over-TLS server <tls-server-config>`, or pick some public DNS-over-TLS server. Please see `DNS Privacy Project`_ homepage for list of public servers.

When multiple servers are specified, the one with the lowest round-trip time is used.

CA+hostname authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~
Traditional PKI authentication requires server to present certificate with specified hostname, which is issued by one of trusted CAs. Example policy is:

.. code-block:: lua

        policy.TLS_FORWARD({
                {'2001:DB8::d0c', hostname='res.example.com', ca_file='/etc/knot-resolver/tlsca.crt'}})

- `hostname` must exactly match hostname in server's certificate, i.e. in most cases it must not contain trailing dot (`res.example.com`).
- `ca_file` must be path to CA certificate (or certificate bundle) in `PEM format`_.

TLS Examples
~~~~~~~~~~~~

.. code-block:: lua

	modules = { 'policy' }
	-- forward all queries over TLS to the specified server
	policy.add(policy.all(policy.TLS_FORWARD({{'192.0.2.1', pin_sha256='YQ=='}})))
	-- for brevity, other TLS examples omit policy.add(policy.all())
	-- single server authenticated using its certificate pin_sha256
	  policy.TLS_FORWARD({{'192.0.2.1', pin_sha256='YQ=='}})  -- pin_sha256 is base64-encoded
	-- single server using non-standard port
	  policy.TLS_FORWARD({{'192.0.2.1@443', pin_sha256='YQ=='}})  -- use @ or # to specify port
	-- single server with multiple valid pins (e.g. anycast)
	  policy.TLS_FORWARD({{'192.0.2.1', pin_sha256={'YQ==', 'Wg=='}})
	-- multiple servers, each with own authenticator
	  policy.TLS_FORWARD({ -- please note that { here starts list of servers
		{'192.0.2.1', pin_sha256='Wg=='},
		-- server must present certificate issued by specified CA and hostname must match
		{'2001:DB8::d0c', hostname='res.example.com', ca_file='/etc/knot-resolver/tlsca.crt'}
	})

.. _policy_examples:

Policy examples
^^^^^^^^^^^^^^^

.. code-block:: lua

	-- Whitelist 'www[0-9].badboy.cz'
	policy.add(policy.pattern(policy.PASS, '\4www[0-9]\6badboy\2cz'))
	-- Block all names below badboy.cz
	policy.add(policy.suffix(policy.DENY, {todname('badboy.cz.')}))

	-- Custom rule
	local ffi = require('ffi')
	local function genRR (state, req)
		local answer = req.answer
		local qry = req:current()
		if qry.stype ~= kres.type.A then
			return state
		end
		ffi.C.kr_pkt_make_auth_header(answer)
		answer:rcode(kres.rcode.NOERROR)
		answer:begin(kres.section.ANSWER)
		answer:put(qry.sname, 900, answer:qclass(), kres.type.A, '\192\168\1\3')
		return kres.DONE
	end
	policy.add(policy.suffix(genRR, { todname('my.example.cz.') }))

	-- Disallow ANY queries
	policy.add(function (req, query)
		if query.stype == kres.type.ANY then
			return policy.DROP
		end
	end)
	-- Enforce local RPZ
	policy.add(policy.rpz(policy.DENY, 'blacklist.rpz'))
	-- Forward all queries below 'company.se' to given resolver
	policy.add(policy.suffix(policy.FORWARD('192.168.1.1'), {todname('company.se')}))
	-- Forward all queries matching pattern
	policy.add(policy.pattern(policy.FORWARD('2001:DB8::1'), '\4bad[0-9]\2cz'))
	-- Forward all queries (to public resolvers https://www.nic.cz/odvr)
	policy.add(policy.all(policy.FORWARD({'2001:678:1::206', '193.29.206.206'})))
	-- Print all responses with matching suffix
	policy.add(policy.suffix(policy.QTRACE, {todname('rhybar.cz.')}))
	-- Print all responses
	policy.add(policy.all(policy.QTRACE))
	-- Mirror all queries and retrieve information
	local rule = policy.add(policy.all(policy.MIRROR('127.0.0.2')))
	-- Print information about the rule
	print(string.format('id: %d, matched queries: %d', rule.id, rule.count)
	-- Reroute all addresses found in answer from 192.0.2.0/24 to 127.0.0.x
	-- this policy is enforced on answers, therefore 'postrule'
	local rule = policy.add(policy.REROUTE({'192.0.2.0/24', '127.0.0.0'}), true)
	-- Delete rule that we just created
	policy.del(rule.id)

Additional properties
^^^^^^^^^^^^^^^^^^^^^

Most properties (actions, filters) are described above.

.. function:: policy.add(rule, postrule)

  :param rule: added rule, i.e. ``policy.pattern(policy.DENY, '[0-9]+\2cz')``
  :param postrule: boolean, if true the rule will be evaluated on answer instead of query
  :return: rule description

  Add a new policy rule that is executed either or queries or answers, depending on the ``postrule`` parameter. You can then use the returned rule description to get information and unique identifier for the rule, as well as match count.

.. function:: policy.del(id)

  :param id: identifier of a given rule
  :return: boolean

  Remove a rule from policy list.

.. function:: policy.suffix_common(action, suffix_table[, common_suffix])

  :param action: action if the pattern matches QNAME
  :param suffix_table: table of valid suffixes
  :param common_suffix: common suffix of entries in suffix_table

  Like suffix match, but you can also provide a common suffix of all matches for faster processing (nil otherwise).
  This function is faster for small suffix tables (in the order of "hundreds").

.. function:: policy.rpz(action, path[, format])

  :param action: the default action for match in the zone (e.g. RH-value `.`)
  :param path: path to zone file | database

  Enforce RPZ_ rules. This can be used in conjunction with published blocklist feeds.
  The RPZ_ operation is well described in this `Jan-Piet Mens's post`_,
  or the `Pro DNS and BIND`_ book. Here's compatibility table:

  .. csv-table::
   :header: "Policy Action", "RH Value", "Support"

   "NXDOMAIN", "``.``", "**yes**"
   "NODATA", "``*.``", "*partial*, implemented as NXDOMAIN"
   "Unchanged", "``rpz-passthru.``", "**yes**"
   "Nothing", "``rpz-drop.``", "**yes**"
   "Truncated", "``rpz-tcp-only.``", "**yes**"
   "Modified", "anything", "no"

  .. csv-table::
   :header: "Policy Trigger", "Support"

   "QNAME", "**yes**"
   "CLIENT-IP", "*partial*, may be done with :ref:`views <mod-view>`"
   "IP", "no"
   "NSDNAME", "no"
   "NS-IP", "no"

.. function:: policy.todnames({name, ...})

   :param: names table of domain names in textual format

   Returns table of domain names in wire format converted from strings.

   .. code-block:: lua

      -- Convert single name
      assert(todname('example.com') == '\7example\3com\0')
      -- Convert table of names
      policy.todnames({'example.com', 'me.cz'})
      { '\7example\3com\0', '\2me\2cz\0' }

This module is enabled by default because it implements mandatory :rfc:`6761` logic. For debugging purposes you can add ``modules.unload('policy')`` to your config to unload the module.


.. _`Aho-Corasick`: https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_string_matching_algorithm
.. _`@jgrahamc`: https://github.com/jgrahamc/aho-corasick-lua
.. _RPZ: https://dnsrpz.info/
.. _`PEM format`: https://en.wikipedia.org/wiki/Privacy-enhanced_Electronic_Mail
.. _`Pro DNS and BIND`: http://www.zytrax.com/books/dns/ch7/rpz.html
.. _`Jan-Piet Mens's post`: http://jpmens.net/2011/04/26/how-to-configure-your-bind-resolvers-to-lie-using-response-policy-zones-rpz/
.. _`Transport Layer Security`: https://en.wikipedia.org/wiki/Transport_Layer_Security
.. _`DNS Privacy Project`: https://dnsprivacy.org/
.. _`IETF draft dprive-dtls-and-tls-profiles`: https://tools.ietf.org/html/draft-ietf-dprive-dtls-and-tls-profiles
