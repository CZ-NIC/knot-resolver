.. _mod-policy:

Query policies 
--------------

This module can block, rewrite, or alter queries based on user-defined policies.
By default, it blocks queries to reverse lookups in private subnets as per :rfc:`1918`, :rfc:`5735` and :rfc:`5737`.
You can however extend it to deflect `Slow drip DNS attacks <https://blog.secure64.com/?p=377>`_ for example, or gray-list resolution of misbehaving zones.

There are several policies implemented:

* ``pattern``
  - applies action if QNAME matches `regular expression <http://lua-users.org/wiki/PatternsTutorial>`_
* ``suffix``
  - applies action if QNAME suffix matches given list of suffixes (useful for "is domain in zone" rules),
  uses `Aho-Corasick`_ string matching algorithm implemented by `@jgrahamc`_ (CloudFlare, Inc.) (BSD 3-clause)
* ``rpz``
  - implementes a subset of the RPZ_ format. Currently it can be used with a zonefile, a binary database support is on the way. Binary database can be updated by an external process on the fly.
* custom filter function

There are several defined actions:

* ``PASS`` - let the query pass through
* ``DENY`` - return NXDOMAIN answer
* ``DROP`` - terminate query resolution, returns SERVFAIL to requestor
* ``TC`` - set TC=1 if the request came through UDP, forcing client to retry with TCP

.. note:: The module (and ``kres``) treats domain names as wire, not textual representation. So each label in name is prefixed with its length, e.g. "example.com" equals to ``"\7example\3com"``.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

	-- Load default policies
	modules = { 'policy' }
	-- Whitelist 'www[0-9].badboy.cz'
	policy:add(policy.pattern(policy.PASS, '\4www[0-9]\6badboy\2cz'))
	-- Block all names below badboy.cz
	policy:add(policy.suffix(policy.DENY, {'\6badboy\2cz'}))
	-- Custom rule
	policy:add(function (req, query)
		if query:qname():find('%d.%d.%d.224\7in-addr\4arpa') then
			return policy.DENY
		end
	end)
	-- Disallow ANY queries
	policy:add(function (req, query)
		if query.type == kres.type.ANY then
			return policy.DROP
		end
	end)
	-- Enforce local RPZ
	policy:add(policy.rpz(policy.DENY, 'blacklist.rpz'))

Properties
^^^^^^^^^^

.. envvar:: policy.PASS (number)
.. envvar:: policy.DENY (number)
.. envvar:: policy.DROP (number)
.. envvar:: policy.TC   (number)

.. function:: policy:add(rule)

  :param rule: added rule, i.e. ``policy.pattern(policy.DENY, '[0-9]+\2cz')``
  :param pattern: regular expression
  
  Policy to block queries based on the QNAME regex matching.

.. function:: policy.pattern(action, pattern)

  :param action: action if the pattern matches QNAME
  :param pattern: regular expression
  
  Policy to block queries based on the QNAME regex matching.

.. function:: policy.suffix(action, suffix_table)

  :param action: action if the pattern matches QNAME
  :param suffix_table: table of valid suffixes
  
  Policy to block queries based on the QNAME suffix match.

.. function:: policy.suffix_common(action, suffix_table[, common_suffix])

  :param action: action if the pattern matches QNAME
  :param suffix_table: table of valid suffixes
  :param common_suffix: common suffix of entries in suffix_table
  
  Like suffix match, but you can also provide a common suffix of all matches for faster processing (nil otherwise).
  This function is faster for small suffix tables (in the order of "hundreds").

.. function:: policy.rpz(action, path[, format])

  :param action: the default action for match in the zone (e.g. RH-value `.`)
  :param path: path to zone file | database
  :param format: set to `'lmdb'` for binary DB, currently NYI
  
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

.. _`Aho-Corasick`: https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_string_matching_algorithm
.. _`@jgrahamc`: https://github.com/jgrahamc/aho-corasick-lua
.. _RPZ: https://dnsrpz.info/
.. _`Pro DNS and BIND`: http://www.zytrax.com/books/dns/ch7/rpz.html
.. _`Jan-Piet Mens's post`: http://jpmens.net/2011/04/26/how-to-configure-your-bind-resolvers-to-lie-using-response-policy-zones-rpz/