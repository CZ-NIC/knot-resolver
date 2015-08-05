.. _mod-block:

Query blocking
--------------

This module can block queries (and subrequests) based on user-defined policies.
By default, it blocks queries to reverse lookups in private subnets as per :rfc:`1918`, :rfc:`5735` and :rfc:`5737`.
You can however extend it to deflect `Slow drip DNS attacks <https://blog.secure64.com/?p=377>`_ for example, or gray-list resolution of misbehaving zones.

There are two policies implemented:

* ``pattern``
  - applies action if QNAME matches `regular expression <http://lua-users.org/wiki/PatternsTutorial>`_
* ``suffix``
  - applies action if QNAME suffix matches given list of suffixes (useful for "is domain in zone" rules),
  uses `Aho-Corasick`_ string matching algorithm implemented by `@jgrahamc`_ (CloudFlare, Inc.) (BSD 3-clause)

There are three action:

* ``PASS`` - let the query pass through
* ``DENY`` - return NXDOMAIN answer
* ``DROP`` - terminate query resolution, returns SERVFAIL to requestor

.. note:: The module (and ``kres``) treats domain names as wire, not textual representation. So each label in name is prefixed with its length, e.g. "example.com" equals to "\7example\3com".

Example configuration
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

	-- Load default block rules
	modules = { 'block' }
	-- Whitelist 'www[0-9].badboy.cz'
	block:add(block.pattern(block.PASS, '\4www[0-9]\6badboy\2cz'))
	-- Block all names below badboy.cz
	block:add(block.suffix(block.DENY, {'\6badboy\2cz'}))
	-- Custom rule
	block:add(function (req, query)
		if query:qname():find('%d.%d.%d.224\7in-addr\4arpa') then
			return block.DENY
		end
	end)
	-- Disallow ANY queries
	block:add(function (req, query)
		if query.type == kres.type.ANY then
			return block.DROP
		end
	end)

Properties
^^^^^^^^^^

.. envvar:: block.PASS (number)
.. envvar:: block.DENY (number)
.. envvar:: block.DROP (number)

.. function:: block:add(rule)

  :param rule: added rule, i.e. ``block.pattern(block.DENY, '[0-9]+\2cz')``
  :param pattern: regular expression
  
  Policy to block queries based on the QNAME regex matching.

.. function:: block.pattern(action, pattern)

  :param action: action if the pattern matches QNAME
  :param pattern: regular expression
  
  Policy to block queries based on the QNAME regex matching.

.. function:: block.suffix(action, suffix_table)

  :param action: action if the pattern matches QNAME
  :param suffix_table: table of valid suffixes
  
  Policy to block queries based on the QNAME suffix match.

.. function:: block.suffix_common(action, suffix_table[, common_suffix])

  :param action: action if the pattern matches QNAME
  :param suffix_table: table of valid suffixes
  :param common_suffix: common suffix of entries in suffix_table
  
  Like suffix match, but you can also provide a common suffix of all matches for faster processing (nil otherwise).
  This function is faster for small suffix tables (in the order of "hundreds").

.. _`Aho-Corasick`: https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_string_matching_algorithm
.. _`@jgrahamc`: https://github.com/jgrahamc/aho-corasick-lua

