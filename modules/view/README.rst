.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-view:

Views and ACLs
==============

The :ref:`policy <mod-policy>` module implements policies for global query matching, e.g. solves "how to react to certain query".
This module combines it with query source matching, e.g. "who asked the query". This allows you to create personalized blacklists, filters and ACLs.

There are two identification mechanisms:

* ``addr``
  - identifies the client based on his subnet
* ``tsig``
  - identifies the client based on a TSIG key name (only for testing purposes, TSIG signature is not verified!)

View module allows you to combine query source information with :ref:`policy <mod-policy>` rules.

.. code-block:: lua

	view:addr('10.0.0.1', policy.suffix(policy.TC, policy.todnames({'example.com'})))

This example will force given client to TCP for names in ``example.com`` subtree.
You can combine view selectors with RPZ_ to create personalized filters for example.

.. warning::

	Beware that cache is shared by *all* requests.  For example, it is safe
	to refuse answer based on who asks the resolver, but trying to serve
	different data to different clients will result in unexpected behavior.
	Setups like **split-horizon** which depend on isolated DNS caches
        are explicitly not supported.


Example configuration
---------------------

.. code-block:: lua

	-- Load modules
	modules = { 'view' }
	-- Whitelist queries identified by TSIG key
	view:tsig('\5mykey', policy.all(policy.PASS))
	-- Block local IPv4 clients (ACL like)
	view:addr('127.0.0.1', policy.all(policy.DENY))
	-- Block local IPv6 clients (ACL like)
	view:addr('::1', policy.all(policy.DENY))
	-- Drop queries with suffix match for remote client
	view:addr('10.0.0.0/8', policy.suffix(policy.DROP, policy.todnames({'xxx'})))
	-- RPZ for subset of clients
	view:addr('192.168.1.0/24', policy.rpz(policy.PASS, 'whitelist.rpz'))
	-- Do not try this - it will pollute cache and surprise you!
	-- view:addr('10.0.0.0/8', policy.all(policy.FORWARD('2001:DB8::1')))
	-- Drop everything that hasn't matched
	view:addr('0.0.0.0/0', policy.all(policy.DROP))

Rule order
----------

The current implementation is best understood as three separate rule chains:
vanilla ``policy.add``, ``view:tsig`` and ``view:addr``.
For each request the rules in these chains get tried one by one until a :ref:`non-chain policy action <mod-policy-actions>` gets executed.

By default :ref:`policy module <mod-policy>` acts before ``view`` module due to ``policy`` being loaded by default. If you want to intermingle universal rules with ``view:addr``, you may simply wrap the universal policy rules in view closure like this:

.. code-block:: lua

    view:addr('0.0.0.0/0', policy.<rule>) -- and
    view:addr('::0/0',     policy.<rule>)


Properties
----------

.. function:: view:addr(subnet, rule)

  :param subnet: client subnet, i.e. ``10.0.0.1``
  :param rule: added rule, i.e. ``policy.pattern(policy.DENY, '[0-9]+\2cz')``

  Apply rule to clients in given subnet.

.. function:: view:tsig(key, rule)

  :param key: client TSIG key domain name, i.e. ``\5mykey``
  :param rule: added rule, i.e. ``policy.pattern(policy.DENY, '[0-9]+\2cz')``

  Apply rule to clients with given TSIG key.

  .. warning:: This just selects rule based on the key name, it doesn't verify the key or signature yet.

.. _RPZ: https://dnsrpz.info/
