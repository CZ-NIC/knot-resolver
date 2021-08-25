.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-dns64:

DNS64
=====

The module for :rfc:`6147` DNS64 AAAA-from-A record synthesis, it is used to enable client-server communication between an IPv6-only client and an IPv4-only server. See the well written `introduction`_ in the PowerDNS documentation.
If no address is passed (i.e. ``nil``), the well-known prefix ``64:ff9b::`` is used.

.. _introduction: https://doc.powerdns.com/md/recursor/dns64

Simple example
--------------

.. code-block:: lua

	-- Load the module with default settings
	modules = { 'dns64' }
	-- Reconfigure later
	dns64.config({ prefix = '2001:db8::aabb:0:0' })

.. warning:: The module currently won't work well with :func:`policy.STUB`.
   Also, the IPv6 ``prefix`` passed in configuration is assumed to be ``/96``.

.. tip:: The A record sub-requests will be DNSSEC secured, but the synthetic AAAA records can't be. Make sure the last mile between stub and resolver is secure to avoid spoofing.


Advanced options
----------------

TTL in CNAME generated in the reverse ``ip6.arpa.`` subtree is configurable:

.. code-block:: lua

   dns64.config({ prefix = '2001:db8:77ff::', rev_ttl = 300 })

You can specify a set of IPv6 subnets that are disallowed in answer.
If they appear, they will be replaced by AAAAs generated from As.

.. code-block:: lua

   dns64.config({
       prefix = '2001:db8:3::',
       exclude_subnets = { '2001:db8:888::/48', '::ffff/96' },
   })
   -- You could even pass '::/0' to always force using generated AAAAs.

In case you don't want dns64 for all clients,
you can set ``DNS64_DISABLE`` flag via the :ref:`view module <mod-view>`.

.. code-block:: lua

    modules = { 'dns64', 'view' }
    -- Disable dns64 for everyone, but re-enable it for two particular subnets.
    view:addr('::/0', policy.all(policy.FLAGS('DNS64_DISABLE')))
    view:addr('2001:db8:11::/48', policy.all(policy.FLAGS(nil, 'DNS64_DISABLE')))
    view:addr('2001:db8:93::/48', policy.all(policy.FLAGS(nil, 'DNS64_DISABLE')))

