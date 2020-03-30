.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-dns64:

DNS64
=====

The module for :rfc:`6147` DNS64 AAAA-from-A record synthesis, it is used to enable client-server communication between an IPv6-only client and an IPv4-only server. See the well written `introduction`_ in the PowerDNS documentation.
If no address is passed (i.e. ``nil``), the well-known prefix ``64:ff9b::`` is used.

.. warning:: The module currently won't work well with :ref:`policy.STUB <mod-policy>`.
   Also, the IPv6 passed in configuration is assumed to be ``/96``, and
   PTR synthesis and "exclusion prefixes" aren't implemented.

.. tip:: The A record sub-requests will be DNSSEC secured, but the synthetic AAAA records can't be. Make sure the last mile between stub and resolver is secure to avoid spoofing.

Example configuration
---------------------

.. code-block:: lua

	-- Load the module with a NAT64 address
	modules = { dns64 = 'fe80::21b:77ff:0:0' }
	-- Reconfigure later
	dns64.config('fe80::21b:aabb:0:0')


.. _introduction: https://doc.powerdns.com/md/recursor/dns64
