.. _mod-dns64:

DNS64
-----

The module for :rfc:`6147` DNS64 AAAA-from-A record synthesis, it is used to enable client-server communication between an IPv6-only client and an IPv4-only server. See the well written `introduction`_ in the PowerDNS documentation.

.. warning:: The module currently won't work well with query policies.

.. tip:: The A record sub-requests will be DNSSEC secured, but the synthetic AAAA records can't be. Make sure the last mile between stub and resolver is secure to avoid spoofing.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

	-- Load the module with a NAT64 address
	modules = { dns64 = 'fe80::21b:77ff:0:0' }
	-- Reconfigure later
	dns64.config('fe80::21b:aabb:0:0')



.. _RPZ: https://dnsrpz.info/
.. _introduction: https://doc.powerdns.com/md/recursor/dns64
