.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-dns64:

*****
DNS64
*****

DNS64 AAAA-from-A record synthesis :rfc:`6147` is used to enable client-server communication between an IPv6-only client and an IPv4-only server.
See the well written `introduction`_ in the PowerDNS documentation.

DNS64 can be enabled by switching its configuration option to `true`.
By default, the well-known prefix ``64:ff9b::/96`` is used.

.. code-block:: yaml

   dns64:
     enable: true

It is also possible to configure own prefix.

.. code-block:: yaml

   dns64:
     enable: true
     prefix: 2001:db8::aabb:0:0/96

.. warning::

    The module currently won't work well with :func:`policy.STUB`. Also, the IPv6 ``prefix`` passed in configuration is assumed to be ``/96``.

.. tip::

    The A record sub-requests will be DNSSEC secured, but the synthetic AAAA records can't be. Make sure the last mile between stub and resolver is secure to avoid spoofing.


Advanced options
================

TTL in CNAME generated in the reverse ``ip6.arpa.`` subtree is configurable.

.. code-block:: yaml

   dns64:
     enable: true
     prefix: 2001:db8:77ff::/96
     reverse-ttl: 300s

You can specify a set of IPv6 subnets that are disallowed in answer.
If they appear, they will be replaced by AAAAs generated from As.

.. code-block:: yaml

   dns64:
     enable: true
     prefix: 2001:db8:3::/96
     exclude: [2001:db8:888::/48, '::ffff/96']

    # You could even pass '::/0' to always force using generated AAAAs.

In case you don't want DNS64 for all clients, you can set ``dns64`` option to ``false`` via the :ref:`views <config-views>` section.

.. code-block:: yaml

    views:
      # disable DNS64 for a subnet
      - subnets: [2001:db8:11::/48]
        tags: [t01]
        options:
          dns64: false

    dns64: true


.. _introduction: https://doc.powerdns.com/md/recursor/dns64
