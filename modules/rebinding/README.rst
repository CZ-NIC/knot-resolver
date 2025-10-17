.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-rebinding:

Rebinding protection
====================

This module provides protection from `DNS Rebinding attack`_ by blocking
answers which contain IPv4_ or IPv6_ addresses for private use
(or some other special-use addresses).

To enable this module insert following line into your configuration file:

.. code-block:: lua

  modules.load('rebinding < iterate')

Please note that this module does not offer stable configuration interface
yet. For this reason it is suitable mainly for public resolver operators
who do not need to whitelist certain subnets.

There is experimental support for whitelisting:

.. code-block:: lua

  modules.load('rebinding < iterate')
  rebinding.add_whitelist_entry('my.domain', '192.168.1.0/24', 'fd31:6ac3:7c6b:70d4::/64'))

.. warning:: DNS Blacklists (`RFC 5782`_) often use `127.0.0.0/8` to blacklist
   a domain. Using the rebinding module prevents DNSBL from functioning
   properly.

.. _`DNS Rebinding attack`: https://en.wikipedia.org/wiki/DNS_rebinding
.. _IPv4: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
.. _IPv6: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
.. _`RFC 5782`: https://tools.ietf.org/html/rfc5782#section-2.1
