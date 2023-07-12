.. SPDX-License-Identifier: GPL-3.0-or-later

IPv4 and IPv6 usage
-------------------

Following settings affect client part of the resolver,
i.e. communication between the resolver itself and other DNS servers.

IPv4 and IPv6 protocols are used by default. For performance reasons it is
recommended to explicitly disable protocols which are not available
on your system, though the impact of IPv6 outage is lowered since release 5.3.0.


.. option:: network/do-ipv4: true|false

   :default: true

   Enable/disable using IPv4 for contacting upstream nameservers.

.. option:: network/do-ipv6: true|false

   :default: true

   Enable/disable using IPv6 for contacting upstream nameservers.

.. option:: network/out-interface-v4: <IPv4 address>

   The IPv4 address used to perform queries.
   Not configured by default, which lets the OS choose any address.

.. option:: network/out-interface-v6: <IPv6 address>

   The IPv6 address used to perform queries.
   Not configured by default, which lets the OS choose any address.
