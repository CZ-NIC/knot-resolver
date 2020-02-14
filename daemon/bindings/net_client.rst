.. SPDX-License-Identifier: GPL-3.0-or-later

IPv4 and IPv6 usage
-------------------

Following settings affect client part of the resolver,
i.e. communication between the resolver itself and other DNS servers.

IPv4 and IPv6 protocols are used by default. For performance reasons it is
recommended to explicitly disable protocols which are not available
on your system.

.. envvar:: net.ipv4 = true|false

   :return: boolean (default: true)

   Enable/disable using IPv4 for contacting upstream nameservers.

.. envvar:: net.ipv6 = true|false

   :return: boolean (default: true)

   Enable/disable using IPv6 for contacting upstream nameservers.

.. function:: net.outgoing_v4([string address])

   Get/set the IPv4 address used to perform queries.
   The default is ``nil``, which lets the OS choose any address.

.. function:: net.outgoing_v6([string address])

   Get/set the IPv6 address used to perform queries.
   The default is ``nil``, which lets the OS choose any address.

