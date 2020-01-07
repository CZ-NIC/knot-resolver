Client
======

Following settings affect client part of the resolver, i.e. communication between the resolver itself and other DNS servers.

.. envvar:: net.ipv4 = true|false

   :return: boolean (default: true)

   Enable/disable using IPv4 for contacting upstream nameservers.

.. function:: net.outgoing_v4([string address])

   Get/set the IPv4 address used to perform queries.
   The default is ``nil``, which lets the OS choose any address.

.. envvar:: net.ipv6 = true|false

   :return: boolean (default: true)

   Enable/disable using IPv6 for contacting upstream nameservers.

.. function:: net.outgoing_v6([string address])

   Get/set the IPv6 address used to perform queries.
   The default is ``nil``, which lets the OS choose any address.

