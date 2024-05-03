.. SPDX-License-Identifier: GPL-3.0-or-later

Addresses and services
----------------------

Addresses, ports, protocols, and API calls available for clients communicating
with the resolver are configured in :option:`network/listen <network/listen: <list>>`.

.. code-block:: yaml

   network: # typical examples
     listen:
       - interface: lo # plain DNS on localhost, port 53
       - interface: eth0
         kind: dot
       - interface: [ 127.0.0.1, '::1' ]
         kind: doh2

First, you need to decide what type of service should be available on a given IP
address + port combination.

.. csv-table::
   :header: "Protocol/service", :option:`kind <kind: dns|xdp|dot|doh2|doh-legacy>`

   "DNS (unencrypted UDP+TCP, :rfc:`1034`)","``dns``"
   "DNS (unencrypted UDP, `using XDP Linux API <./dev/daemon-bindings-net_xdpsrv.html#dns-over-xdp>`_)","``xdp``"
   ":ref:`dns-over-tls`","``dot``"
   ":ref:`dns-over-https`","``doh2``"
   "`Legacy DNS-over-HTTPS (DoH) <./dev/modules-http.html#mod-http-doh>`_","``doh-legacy``"

.. note::

   By default, **unencrypted DNS and DNS-over-TLS** are configured to **listen on localhost**.

.. option:: network/listen: <list>

   .. option:: unix-socket: <path>

      Path to a unix domain socket to listen on.

   .. option:: interface: <address or interface>

      IP address or interface name to listen on. May also be a list of addresses
      and interface names. Optionally, the port number may be specified using
      ``@`` as a separator, e.g. ``127.0.0.1@3535`` or ``eth0@5353``.

      .. warning::

         On machines with multiple IP addresses, avoid listening on wildcards like
         ``0.0.0.0`` or ``::``. If a client can be reached through multiple addresses,
         UDP answers from a wildcard address might pick a wrong source address - most
         well-behaved clients will then refuse such a response.

   .. option:: port: <1-65535>

      :default: 53 (dns, xdp), 853 (dot), 443 (doh2, doh-legacy)

      Port number to listen on.

   .. option:: kind: dns|xdp|dot|doh2|doh-legacy

      :default: dns

      DNS query transport protocol.

   .. option:: freebind: true|false

      :default: false

      Freebind allows binding to a non-local or not yet available address.

.. code-block:: yaml

   network: # some unusual examples
     listen:
       - interface: '::1'
         port: 3535
       - interface: eth0
         port: 5353  # custom port number, default is 53 for XDP
         kind: xdp
       - unix-socket: /tmp/kres-socket  # bind to unix domain socked


.. _config-network-proxyv2:

PROXYv2 protocol
^^^^^^^^^^^^^^^^

Knot Resolver supports proxies that utilize the `PROXYv2 protocol <https://www.haproxy.org/download/2.5/doc/proxy-protocol.txt>`_
to identify clients.

A PROXY header contains the IP address of the original client who sent a query.
This allows the resolver to treat queries as if they actually came from the
client's IP address, rather than the address of the proxy they came through. For
example, :ref:`Views and ACLs <config-views>` are able to work as intended when
PROXYv2 is in use.

Allowing usage of the PROXYv2 protocol for all clients would be a security
vulnerability, because clients would then be able to spoof their IP addresses
via the PROXYv2 header. Because of this, the resolver requires explicit
specification of which clients are allowed to send PROXYv2 headers. Queries with
PROXYv2 headers from clients who are not explicitly allowed to use the protocol
will be discarded.

.. option:: network/proxy-protocol: false|<options>

   :default: false

   .. option:: allow: <list of addresses and subnets>

      Allow usage of the PROXYv2 protocol headers by clients on the specified
      addresses. It is possible to permit whole networks to send PROXYv2 headers
      by specifying the network mask using the CIDR notation
      (e.g. ``172.22.0.0/16``). IPv4 as well as IPv6 addresses are supported.

      If you wish to allow all clients to use PROXYv2 (e.g. because you have this
      kind of security handled on another layer of your network infrastructure),
      you can specify a netmask of ``/0``. Please note that this setting is
      address-family-specific, so this needs to be applied to both IPv4 and IPv6
      separately.

.. code-block:: yaml

   network:
     proxy-protocol:
       allow:
         - 172.22.0.1     # allows '172.22.0.1' specifically
         - 172.18.1.0/24  # allows everyone at '172.18.1.*'
         - fe80::/10      # allows everyone at IPv6 link-local
         - '::/0'         # allows all IPv6 (but no IPv4)
         - 0.0.0.0/0      # allows all IPv4 (but no IPv6)


TCP pipeline limit
^^^^^^^^^^^^^^^^^^

TCP pipeline limit per-client, i.e. the number of outstanding queries that a single client connection can make in parallel.

.. option:: network/tcp-pipeline: <int>

    :default: 100

.. code-block:: yaml

   network:
     tcp-pipeline: 50

.. warning::

   Please note that too large limit may have negative impact on performance and can lead to increased number of SERVFAIL answers.

.. _`dnsproxy module`: https://www.knot-dns.cz/docs/2.7/html/modules.html#dnsproxy-tiny-dns-proxy
