.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-forward:

Forwarding
==========

*Forwarding* configuration instructs resolver to forward cache-miss queries from clients to manually specified DNS resolvers *(upstream servers)*.
In other words the *forwarding* mode does exact opposite of the default *recursive* mode because resolver in *recursive* mode automatically selects which servers to ask.

Main use-cases are:

  * Building a tree structure of DNS resolvers to improve performance (by improving cache hit rate).
  * Accessing domains which are not available using recursion (e.g. if internal company servers return different answers than public ones).
  * Forwarding through a central DNS traffic filter.

Forwarding implementation in Knot Resolver has following properties:

  * Answers from *upstream* servers are cached.
  * Answers from *upstream* servers are locally DNSSEC-validated, unless dnssec is disabled.
  * Resolver automatically selects which IP address from given set of IP addresses will be used (based on performance characteristics).
  * Forwarding can use either encrypted or unencrypted DNS protocol.

.. warning::

        We strongly discourage use of "fake top-level domains" like ``corp.`` because these made-up domains are indistinguishable from an attack, so DNSSEC validation will prevent such domains from working.
        In the long-term it is better to migrate data into a legitimate, properly delegated domains which do not suffer from these security problems.

.. code-block:: yaml

  forward:
    # ask everything through some public resolver
    - subtree: .
      servers: [ 2001:148f:fffe::1, 193.17.47.1 ]

.. code-block:: yaml

  forward:
    # encrypted public resolver, again for all names
    - subtree: .
      servers:
        - address: [ 2001:148f:fffe::1, 193.17.47.1 ]
          transport: tls
          hostname: odvr.nic.cz

    # use a local authoritative server for an internal-only zone
    - subtree: internal.example.com
      servers: [ 10.0.0.53 ]
      options:
        authoritative: true
        dnssec: false

The :option:`forward <forward: <list>>` list of rules overrides which servers get asked to obtain DNS data.

.. option:: forward: <list>

   .. option:: subtree: <subtree name>

      Subtree to forward.

   .. option:: servers: <list of addresses>|<list of servers>

      Optionaly you can set port after address by ``@`` separator (``193.17.47.1@5353``).

      .. option:: address: <address>|<list of addresses>

         IP address(es) of a forward server.

      .. option:: transport: tls

         Optional, transport protocol for a forward server.

      .. option:: hostname: <hostname>

         Hostname of the Forward server.

      .. option:: ca-file: <path>

         Optional, path to CA certificate file.

   .. option:: options:

      .. option:: authoritative: true|false

         :default: false

         The forwarding target is an authoritative server.
         For those we only support specifying the address, i.e. TLS, ports and IPv6
         scope IDs (``%interface``) are **not** supported.

      .. option:: dnssec: true|false

         :default: true

         Enable/disable DNSSEC for a subtree.
