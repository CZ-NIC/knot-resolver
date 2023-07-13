.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-forward:

Forwarding
==========

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

      .. option:: dnssec: true|false

         :default: true

         Enable/disable DNSSEC for a subtree.

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
