.. SPDX-License-Identifier: GPL-3.0-or-later

.. _gettingstarted-config:

*************
Configuration
*************

The easiest way to configure Knot Resolver is via the ``/etc/knot-resolver/config.yaml`` file containing a declarative YAML configuration.

You can start exploring the configuration by reading further in this chapter, or you can take a look at the complete :ref:`configuration <configuration-chapter>` documentation.

.. contents::
   :depth: 1
   :local:

Complete example configuration files can be found `in Knot Resolver's source repository <https://gitlab.nic.cz/knot/knot-resolver/tree/master/etc/config>`_.
Examples are also installed as documentation files, typically in the ``/usr/share/doc/knot-resolver*/examples/`` directory (the location may differ based on your Linux distribution).

.. tip::

   The :ref:`kresctl <manager-client>` utility may be used to **validate** your configuration before you push it to the running resolver.
   This can help prevent typos in the configuration from causing resolver outages.

   .. code-block::

      $ kresctl validate /etc/knot-resolver/config.yaml

If you update the configuration file while Knot Resolver is running, you can force the resolver to **reload** it by invoking a ``systemd`` reload command.

.. code-block::

   $ systemctl reload knot-resolver.service

.. note::

   **Reloading configuration** may fail, even when your configuration is valid, because some options cannot be changed while running.
   You can always find an explanation of the error in the log accesed by the ``journalctl -eu knot-resolver`` command.

===============================
Listening on network interfaces
===============================

The first thing you will probably want to configure are the network interfaces to listen on.
The following example instructs the resolver to receive standard unencrypted DNS queries on IP addresses ``192.0.2.1`` and ``2001:db8::1``.
Encrypted DNS queries using the DNS-over-TLS protocol are accepted on all IP addresses of the ``eth0`` network interface, TCP port ``853``.

.. code-block:: yaml

   network:
     listen:
       - interface: # port 53 is default
           - 192.0.2.1
           - 2001:db8::1
       - interface: eth0
         port: 853
         kind: dot # DNS-over-TLS

For more details, see :ref:`network configuration <config-network>`.

.. warning::

   On machines with multiple IP addresses, avoid listening on wildcards like
   ``0.0.0.0`` or ``::``. If a client can be reached through multiple addresses,
   UDP answers from a wildcard address might pick a wrong source address - most
   well-behaved clients will then refuse such a response.


.. _example-internal:

==========================
Example: Internal Resolver
==========================

This is an example configuration snippet typical for a company-internal resolver inaccessible from the outside of a company network.

^^^^^^^^^^^^^^^^^^^^^
Internal-only domains
^^^^^^^^^^^^^^^^^^^^^

An internal-only domain is a domain not accessible from the public Internet.
In order to resolve internal-only domains, a query policy needs to be added to forward queries to a correct internal server.
This configuration will forward the two listed domains to an internal authoritative DNS server with the IP address ``192.0.2.44``.

.. code-block:: yaml

   forward:
     # define a list of internal-only domains
     - subtree:
         - company.example
         - internal.example
       # forward all queries belonging to the domains in the list above to IP address '192.0.2.44'
       servers:
         - 192.0.2.44
       # common options configuration for internal-only domains
       options:
         authoritative: true
         dnssec: false

See the :ref:`forwarding <config-forward>` chapter for more details.


.. _example-isp:

=====================
Example: ISP Resolver
=====================

The following configuration snippets are typical for Internet Service Providers offering DNS resolver
services to their own clients on their own network. Please note that running a *public DNS resolver*
is a more complicated use-case and not covered by this example.

^^^^^^^^^^^^^^^^^^^^^^
Limiting client access
^^^^^^^^^^^^^^^^^^^^^^

With the exception of public resolvers, a DNS resolver should resolve only queries sent by clients in its own network. This restriction limits the attack surface on the resolver itself, as well as the rest of the Internet.

In a situation where access to your DNS resolver is not limited using an IP firewall, you may want to implement access restrictions.
The following example allows only queries from clients on the subnet ``192.0.2.0/24`` and refuses all the rest.

.. code-block:: yaml

   views:
     # refuse everything that hasn't matched
     - subnets: [ 0.0.0.0/0, "::/0" ]
       answer: refused
     # whitelist queries identified by subnet
     - subnets: [ 192.0.2.0/24 ]
       answer: allow

^^^^^^^^^^^^^^^^^^^^^^^^
TLS server configuration
^^^^^^^^^^^^^^^^^^^^^^^^

Knot Resolver supports secure transport for DNS queries between client machines and the resolvers, a feature whose popular demand is on the rise.
The recommended way to achieve this is to start a DNS-over-TLS server and accept encrypted queries.

First step is to enable TLS on listening interfaces:

.. code-block:: yaml

    network:
      listen:
        # DNS over TLS on port 853
        - interface:
            - 192.0.2.1
            - 2001:db8::1
          kind: dot

By default, a self-signed certificate is generated.
The second step is then obtaining and configuring your own TLS certificates signed by a trusted CA.
Once a certificate was obtained, a path to the certificate files can be specified as follows:

.. code-block:: yaml

   network:
     tls:
       cert-file: '/etc/knot-resolver/server-cert.pem'
       key-file: '/etc/knot-resolver/server-key.pem'

^^^^^^^^^^^^^^^^^^^^^^^^^
Mandatory domain blocking
^^^^^^^^^^^^^^^^^^^^^^^^^

Some jurisdictions mandate blocking access to certain domains.
This can be achieved e.g. by using :option:`rules <rules: <list>>`.
(Or you might use a :ref:`RPZ file <config-local-data-rpz>`, as many resolver implementations accept that format.)

.. code-block:: yaml

   local-data:
     rules:
       - name:
           - example.com.
           - blocked.example.net.
         subtree: nxdomain


.. _example-personal:

==========================
Example: Personal Resolver
==========================

DNS queries can be used to gather data about user behavior.
Knot Resolver can be configured to forward DNS queries elsewhere,
to protect the users from being eavesdropped on by using TLS encryption.

.. warning::

   Latest research has proven that encrypting DNS traffic is not sufficient to protect the users' privacy.
   Therefore, we recommend all users to use a full VPN instead of encrypting *just* DNS queries.
   The following configuration is provided **only for users who are not able to encrypt all their traffic**.
   For more information, please see the following articles:

   - Simran Patil and Nikita Borisov. 2019. What can you learn from an IP? (`slides <https://irtf.org/anrw/2019/slides-anrw19-final44.pdf>`_, `the article itself <https://dl.acm.org/authorize?N687437>`_)
   - `Bert Hubert. 2019. Centralised DoH is bad for Privacy, in 2019 and beyond <https://labs.ripe.net/Members/bert_hubert/centralised-doh-is-bad-for-privacy-in-2019-and-beyond>`_

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Forwarding over TLS protocol (DNS-over-TLS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Forwarding over the TLS protocol protects DNS queries sent out by the resolver.
It can be configured using :ref:`forwarding <config-forward>`, which provides settings for authentication.

.. code-block:: yaml

   forward:
     # encrypted public resolver, for all names
     - subtree: "."
       servers:
         - address:
             - 2001:148f:fffe::1
             - 193.17.47.1
           transport: tls
           hostname: odvr.nic.cz

.. tip::

   See list of `DNS Privacy Test Servers`_ supporting DNS-over-TLS to test your configuration.

.. future

   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   Forwarding to multiple targets
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

   With the use of slice function, it is possible to split the
   .. With the use of :any:`policy.slice` function, it is possible to split the
   entire DNS namespace into distinct "slices". When used in conjunction with
   :ref:`TLS forwarding <tls-forwarding>`, it's possible to forward different queries to different
   .. :ref:`policy.TLS_FORWARD <tls-forwarding>`, it's possible to forward different queries to different
   remote resolvers. As a result no single remote resolver will get complete list
   of all queries performed by this client.

   .. warning::

      Beware that this method has not been scientifically tested and there might be
      types of attacks which will allow remote resolvers to infer more information about the client.
      Again: If possible encrypt **all** your traffic and not just DNS queries!

   .. code-block:: yaml

      policy:
         # TODO

   .. code-block:: lua

      policy.add(policy.slice(
         policy.slice_randomize_psl(),
         policy.TLS_FORWARD({{'192.0.2.1', hostname='res.example.com'}}),
         policy.TLS_FORWARD({
            -- multiple servers can be specified for a single slice
            -- the one with lowest round-trip time will be used
            {'193.17.47.1', hostname='odvr.nic.cz'},
            {'185.43.135.1', hostname='odvr.nic.cz'},
         })
      ))

^^^^^^^^^^^^^^^^^^^^
Non-persistent cache
^^^^^^^^^^^^^^^^^^^^

Knot Resolver's cache contains data its clients queried for.
If you are concerned about attackers who are able to get access to your
computer system in power-off state, and your storage device is not secured by
encryption, you can move the cache to tmpfs_.
See :ref:`config-cache-persistence`.

.. .. raw:: html

..    <h2>Next steps</h2>

.. Congratulations! Your resolver is now up and running and ready to accept queries. For
.. serious deployments, do not forget to read the chapters :ref:`configuration-chapter` and
.. :ref:`operation-chapter`.

.. _`DNS Privacy Test Servers`: https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Test+Servers
.. _tmpfs: https://en.wikipedia.org/wiki/Tmpfs
