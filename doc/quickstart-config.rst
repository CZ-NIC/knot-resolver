.. SPDX-License-Identifier: GPL-3.0-or-later

.. _quickstart-config:

*************
Configuration
*************

.. contents::
   :depth: 1
   :local:

.. note::

   When copy&pasting examples from this manual please pay close
   attention to brackets and also line ordering - order of lines matters.

   The configuration language is in fact Lua script, so you can use full power
   of this programming language. See article
   `Learn Lua in 15 minutes`_ for a syntax overview.

Easiest way to configure Knot Resolver is to paste your configuration into
configuration file ``/etc/knot-resolver/kresd.conf``.
Complete configurations files for examples in this chapter
can be found `here <https://gitlab.labs.nic.cz/knot/knot-resolver/tree/master/etc/config>`_.
The example configuration files are also installed as documentation files, typically in directory ``/usr/share/doc/knot-resolver/examples/`` (their location may be different based on your Linux distribution).
Detailed configuration of daemon and implemented modules can be found in configuration reference:


Listening on network interfaces
===============================

Network interfaces to listen on and supported protocols are configured using :func:`net.listen()` function.

The following configuration instructs Knot Resolver to receive standard unencrypted DNS queries on IP addresses `192.0.2.1` and `2001:db8::1`. Encrypted DNS queries are accepted using DNS-over-TLS protocol on all IP addresses configured on network interface `eth0`, TCP port 853.

.. code-block:: lua

    -- unencrypted DNS on port 53 is default
    net.listen('192.0.2.1')
    net.listen('2001:db8::1')
    net.listen(net.eth0, 853, { kind = 'tls' })

.. warning::

    On machines with multiple IP addresses on the same interface avoid listening on wildcards ``0.0.0.0`` or ``::``.
    Knot Resolver could answer from different IP addresses if the network address ranges
    overlap, and clients would refuse such a response.


Scenario: Internal Resolver
===========================

This is an example of typical configuration for company-internal resolver which is not accessible from outside of company network.

Internal-only domains
^^^^^^^^^^^^^^^^^^^^^

An internal-only domain is a domain not accessible from the public Internet.
In order to resolve internal-only domains a query policy has to be added to forward queries to a correct internal server.
This configuration will forward two listed domains to a DNS server with IP address ``192.0.2.44``.

.. code-block:: lua

    -- define list of internal-only domains
    internalDomains = policy.todnames({'company.example', 'internal.example'})

    -- forward all queries belonging to domains in the list above to IP address '192.0.2.44'
    policy.add(policy.suffix(policy.FLAGS({'NO_CACHE'}), internalDomains))
    policy.add(policy.suffix(policy.STUB({'192.0.2.44'}), internalDomains))

See chapter :ref:`dns-graft` for more details.


.. _ispresolver:

Scenario: ISP Resolver
======================

The following configuration is typical for Internet Service Providers who offer DNS resolver
service to their own clients in their own network. Please note that running a *public DNS resolver*
is more complicated and not covered by this quick start guide.

Limiting client access
^^^^^^^^^^^^^^^^^^^^^^
With exception of public resolvers, a DNS resolver should resolve only queries sent by clients in its own network. This restriction limits attack surface on the resolver itself and also for the rest of the Internet.

In a situation where access to DNS resolver is not limited using IP firewall, you can implement access restrictions using the :ref:`view module <mod-view>` which combines query source information with :ref:`policy rules <mod-policy>`.
Following configuration allows only queries from clients in subnet 192.0.2.0/24 and refuses all the rest.

.. code-block:: lua

    modules.load('view')

    -- whitelist queries identified by subnet
    view:addr('192.0.2.0/24', policy.all(policy.PASS))

    -- drop everything that hasn't matched
    view:addr('0.0.0.0/0', policy.all(policy.DROP))

TLS server configuration
^^^^^^^^^^^^^^^^^^^^^^^^
Today clients are demanding secure transport for DNS queries between client machine and DNS resolver. The recommended way to achieve this is to start DNS-over-TLS server and accept also encrypted queries.

First step is to enable TLS on listening interfaces:

.. code-block:: lua

   net.listen('192.0.2.1', 853, { kind = 'tls' })
   net.listen('2001::db8:1', 853, { kind = 'tls' })

By default a self-signed certificate is generated.
Second step is then obtaining and configuring your own TLS certificates
signed by a trusted CA. Once the certificate was obtained a path to certificate files can be specified using function :func:`net.tls()`:

.. code-block:: lua

    net.tls("/etc/knot-resolver/server-cert.pem", "/etc/knot-resolver/server-key.pem")


Mandatory domain blocking
^^^^^^^^^^^^^^^^^^^^^^^^^

Some jurisdictions mandate blocking access to certain domains. This can be achieved using following :ref:`policy rule <mod-policy>`:

.. code-block:: lua

  policy.add(
        policy.suffix(policy.DENY,
                policy.todnames({'example.com.', 'blocked.example.net.'})))



.. _personalresolver:

Scenario: Personal Resolver
===========================

DNS queries can be used to gather data about user behavior.
Knot Resolver can be configured to forward DNS queries elsewhere,
and to protect them from eavesdropping by TLS encryption.

.. warning::

    Latest research has proven that encrypting DNS traffic is not sufficient to protect privacy of users.
    For this reason we recommend all users to use full VPN instead of encrypting *just* DNS queries.
    Following configuration is provided **only for users who cannot encrypt all their traffic**.
    For more information please see following articles:

    - Simran Patil and Nikita Borisov. 2019. What can you learn from an IP? (`slides <https://irtf.org/anrw/2019/slides-anrw19-final44.pdf>`_, `the article itself <https://dl.acm.org/authorize?N687437>`_)
    - `Bert Hubert. 2019. Centralised DoH is bad for Privacy, in 2019 and beyond <https://labs.ripe.net/Members/bert_hubert/centralised-doh-is-bad-for-privacy-in-2019-and-beyond>`_


Forwarding over TLS protocol (DNS-over-TLS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Forwarding over TLS protocol protects DNS queries sent out by resolver.
It can be configured using :ref:`policy.TLS_FORWARD <tls-forwarding>` function which provides methods for authentication.
See list of `DNS Privacy Test Servers`_ supporting DNS-over-TLS to test your configuration.

Read more on :ref:`tls-forwarding`.


Forwarding to multiple targets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
With the use of :any:`policy.slice` function, it is possible to split the
entire DNS namespace into distinct "slices". When used in conjunction with
:ref:`policy.TLS_FORWARD <tls-forwarding>`, it's possible to forward different queries to different
remote resolvers. As a result no single remote resolver will get complete list
of all queries performed by this client.

.. warning::

    Beware that this method has not been scientifically tested and there might be
    types of attacks which will allow remote resolvers to infer more information about the client.
    Again: If possible encypt **all** your traffic and not just DNS queries!

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

Non-persistent cache
^^^^^^^^^^^^^^^^^^^^
Knot Resolver's cache contains data clients queried for.
If you are concerned about attackers who are able to get access to your
computer system in power-off state and your storage device is not secured by
encryption you can move the cache to tmpfs_.
See chapter :ref:`cache_persistence`.


.. raw:: html

   <h2>Next steps</h2>

Congratulations! Your resolver is now up and running and ready for queries. For
serious deployments do not forget to read :ref:`configuration-chapter` and
:ref:`operation-chapter` chapters.

.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
.. _`DNS Privacy Test Servers`: https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Test+Servers
.. _tmpfs: https://en.wikipedia.org/wiki/Tmpfs
