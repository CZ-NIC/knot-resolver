.. _startguide:

Welcome to Knot Resolver Quick Start Guide! This chapter will guide you through first installation and basic setup recommended for your use-case.

Before we start let us explain basic conventions used in this text:

This is Linux/Unix shell command to be executed and an output from this command:

.. code-block:: bash

    $ echo "This is output!"
    This is output!
    $ echo "We use sudo to execute commands as root:"
    We use sudo to execute commands as root:
    $ sudo id
    uid=0(root) gid=0(root) groups=0(root)

Snippets from Knot Resolver's configuration file **do not start with $ sign** and look like this:

.. code-block:: lua

    -- this is a comment
    -- following line will start listening on IP address 192.0.2.1 port 53
    net.listen('192.0.2.1')


************
Installation
************

As a first step add following repositories with the **latest version** of Knot Resolver. Please note that the packages available in distribution's repositories are often outdated, especially in Debian and Ubuntu repositories, and this guide might not work with their old versions.

**Arch Linux**

Use
`knot-resolver <https://aur.archlinux.org/packages/knot-resolver/>`_
package from AUR_.

**CentOS**

.. code-block:: bash

    $ sudo yum install -y https://secure.nic.cz/files/knot-resolver/knot-resolver-release.el.rpm
    $ sudo yum install -y knot-resolver

**Debian/Ubuntu**

.. code-block:: bash

    $ wget https://secure.nic.cz/files/knot-resolver/knot-resolver-release.deb
    $ sudo dpkg -i knot-resolver-release.deb
    $ sudo apt update
    $ sudo apt install -y knot-resolver

**Fedora**

.. code-block:: bash

    $ sudo dnf install -y https://secure.nic.cz/files/knot-resolver/knot-resolver-release.fedora.rpm
    $ sudo dnf install -y knot-resolver

**OpenSUSE Leap / Tumbleweed**

Add the `OBS <https://en.opensuse.org/Portal:Build_Service>`_ package repository `home:CZ-NIC:knot-resolver-latest <https://build.opensuse.org/package/show/home:CZ-NIC:knot-resolver-latest/knot-resolver>`_ to your system.


*******
Startup
*******

Knot Resolver can run in multiple independent instances (processes), where each `single instance`_ of Knot Resolver will utilize at most single CPU core on your machine. If your machine handles a lot of DNS traffic, run `multiple instances`_.

Advantage of using multiple instances is that a problem in a single instance will not affect others, so a single instance crash will not bring whole DNS resolver service down.

Single instance
===============

The simplest way to run single instance of
Knot Resolver is to use provided Knot Resolver's Systemd integration:

.. code-block:: bash

   $ sudo systemctl start kresd@1.service

See logs and status of running instance with ``systemctl status kresd@1.service`` command. For more information about Systemd integration see ``man kresd.systemd``.

.. warning::

    ``kresd@*.service`` is not enabled by default, thus Knot Resolver won't start automatically after reboot.
    To start and enable service in one command use ``systemctl enable --now kresd@1.service``


Multiple instances
==================

Knot Resolver can run in multiple independent processes, all sharing the same configuration and cache. Incomming queries will be distributed among all instances automatically.

To use up all resources, for instance of 4 CPUs system, the best way is to run four instances at a time.

.. code-block:: bash

    $ sudo systemctl start kresd@1.service
    $ sudo systemctl start kresd@2.service
    $ sudo systemctl start kresd@3.service
    $ sudo systemctl start kresd@4.service

or simpler way

.. code-block:: bash

    $ sudo systemctl start kresd@{1..4}.service


Testing
=======
After installation and first startup, Knot Resolver's default configuration accepts queries on loopback interface. This allows you to test that the installation and service startup were successful before continuing with configuration.

For instance, you can use DNS lookup utility ``kdig`` to send DNS queries. The ``kdig`` command is provided by following packages:

============   =================
Distribution   package with kdig
============   =================
Arch           knot
CentOS         knot-utils
Debian         knot-dnsutils
Fedora         knot-utils
OpenSUSE       knot-utils
Ubuntu         knot-dnsutils
============   =================

The following query should return list of Root Name Servers:

.. code-block:: bash

    $ kdig +short @localhost . NS
    a.root-servers.net.
    ...
    m.root-servers.net.


*************
Configuration
*************

.. contents::
   :depth: 1
   :local:

.. note::

   Copy&pasting examples from this manual is sufficient for normal use-cases.
   Please pay close attention to brackets, especially
   in more complex configurations like :func:`policy.add` and :func:`view:addr`.

   If you want to use full power of configuration language, see article
   `Learn Lua in 15 minutes`_ for a syntax overview.

Easiest way to configure Knot Resolver is to paste your configuration into
configuration file ``/etc/knot-resolver/kresd.conf``.
Complete configurations files for examples in this chapter
can be found `here <https://gitlab.labs.nic.cz/knot/knot-resolver/tree/master/etc/config>`_.
The example configuration files are also installed as documentation files, typically in directory ``/usr/share/doc/knot-resolver/examples/`` (their location may be different based on your Linux distribution).
Detailed configuration of daemon and implemented modules can be found in configuration reference:

- :ref:`Daemon configuration <daemon>`
- :ref:`Modules configuration <modules-implemented>`



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

Cache configuration
===================

Sizing
^^^^^^

For personal use-cases and small deployments cache size around 100 MB is more than enough.

For large deployments we recommend to run Knot Resolver on a dedicated machine, and to allocate 90% of machine's free memory for resolver's cache.

For example, imagine you have a machine with 16 GB of memory.
After machine restart you use command ``free -m`` to determine amount of free memory (without swap):

.. code-block:: bash

  $ free -m
                total        used        free
  Mem:          15907         979       14928

Now you can configure cache size to be 90% of the free memory 14 928 MB, i.e. 13 453 MB:

.. code-block:: lua

   -- 90 % of free memory after machine restart
   cache.size = 13453 * MB

.. _quick-cache_persistence:

Cache persistence
^^^^^^^^^^^^^^^^^
By default the cache is saved on a persistent storage device
so the content of the cache is persisted during system reboot.
This usually leads to smaller latency after restart etc.,
however in certain situations a non-persistent cache storage might be preferred, e.g.:

  - Resolver handles high volume of queries and I/O performance to disk is too low.
  - Threat model includes attacker getting access to disk content in power-off state.
  - Disk has limited number of writes (e.g. flash memory in routers).

If non-persistent cache is desired configure cache directory to be on
tmpfs_ filesystem, a temporary in-memory file storage.
The cache content will be saved in memory, and thus have faster access
and will be lost on power-off or reboot.

In most of the Unix-like systems ``/tmp`` and ``/var/run`` are commonly mounted to *tmpfs*.
This allows us to move cache e.g. to directory ``/tmp/knot-resolver``:

.. code-block:: lua

   -- do not forget the lmdb:// prefix before absolute path
   cache.storage = 'lmdb:///tmp/knot-resolver'

If the temporary directory doesn't exist it will be created automatically with access only
for ``knot-resolver`` user and group.


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
    policy.add(policy.suffix(policy.FORWARD({'192.0.2.44'}), internalDomains))


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


Performance tunning
^^^^^^^^^^^^^^^^^^^
For very high-volume traffic do not forget to run `multiple instances`_ and consider using :ref:`non-persistent cache storage <quick-cache_persistence>`.

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
See previous chapter :ref:`quick-cache_persistence`.


**********
Monitoring
**********

Statistics for monitoring purposes are available in :ref:`mod-stats` module. If you want to export these statistics to a central system like Graphite, Metronome, InfluxDB or any other compatible storage see :ref:`mod-graphite`. Statistics can also be made available over HTTP protocol in Prometheus format, see module providing :ref:`mod-http`, Prometheus is supported by ``webmgmt`` endpoint.

More extensive logging can be enabled using :ref:`mod-bogus_log` module.

If none of these options fits your deployment or if you have special needs you can configure your own checks and exports using :ref:`async-events`.

.. note::

  Please remember that each Knot Resolver instance keeps its own statistics, and instances can be started and stopped dynamically. This might affect your data postprocessing procedures.

*********
Upgrading
*********
Before upgrade please see :ref:`upgrading` guide for each respective version.



.. _SNI: https://en.wikipedia.org/wiki/Server_Name_Indication
.. _AUR: https://wiki.archlinux.org/index.php/Arch_User_Repository
.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
.. _`DNS Privacy Test Servers`: https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Test+Servers
.. _lua-filesystem: https://keplerproject.github.io/luafilesystem//manual.html#reference
.. _KnotDNS: https://www.knot-dns.cz/
.. _tmpfs: https://en.wikipedia.org/wiki/Tmpfs
