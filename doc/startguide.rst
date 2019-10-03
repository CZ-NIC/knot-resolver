.. _startguide:

************
Installation
************

We recommend using these official upstream repositories with the **latest version** of Knot Resolver.

.. warning::

    Packages available in distribution's repositories are often outdated,
    especially in **Debian** and **Ubuntu** repositories.

**Debian/Ubuntu**

.. code-block:: bash

    $ wget https://secure.nic.cz/files/knot-resolver/knot-resolver-release.deb
    $ dpkg -i knot-resolver-release.deb
    $ apt update
    $ apt install -y knot-resolver

**CentOS**

.. code-block:: bash

    $ yum install -y https://secure.nic.cz/files/knot-resolver/knot-resolver-release.el.rpm
    $ yum install -y knot-resolver

**Fedora**

.. code-block:: bash

    $ dnf install -y https://secure.nic.cz/files/knot-resolver/knot-resolver-release.fedora.rpm
    $ dnf install -y knot-resolver

**OpenSUSE Leap / Tumbleweed**

Add the *OBS* package repository `home:CZ-NIC:knot-resolver-latest <https://build.opensuse.org/package/show/home:CZ-NIC:knot-resolver-latest/knot-resolver>`_ to your system.

**Arch Linux**

`Knot-resolver <https://aur.archlinux.org/packages/knot-resolver/>`_
package for Arch Linux is maintained in AUR_.


*****************
Run Knot Resolver
*****************

After installation, Knot Resolver's default configuration should work for loopback
queries. This allows you to test that installation and service setup works before
managing configuration.


Single instance
===============

If you're using our packages, the simplest way to run **single instance** of
Knot Resolver is to use provided Knot Resolver's ``systemd`` integration.

.. note:: The instance of Knot Resolver is a single process incapable of multithreading.

For help run ``man kresd.systemd``

.. code-block:: bash

   $ systemctl start kresd@1.service

See logs and status of running instance with ``systemctl status kresd@1.service`` command.


.. warning::

    ``kresd@*.service`` is not enabled by default, thus Knot Resolver won't start automatically after reboot.
    To start and enable service in one command use ``systemctl enable --now kresd@1.service``


Multiple instances
==================

Knot Resolver can run in multiple independent processes, all sharing the same interface socket and cache.

Because single running instance of Knot Resolver is incapable of multithreading, to use up of all resources,
for instance, of 4 CPUs system, the best way is to run four instances at a time.

.. code-block:: bash

    $ systemctl start kresd@1.service
    $ systemctl start kresd@2.service
    $ systemctl start kresd@3.service
    $ systemctl start kresd@4.service

or simpler way

.. code-block:: bash

    ~$ systemctl start kresd@{1..4}.service


*************
Configuration
*************

.. contents::
   :depth: 1
   :local:

.. note::

   The configuration syntax is **Lua** language.
   Please pay close attention to brackets especially in more complex configurations like :func:`policy.add` and :func:`view:addr`.
   If you are not familiar with Lua you can read `Learn Lua in 15 minutes`_ for a syntax overview.

Detailed configuration of daemon and implemented modules:

- :ref:`Daemon configuration <daemon>`
- :ref:`Modules configuration <modules-implemented>`

Easiest way to configure Knot Resolver is to paste your configuration to
``/etc/knot-resolver/kresd.conf`` configuration file loaded on resolver's startup.
You can easily save configuration files and switch between them.
All configuration files of following examples and more are stored in `/etc/config`_ directory.

Bind to interfaces
==================

Network interfaces to listen on and supported protocols are configured using :func:`net.listen()` function.

Following configuration listens for plain DNS queries on IP addresses `192.168.1.1` and `2001:db8::1`, and for DNS-over-TLS queries on all IP addresses configured on network interface `eth0`.

.. code-block:: lua

    -- examples
    net.listen('192.168.1.1')
    net.listen('2001:db8::1')
    net.listen(net.eth0, 853, { kind = 'tls' })

.. warning::

    On machines with multiple IP addresses on the same interface avoid listening on wildcards ``0.0.0.0`` or ``::``.
    Knot Resolver could answer from different IP addresses if the network address ranges
    overlap, and clients would probably refuse such a response.


Internal Resolver
=================

How to configure Knot Resolver to resolve internal-only domains.

Forward internal-only domain
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For instance, ``company.example`` is the internal-only domain which is not available from the public Internet.
To resolve internal-only domain, e.g. ``company.example`` a query policy to forward query has to be added.
The followind example will add query policy that will trigger ``FORWARD`` action based on suffix of a domain.
This configuration will forward everything below ``company.example`` domain to ``192.168.1.2`` IP address, port ``443``.

.. code-block:: lua

    -- define internal only domains
    internalDomains = policy.todnames({'company.example', 'internal.example'})

    -- forward all queries below 'internalDomains' to '192.168.1.2@443'
    policy.add(policy.suffix(policy.FORWARD({'192.168.1.2@443'}), internalDomains))


.. _personalresolver:


Personal privacy-preserving Resolver
====================================

Forwarding over TLS protocol (DNS-over-TLS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Forwarding over TLS protocol protects queries send out by resolver.
It is done by :func:`policy.TLS_FORWARD()` function which provides methods for authentication.
There is a list of `DNS Privacy Test Servers`_ supporting DNS-over-TLS to test your configuration.

CA+hostname authentication
``````````````````````````
Traditional PKI authentication requires server to present certificate
with specified hostname, which is issued by one of trusted CAs.

.. code-block:: lua

    -- forward all queries over TLS to the specified server
    policy.add(policy.all(
       policy.TLS_FORWARD({
          {'2001:DB8::d0c', hostname='res.example.com'}
       })
    ))

The system-wide CA storage is used, which should cover most of use cases.
More on :func:`policy.TLS_FORWARD()`


Key-pinned authentication
``````````````````````````
Instead of CAs, you can specify hashes of accepted certificates in ``pin_sha256``.
They are in the usual format -- base64 from sha256.
You may still specify ``hostname`` if you want SNI_ to be sent.

.. code-block:: lua

    -- forward all queries over TLS to the specified server
    policy.add(policy.all(
       policy.TLS_FORWARD({
          {'192.0.2.1', pin_sha256={'YQ=='}
       })
    ))

Forwarding to multiple targets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
With the use of :any:`policy.slice` function, it is possible to split the
entire DNS namespace into distinct slices. When used in conjunction with
``policy.TLS_FORWARD``, it's possible to forward different queries to different
targets.

.. code-block:: lua

    policy.add(policy.slice(
       policy.slice_randomize_psl(),
       policy.TLS_FORWARD({{'192.0.2.1', hostname='res.example.com'}}),
       -- multiple servers can be specified for a single slice
       -- the one with lowest round-trip time will be used
       policy.TLS_FORWARD({
          {'193.17.47.1', hostname='odvr.nic.cz'},
          {'185.43.135.1', hostname='odvr.nic.cz'},
       })
    ))

Non-persistent cache
^^^^^^^^^^^^^^^^^^^^

Knot Resolver's cache contains data clients queried for.
By default the cache is saved on persistent storage device
it means content in cache is persisted during power-off and reboot.

If you are concerned about attackers who are able to get access to your
computer system in power-off state and your storage device is not secured by
encryption you can move the cache to **tmpfs**, temporary file storage.
The cache content will be saved in memory and lost on power-off or reboot.
In most of the Unix-like systems ``/tmp``, ``/var/lock`` and ``/var/run`` are commonly *tmpfs*.
Directory for resolver can be configured by ``systemd-tmpfiles`` to be automatically created on boot.

Copy Knot Resolver's ``tmpfiles.d`` configuration to ``/etc/tmpfiles.d``.

.. code-block:: bash

   $ cp /usr/lib/tmpfiles.d/knot-resolver.conf /etc/tmpfiles.d/knot-resolver.conf

Add directory rules to ``knot-resolver.conf``.

.. code-block:: bash

   $ echo 'd /tmp/knot-resolver 0750 knot-resolver knot-resolver - -' | sudo tee -a /etc/tmpfiles.d/knot-resolver.conf

The file should look like this

.. code-block:: bash

   $ cat /etc/tmpfiles.d/knot-resolver.conf
   # tmpfiles.d(5) directories for knot-resolver (kresd)
   # Type Path                     Mode UID           GID           Age Argument
     d     /run/knot-resolver       0750 root          root          -   -
     d     /var/cache/knot-resolver 0750 knot-resolver knot-resolver -   -
     d     /tmp/knot-resolver       0750 knot-resolver knot-resolver -   -

You can reboot system to check if directory was created and then cache can be moved to ``/tmp/knot-resolver``

.. code-block:: lua

   cache.storage = 'lmdb:///tmp/knot-resolver'


TLS server configuration
^^^^^^^^^^^^^^^^^^^^^^^^

This allows clients to send queries to your resolver
using DNS-over-TLS. It does not protect queries send out by your resolver.
To protect queries send out by your resolver DNS forwarding over
DNS-over-TLS needs to be configured.

Enable tls on listening interfaces.

.. code-block:: lua

   net.listen('192.168.1.1', 853, { kind = 'tls' })
   net.listen('fc00::1:1', 853, { kind = 'tls' })


.. Warning::

    By default a self-signed certificate is generated.
    For serious deployments it is strongly recommended to
    configure your own TLS certificates signed by a trusted CA.
    This can be done by using function :func:`net.tls()`.

.. code-block:: lua

    net.tls("/etc/knot-resolver/server-cert.pem", "/etc/knot-resolver/server-key.pem")

.. _ispresolver:

ISP Resolver
============

Limiting client access
^^^^^^^^^^^^^^^^^^^^^^

The current implementation is best understood as three separate rule chains:
vanilla :func:`policy.add()`, :func:`view:tsig()` and :func:`view:addr`.
For each request the rules in these chains get tried one by one until a non-chain
policy action gets executed.

View module allows you to combine query source information with policy rules.

.. code-block:: lua

    modules = { 'view' }

    -- block local IPv4 clients (ACL like)
    view:addr('127.0.0.1', policy.all(policy.DENY))

    -- brop queries with suffix match for remote client
    view:addr('10.0.0.0/8', policy.suffix(policy.TC, policy.todnames({'example.com'})))

    -- whitelist queries identified by TSIG key
    view:tsig('\5mykey', policy.all(policy.PASS))


Mandatory domain blocking
^^^^^^^^^^^^^^^^^^^^^^^^^

RPZ
```
DNS Response Policy Zones Blacklist

.. code-block:: lua

   policy.add(policy.rpz(policy.DENY, 'blacklist.rpz'))


Max cache size
^^^^^^^^^^^^^^
Maximal cache size can be larger than available RAM,
least frequently accessed records will be paged out.
For large cache size we don't need to flush cache often.

.. code-block:: lua

   cache.size = 4 * GB


..   Statistics
    ^^^^^^^^^^

    Worker is a service over event loop that tracks and schedules outstanding queries,
    you can see the statistics or schedule new queries.

    .. code-block:: lua

       -- return table of worker statistics
       > worker.stats()

       -- return table of low-level cache statistics
       > cache.stats()


    ``worker.stats() cache.stats()`` commands can be executed synchronously over all forks.
    Results are returned as a table ordered as forks.
    Expression inserted to ``map ''`` can be any valid expression in Lua.

    .. code-block:: lua

        > map 'worker.stats()'


    :ref:`mod-stats` gathers various counters from the query resolution and server internals,
    and offers them as a key-value storage :func:`stats.list()`.

    .. code-block:: lua

        -- statistics collector is a module
        > modules.load('stats')

        -- enumerate metrics
        > stats.list()


Monitoring/logging
^^^^^^^^^^^^^^^^^^

Lua supports a concept called `closures`_, this is extremely useful for scripting actions upon various events,
say for example - publish statistics each minute and so on.
Here's an example of an anonymous function with :func:`event.recurrent()`.

.. note::

    Each scheduled event is identified by a number valid for the duration of the event,
    you may use it to cancel the event at any time.

.. code-block:: lua

    -- load module for statistics
    modules = { 'stats' }

    -- log statistics every second
    local stat_id = event.recurrent(1 * second, function(evid)
        log(table_print(stats.list()))
    end)

    -- stop printing statistics after first minute
    event.after(1 * minute, function(evid)
        event.cancel(stat_id)
    end)

If you need to persist state between events, encapsulate even handle in closure
function which will provide persistent variable (called ``previous``):

.. code-block:: lua

    -- load module for statistics
    modules = { 'stats' }

    -- make a closure, encapsulating counter
    function speed_monitor()
            local previous = stats.list()
            -- monitoring function
            return function(evid)
                    local now = stats.list()
                    local total_increment = now['answer.total'] - previous['answer.total']
                    local slow_increment = now['answer.slow'] - previous['answer.slow']
                    if slow_increment / total_increment > 0.05 then
                            log('WARNING! More than 5 %% of queries was slow!')
                    end
                    previous = now  -- store current value in closure
             end
    end

    -- speed monitor every minute
    local monitor_id = event.recurrent(1 * minute, speed_monitor())


.. _SNI: https://en.wikipedia.org/wiki/Server_Name_Indication
.. _closures: https://www.lua.org/pil/6.1.html
.. _AUR: https://wiki.archlinux.org/index.php/Arch_User_Repository
.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
.. _`DNS Privacy Test Servers`: https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Test+Servers
.. _`/etc/config`: https://github.com/CZ-NIC/knot-resolver/tree/master/etc/config