.. _startguide:

************
Installation
************

- :ref:`build`
- `All downloadable packages <https://secure.nic.cz/files/knot-resolver>`_


.. Warning::

    Packages available in distribution's repositories are often outdated,
    especially in **Debian** and **Ubuntu** repositories.

We recommend using these official upstream repositories with the **latest version** of Knot Resolver.

**Debian/Ubuntu**

.. code-block:: bash

    ~$ wget https://secure.nic.cz/files/knot-resolver/knot-resolver-release.deb
    ~$ dpkg -i knot-resolver-release.deb
    ~$ apt update && apt install -y knot-resolver

**CentOS**

.. code-block:: bash

    ~$ yum install -y https://secure.nic.cz/files/knot-resolver/knot-resolver-release.el.rpm
    ~$ yum install -y knot-resolver

**Fedora**

.. code-block:: bash

    ~$ dnf install -y https://secure.nic.cz/files/knot-resolver/knot-resolver-release.fedora.rpm
    ~$ dnf install -y knot-resolver

**OpenSUSE Leap / Tumbleweed**

Add the *OBS* package repository `home:CZ-NIC:knot-resolver-latest <https://build.opensuse.org/package/show/home:CZ-NIC:knot-resolver-latest/knot-resolver>`_ to your system.

**Arch Linux**

`Knot-resolver <https://aur.archlinux.org/packages/knot-resolver/>`_
package is maintained in **AUR**. It can be installed by using AUR helper,
for instance, ``yay``

.. code-block:: bash

    ~$ yay -S knot-resolver


*************
Configuration
*************

.. contents::
   :depth: 1
   :local:

**Detailed configuration of daemon and modules.**

- :ref:`Daemon configuration <daemon>`
- :ref:`Modules configuration <modules>`

.. note::

   The configuration syntax is **Lua** language.

**Startup configuration**

To set startup configuration, paste required configuration to ``/etc/knot-resolver/kresd.conf``
configuration file or run Knot Resolver with ``-c`` parameter to set path to configuration file.

**Interactive / Dynamic configuration**

Every Knot Resolver instance has its own *unix domain socket*.

For instance, you start Knot Resolver using systemd

.. code-block:: bash

    ~$ systemctl start kresd@1.service


Then the related unix domain socket will be available on ``/run/knot-resolver/control@1``

Connection to the socket can be made by ``socat`` or ``netcat`` through command line

.. code-block:: bash

    ~$ socat - /run/knot-resolver/control@1
    ~$ nc -U /run/knot-resolver/control@1

When successfully connected to a socket, the command line should change to something like ``>``.
Then you can interact with Knot Resolver to list configuration or set a new one.

There are some useful commands.

.. code-block:: bash

    > help()            # shows help
    > net.interfaces()  # lists available interfaces
    > net.list()        # lists running network services

==================
Bind to interfaces
==================

Knot Resolver can listen on multiple interfaces that are defined in configuration.

.. code-block:: lua

    net = {'192.168.1.1','fc00::1:1'}

Default port is ``53``. Port can be specified by separating it by ``@`` from ip address. For example ``'127.0.0.1@5353'``.


Available interfaces can be listed

.. code-block:: bash

   > net.interfaces()
   [eth1] => {
      [addr] => {
         [1] => 192.168.1.1
         [2] => fc00::1:1
         [4] => fe80::1:1
      }
   }
   [lo] => {
      [addr] => {
         [1] => 127.0.0.1
         [2] => ::1
      }
   }

``net.eth1.addr[1]`` refers to ``192.168.1.1`` and ``net.eth1.addr[2]`` refers to ``fc00::1:1``

.. code-block:: lua

    net = {net.eth1.addr[1],net.eth1.addr[2]}

.. warning::

    On machines with multiple IP addresses avoid listening on wildcards ``0.0.0.0`` or ``::``.
    Knot Resolver could answer from different IP addresses if the network address ranges
    overlap, and clients would probably refuse such a response.


=================
Internal Resolver
=================

How to configure Knot Resolver to resolve internal-only domain.

Forward internal-only domain
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For instance, ``company.example`` is the internal-only domain which is not available from the public Internet.
To resolve internal-only domain, e.g. ``company.exmaple`` a query policy to forward query has to be added.
The followind example will add query policy that will trigger ``FORWARD`` action based on suffix of a domain.
This configuration will forward everything below ``company.example`` domain to ``192.168.1.2`` IP address, port ``443``.

.. code-block:: lua

    -- policy module is required for query policy configuration
    modules = { 'policy' }

    -- forward all queries below 'company.example' to '192.168.1.2@443'
    policy.add(policy.suffix(policy.FORWARD('192.168.1.2@443'), {todname('company.example')}))


Example ``kresd.conf``
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

    -- bind to interfaces
    net = {'192.168.1.1','fc00::1:1'}

    -- load policy module
    modules = { 'policy' }

    -- forward all queries below suffix 'company.example' to '192.168.1.2@443'
    policy.add(policy.suffix(policy.FORWARD('192.168.1.2@443'), {todname('company.example')}))


.. _personalresolver:

====================================
Personal privacy-preserving Resolver
====================================

TLS server configuration
^^^^^^^^^^^^^^^^^^^^^^^^
.. Warning::

    By default a self-signed certificate is generated.
    For serious deployments it is strongly recommended to
    configure your own TLS certificates signed by a trusted CA.
    This can be done by using function ``net.tls()``.

.. code-block:: lua

    net.tls("/etc/knot-resolver/server-cert.pem", "/etc/knot-resolver/server-key.pem")

Calling this function without parameters prints configured TLS paths.

Forwarding over TLS protocol (DNS-over-TLS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

More examples on :ref:`tls-examples`.

CA+hostname authentication
``````````````````````````
Traditional PKI authentication requires server to present certificate
with specified hostname, which is issued by one of trusted CAs.

.. code-block:: lua

    -- forward all queries over TLS to the specified server
    policy.add(policy.all(
       policy.TLS_FORWARD({
          {'2001:DB8::d0c', hostname='res.example.com', ca_file='/etc/knot-resolver/tlsca.crt'}
       })
    ))

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

Moving cache to tmpfs
^^^^^^^^^^^^^^^^^^^^^
Moving cache to temporary file storage.
Data is stored in volatile memory instead of a persistent storage device.
On reboot, everything stored in *tmpfs* will be lost.

For example, in most of the Unix-like systems ``/tmp``, ``/var/lock`` and ``/var/run`` are commonly *tmpfs*.
You can check file system type by ``df -T /tmp`` command.

Move cache storage to ``/tmp/knot-resolver``

.. code-block:: lua

   cache.storage = 'lmdb:///tmp/knot-resolver'

Check cache storage

.. code-block:: bash

   > cache.current_storage
   lmdb:///tmp/knot-resolver

Example ``kresd.conf``
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

   -- bind to interfaces
   net = {'192.168.1.1','fc00::1:1'}

   -- configure TLS server
   net.tls(net.tls("/etc/knot-resolver/server-cert.pem", "/etc/knot-resolver/server-key.pem"))

   -- Move cache to '/tmp/knot-resolver' tmpfs
   cache.storage = 'lmdb:///tmp/knot-resolver'

   -- load policy module
   modules = { 'policy' }

   -- forward over TLS
   policy.add(policy.all(
       policy.TLS_FORWARD({
          {'2001:DB8::d0c', hostname='res.example.com', ca_file='/etc/knot-resolver/tlsca.crt'},
          {'192.0.2.1', pin_sha256={'YQ=='}
       })
    ))

   -- forwarding to multiple targets
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

.. _ispresolver:

============
ISP Resolver
============

Limiting client access
^^^^^^^^^^^^^^^^^^^^^^
More on :ref:`mod-view`

The current implementation is best understood as three separate rule chains:
vanilla :func:`policy.add()`, :func:`view:tsig()` and :func:`view:addr`.
For each request the rules in these chains get tried one by one until a non-chain
policy action gets executed.

View module allows you to combine query source information with policy rules.

.. code-block:: lua

    modules = { 'view' }

    -- Block local IPv4 clients (ACL like)
    view:addr('127.0.0.1', policy.all(policy.DENY))

    -- Drop queries with suffix match for remote client
    view:addr('10.0.0.0/8', policy.suffix(policy.TC, policy.todnames({'example.com'})))

    -- Whitelist queries identified by TSIG key
    view:tsig('\5mykey', policy.all(policy.PASS))


Mandatory domain blocking
^^^^^^^^^^^^^^^^^^^^^^^^^

RPZ
```
DNS Response Policy Zones Blacklist

.. code-block:: lua

   policy.add(policy.rpz(policy.DENY, 'blacklist.rpz'))


Hand-made
`````````
Hand-made Blacklist

.. code-block:: lua

   --

Max cache size
^^^^^^^^^^^^^^
Maximal cache size can be larger than available RAM,
least frequently accessed records will be paged out.
For large cache size we don't need to flush cache often.

.. code-block:: lua

   cache.size = 4 * GB


Statistics
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

    -- Statistics collector is a module
    > modules.load('stats')

    -- Enumerate metrics
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
    modules.load('stats')

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

    modules.load('stats')

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


Example ``kresd.conf``
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

    -- bind to interfaces
    net = {'192.168.1.1','fc00::1:1'}

    -- set max cache size
    cache.size = 4 * GB

    -- modules
    modules = {
        'view',
        'stats'
    }

    -- log statistics every second
    local stat_id = event.recurrent(1 * second, function(evid)
        log(table_print(stats.list()))
    end)

    -- stop printing statistics after first minute
    event.after(1 * minute, function(evid)
            event.cancel(stat_id)
    end)

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

    -- Apply RPZ for all clients, default rule is DENY
    policy.add(policy.rpz(policy.DENY, 'blacklist.rpz'))

    -- Block local IPv4 clients (ACL like)
    view:addr('127.0.0.1', policy.all(policy.DENY))

    -- Drop queries with suffix match for remote client
    view:addr('10.0.0.0/8', policy.suffix(policy.TC, policy.todnames({'example.com'})))

    -- Force all clients from 192.168.2.0/24 to TCP
    view:addr('192.168.2.0/24', policy.all(policy.TC))

    -- Whitelist queries identified by TSIG key
    view:tsig('\5mykey', policy.all(policy.PASS))


**********
How to Run
**********

===============
Single instance
===============

If you're using our packages, the simplest way to run **single instance** of Knot Resolver is to use provided Knot Resolver's ``systemd`` integration.

For help run ``man kresd.systemd``

.. code-block:: bash

   ~$ systemctl start kresd@1.service

See logs and status of running instance with ``systemctl status kresd@1.service`` command.

.. Note:: The instance of Knot Resolver is single process incapable of multithreading.

==================
Multiple instances
==================

Knot Resolver can run in multiple independent processes, all sharing the same interface socket and cache.

Because single running instance of Knot Resolver is incapable of multithreading, to use up of all resources, for instance, of 4 CPUs system, the best way is to run four instances at a time.

.. code-block:: bash

    ~$ systemctl start kresd@1.service
    ~$ systemctl start kresd@2.service
    ~$ systemctl start kresd@3.service
    ~$ systemctl start kresd@4.service

or simpler way

.. code-block:: bash

    ~$ systemctl start kresd@{1..4}.service


.. _SNI: https://en.wikipedia.org/wiki/Server_Name_Indication
.. _closures: https://www.lua.org/pil/6.1.html