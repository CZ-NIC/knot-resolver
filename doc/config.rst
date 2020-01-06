.. _config-syntax:

Files and syntax
================

Configuration file is named ``/etc/knot-resolver/kresd.conf`` and is read when you execute Knot Resolver using systemd commands described in section :ref:`startup`. [#]_


The syntax for options is like follows: ``group.option = value`` or ``group.action(parameter1, parameter2)``. You can also comment using a ``--`` prefix.

Following example sets cache size and starts listening for unencrypted and also encrypted DNS queries on IP address 192.0.2.1.

.. code-block:: lua

        cache.size = 10 * MB
        -- this is a comment: listen for unencrypted queries
        net.listen('192.0.2.1')
        -- another comment: listen for queries encrypted using TLS on port 853
        net.listen('192.0.2.1', 853, { kind = 'tls' })

.. tip:: The configuration and CLI syntax is Lua language which allows great
   flexibility. Luckily you do not need to learn Lua, copy&pasting examples
   from this manual is sufficient for normal use-cases. Just pay close
   attention to brackets.

   If you want to use full power of configuration language see article
   `Learn Lua in 15 minutes`_ for a syntax overview.


.. [#] If you decide to run binary ``/usr/sbin/kresd`` manually (instead of using systemd) do not forget to specify ``-c`` option with path to configuration file, otherwise ``kresd`` will read file named ``config`` from its current working directory.

.. include:: ../daemon/bindings/net.rst
.. include:: ../daemon/bindings/cache.rst
.. include:: ../daemon/lua/trust_anchors.rst

Multiple instances
==================

Knot Resolver can utilize multiple CPUs running in multiple independent instances (processes), where each process utilizes at most single CPU core on your machine. If your machine handles a lot of DNS traffic run multiple instances.

All instances typically share the same configuration and cache, and incomming queries are automatically distributed by operating system among all instances.

Advantage of using multiple instances is that a problem in a single instance will not affect others, so a single instance crash will not bring whole DNS resolver service down.

.. tip:: For maximum performance, there should be as many kresd processes as
   there are available CPU threads.

To run multiple instances, use a different identifier after `@` sign for each instance, for
example:

.. code-block:: bash

   $ systemctl start kresd@1.service
   $ systemctl start kresd@2.service
   $ systemctl start kresd@3.service
   $ systemctl start kresd@4.service

With the use of brace expansion in BASH the equivalent command looks like this:

.. code-block:: bash

   $ systemctl start kresd@{1..4}.service

For more details see ``kresd.systemd(7)``.


Zero-downtime restarts
----------------------
When using `multiple instances`_, it is also possible to do a rolling
restart with zero downtime of the service. This can be done by restarting
only a subset of the processes at a time.

On a system with 4 instances we can restart them one-by-one:

.. code-block:: bash

   $ systemctl restart kresd@1.service
   $ systemctl restart kresd@2.service
   $ systemctl restart kresd@3.service
   $ systemctl restart kresd@4.service

At any given time only a single instance is stopped and restarted so remaining three instances continue to service clients.


.. _instance-specific-configuration:

Instance-specific configuration
-------------------------------

Instances can use arbitraty identifiers for the instances, for example we can name instances like `dns1`, `tls` and so on.

.. code-block:: bash

   $ systemctl start kresd@dns1
   $ systemctl start kresd@dns2
   $ systemctl start kresd@tls
   $ systemctl start kresd@doh

The instance name is subsequently exposed to kresd via the environment variable
``SYSTEMD_INSTANCE``. This can be used to tell the instances apart, e.g. when
using the :ref:`mod-nsid` module with per-instance configuration:

.. code-block:: lua

   local systemd_instance = os.getenv("SYSTEMD_INSTANCE")

   modules.load('nsid')
   nsid.name(systemd_instance)

More arcane set-ups are also possible. The following example isolates the
individual services for classic DNS, DoT and DoH from each other.

.. code-block:: lua

   local systemd_instance = os.getenv("SYSTEMD_INSTANCE")

   if string.match(systemd_instance, '^dns') then
   	net.listen('127.0.0.1', 53, { kind = 'dns' })
   elseif string.match(systemd_instance, '^tls') then
   	net.listen('127.0.0.1', 853, { kind = 'tls' })
   elseif string.match(systemd_instance, '^doh') then
   	net.listen('127.0.0.1', 443, { kind = 'doh' })
   else
   	panic("Use kresd@dns*, kresd@tls* or kresd@doh* instance names")
   end

.. include:: ../daemon/README.rst
.. include:: ../daemon/bindings/modules.rst

Monitoring and diagnostics
==========================
.. contents::
   :depth: 1
   :local:
.. include:: ../modules/nsid/README.rst
.. include:: ../modules/graphite/README.rst
.. include:: ../modules/dnstap/README.rst
.. include:: ../modules/watchdog/README.rst
.. include:: ../modules/bogus_log/README.rst
.. include:: ../modules/ta_sentinel/README.rst
.. include:: ../modules/ta_signal_query/README.rst
.. include:: ../modules/detect_time_skew/README.rst
.. include:: ../modules/detect_time_jump/README.rst

Policy, access control, data manipulation
=========================================
.. include:: ../modules/hints/README.rst
.. include:: ../modules/stats/README.rst
.. include:: ../modules/policy/README.rst
.. include:: ../modules/view/README.rst
.. include:: ../modules/rebinding/README.rst
.. include:: ../modules/refuse_nord/README.rst
.. include:: ../modules/dns64/README.rst
.. include:: ../modules/renumber/README.rst


Performance and resiliency
==========================
.. include:: ../modules/predict/README.rst
.. include:: ../modules/priming/README.rst
.. include:: ../modules/rfc7706.rst
.. include:: ../modules/prefill/README.rst
.. include:: ../modules/serve_stale/README.rst
.. include:: ../modules/workarounds/README.rst
.. include:: ../modules/edns_keepalive/README.rst


TODO: Other
===========
.. include:: ../modules/http/README.rst
.. include:: ../modules/http/README.doh.rst
.. include:: ../modules/daf/README.rst
.. include:: ../modules/etcd/README.rst

Experimental features
=====================
.. include:: ../modules/experimental_dot_auth/README.rst

.. include:: ../daemon/scripting.rst


