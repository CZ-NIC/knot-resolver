.. SPDX-License-Identifier: GPL-3.0-or-later

.. _systemd-multiple-instances:

Multiple instances
==================

.. note:: This section describes the usage of kresd when running under systemd.
   For other uses, please refer to :ref:`usage-without-systemd`.

Knot Resolver can utilize multiple CPUs running in multiple independent instances (processes), where each process utilizes at most single CPU core on your machine. If your machine handles a lot of DNS traffic run multiple instances.

All instances typically share the same configuration and cache, and incoming queries are automatically distributed by operating system among all instances.

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


.. _systemd-zero-downtime-restarts:

Zero-downtime restarts
----------------------
Resolver restart normally takes just miliseconds and cache content is persistent to avoid performance drop
after restart. If you want real zero-downtime restarts use `multiple instances`_ and do rolling
restart, i.e. restart only one resolver process at a time.

On a system with 4 instances run these commands sequentially:

.. code-block:: bash

   $ systemctl restart kresd@1.service
   $ systemctl restart kresd@2.service
   $ systemctl restart kresd@3.service
   $ systemctl restart kresd@4.service

At any given time only a single instance is stopped and restarted so remaining three instances continue to service clients.


.. _instance-specific-configuration:

Instance-specific configuration
-------------------------------

Instances can use arbitrary identifiers for the instances, for example we can name instances like `dns1`, `tls` and so on.

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
   	net.listen('127.0.0.1', 443, { kind = 'doh2' })
   else
   	panic("Use kresd@dns*, kresd@tls* or kresd@doh* instance names")
   end
