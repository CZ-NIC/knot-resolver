.. _operator-guide:

****************
Operator's Guide
****************

The out-of-the box configuration of the upstream Knot Resolver packages is
intended for personal or small-scale use. Any deployment with traffic over 100
queries per second will likely benefit from the recommendations in this guide.

Examples in this guide assume systemd is used as a supervisor.  However, the
same logic applies for other supervisors (e.g. supervisord_) or when running
kresd without any supervisor.


Multiple instances
==================

The resolver can run in multiple independent processes. All of them can share
the same socket (utilizing ``SO_REUSEPORT``) and cache.

.. tip:: For maximum performance, there should be as many kresd processes as
   there are available CPU threads.

To run multiple daemons, use a different identifier for each instance, for
example:

.. code-block:: bash

   $ systemctl start kresd@1.service
   $ systemctl start kresd@2.service
   $ systemctl start kresd@3.service
   $ systemctl start kresd@4.service

With the use of brace expansion in bash, the equivalent command looks like:

.. code-block:: bash

   $ systemctl start kresd@{1..4}.service

For more details, see ``kresd.systemd(7)``.

.. note:: When using multiple process, it is also possible to do a rolling
   restart with zero downtime of the service. This can be done by restarting
   only a subset of the processes at a time.


.. _instance-specific-configuration:

Instance-specific configuration
-------------------------------

It is possible to use arbitraty identifiers for the instances.

.. code-block:: bash

   $ systemctl start kresd@dns1
   $ systemctl start kresd@dns2
   $ systemctl start kresd@tls
   $ systemctl start kresd@doh

The instance name is subsequently exposed to kresd via the environment variable
``SYSTEMD_INSTANCE``. This can be used to tell the instances apart, e.g. when
using the :ref:`mod-nsid` module.

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



.. _`supervisord`: http://supervisord.org/
