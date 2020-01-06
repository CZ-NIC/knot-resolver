.. _config-syntax:

Files, syntax, basics
=====================

Configuration file is named ``/etc/knot-resolver/kresd.conf`` and is read when you execute Knot Resolver using systemd commands described in section :ref:`startup`. [#]_

The configuration file syntax allows you to specify different kinds of data:

  - ``group.option = 123456``
  - ``group.option = "string value"``
  - ``group.command(123456, "string value")``
  - ``group.command({ key1 = "value1", key2 = 222, key3 = "third value" })``
  - ``globalcommand(a_parameter_1, a_parameter_2, a_parameter_3, etc)``
  - ``-- any text after -- sign is ignored till end of line``

Following **configuration file snippet** starts listening for unencrypted and also encrypted DNS queries on IP address 192.0.2.1, and sets cache size.

.. code-block:: lua

        -- this is a comment: listen for unencrypted queries
        net.listen('192.0.2.1')
        -- another comment: listen for queries encrypted using TLS on port 853
        net.listen('192.0.2.1', 853, { kind = 'tls' })
        -- 10 MB cache is suitable for a very small deployment
        cache.size = 10 * MB

.. tip::
   When copy&pasting examples from this manual please pay close
   attention to brackets and also line ordering - order of lines matters.

   The configuration language is in fact Lua script, so you can use full power
   of this programming language. See article
   `Learn Lua in 15 minutes`_ for a syntax overview.

When you modify configuration file on disk restart resolver process to get changes into effect. See chapter `Zero-downtime restarts`_ if even short outages are not acceptable for your deployment.

.. [#] If you decide to run binary ``/usr/sbin/kresd`` manually (instead of using systemd) do not forget to specify ``-c`` option with path to configuration file, otherwise ``kresd`` will read file named ``config`` from its current working directory.

Besides text configuration file, Knot Resolver also supports interactive and dynamic configuration using scripts or external systems, which is described in chapter :ref:`runtime-cfg`. Through this manual we present examples for both usage types - static configuration in a text file (see above) and also the interactive mode.

The **interactive prompt** is denoted by ``>``, so all examples starting with ``>`` character are transcripts of user (or script) interaction with Knot Resolver and resolver's responses. For example:

.. code-block:: lua

        > -- this is a comment entered into interactive prompt
        > -- comments have no effect here
        > -- the next line shows a command entered interactivelly and its output
        > verbose()
        false
        > -- the previous line without > character is output from verbose() command

Following example demontrates how to interactivelly list all currently loaded modules, and includes multi-line output:

.. code-block:: lua

        > modules.list()
        [1] => iterate
        [2] => validate
        [3] => cache

One last thing before we dive into configuring features:

.. include:: ../daemon/bindings/modules.rst

Now you know what configuration file to modify, how to read examples and what modules are so you are ready for a real configuration work!

.. include:: ../daemon/README.rst
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

Logging, monitoring, diagnostics
================================
Knot Resolver logs to standard outputs, which is then captured by supervisor
and sent to logging system for further processing.
To read logs use commands usual for your distribution.
E.g. on distributions using systemd-journald use command ``journalctl -u kresd@* -f``.

During normal operation only errors and other very important events are logged,
so by default logs from Knot Resolver should contain only couple lines a day.
For debugging purposes it is possible to enable very verbose logging using
:func:`verbose` function.

.. function:: verbose([true | false])

   :param: ``true`` to enable, ``false`` to disable verbose logging.
   :return: boolean Current state of verbose logging.

   Toggle global verbose logging. Use only for debugging purposes.
   On busy systems vebose logging can produce several MB of logs per
   second and will slow down operation.

More fine-grained tools are available in following modules:

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


