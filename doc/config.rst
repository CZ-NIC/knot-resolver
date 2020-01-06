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
.. include:: ../daemon/lua/trust_anchors.rst


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
Features in this section allow to configure what clients can get access to what DNS data, i.e. DNS data filtering and manipulation.

.. contents::
   :depth: 1
   :local:

.. include:: ../modules/hints/README.rst
.. include:: ../modules/stats/README.rst
.. include:: ../modules/policy/README.rst
.. include:: ../modules/view/README.rst
.. include:: ../modules/rebinding/README.rst
.. include:: ../modules/refuse_nord/README.rst
.. include:: ../modules/dns64/README.rst
.. include:: ../modules/renumber/README.rst

Answer reordering
-----------------
Certain clients are "dumb" and always connect to first IP address or name found
in a DNS answer received from resolver intead of picking randomly.
As a workaround for such broken clients it is possible to randomize
order of records in DNS answers sent by resolver:

.. function:: reorder_RR([true | false])

   :param boolean new_value: ``true`` to enable or ``false`` to disable randomization *(optional)*
   :return: The (new) value of the option

   If set, resolver will vary the order of resource records within RR sets.
   It is disabled by default.


.. _performance:

Performance and resiliency
==========================
For DNS resolvers, the most important parameter from performance perspective
is cache hit rate, i.e. percentage of queries answered from resolver's cache.
Generally the higher cache hit rate the better.

Performance tunning should start with cache :ref:`cache_sizing`
and :ref:`cache_persistence`.

It is also recommended to run `Multiple instances`_ (even on a single machine!)
because it allows to utilize multiple CPU threads
and increases overall resiliency.

Other features described in this section can be used for fine-tunning
performance and resiliency of the resolver but generally have much smaller
impact than cache settings and number of instances.

.. include:: ../daemon/bindings/cache.rst
.. include:: ../systemd/multiinst.rst
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


