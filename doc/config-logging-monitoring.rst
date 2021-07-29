.. SPDX-License-Identifier: GPL-3.0-or-later

********************************
Logging, monitoring, diagnostics
********************************

Knot Resolver logs to standard outputs, which is then captured by supervisor
and sent to logging system for further processing.
To read logs use commands usual for your distribution.
E.g. on distributions using systemd-journald use command ``journalctl -u kresd@* -f``.

Knot Resolver supports 6 logging levels - ``crit``, ``err``, ``warning``,
``notice``, ``info``, ``debug``. All levels with the same meaning as is defined
in ``syslog.h``. It is possible change logging level using
:func:`set_log_level` function.

Logging level ``notice`` is set after start by default,
so logs from Knot Resolver should contain only couple lines a day.
For debugging purposes it is possible to enable very verbose logging using
:func:`verbose` function.

In addition to levels, logging is also divided into the
:ref:`groups <config_log_groups>`. All groups
are logged by default, but you can enable ``debug`` level for some groups using
:func:`add_log_groups` function. Other groups are logged to the log level
set by :func:`set_log_level`.

.. py:function:: set_log_level(level)

  :param: String ``'crit'``, ``'err'``, ``'warning'``, ``'notice'``,
   ``'info'`` or ``'debug'``.
  :return: string Current logging level.

  Set global logging level.

  .. py:function:: verbose([true | false])

     :param: ``true`` enable ``debug`` level, ``false`` switch to default level (``notice``).
     :return: boolean ``true`` when ``debug`` level is enabled.

     Toggle between ``debug`` and ``notice`` log level. Use only for debugging purposes.
     On busy systems vebose logging can produce several MB of logs per
     second and will slow down operation.

.. py:function:: get_log_level()

  :return: string Current logging level.

  Show current logging level.

.. py:function:: get_log_groups()

  :return: table :ref:`Groups <config_log_groups>` switched to ``debug`` level.

  Get :ref:`groups <config_log_groups>` switched to ``debug`` level.

.. py:function:: add_log_groups([string | table])

  :param: :ref:`Groups <config_log_groups>` to switch to ``debug`` level.

  Set debug level for selected :ref:`groups <config_log_groups>`.

.. py:function:: del_log_groups([string | table])

  :param: :ref:`Groups <config_log_groups>` switched to global logging level.

  Switch selected :ref:`groups <config_log_groups>` to logging level set
  by :func:`set_log_level`.

It is also possible to enable ``debug`` logging level for *a single request*, see chapter :ref:`mod-http-trace`.

Less verbose logging for DNSSEC validation errors can be enabled using :ref:`mod-bogus_log` module.

Various statistics for monitoring purposes are available in :ref:`mod-stats` module, including export to central systems like Graphite, Metronome, InfluxDB, or Prometheus format.

Resolver :ref:`mod-watchdog` is tool to detect and recover from potential bugs that cause the resolver to stop responding properly to queries.

Additional monitoring and debugging methods are described below. If none of these options fits your deployment or if you have special needs you can configure your own checks and exports using :ref:`async-events`.

.. toctree::
   :maxdepth: 1

   modules-bogus_log
   modules-stats
   daemon-bindings-worker
   modules-nsid
   modules-http-trace
   modules-watchdog
   modules-dnstap
   modules-ta_sentinel
   modules-ta_signal_query
   modules-detect_time_skew
   modules-detect_time_jump
   config-debugging
   config-logging-header
