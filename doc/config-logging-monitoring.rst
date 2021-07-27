.. SPDX-License-Identifier: GPL-3.0-or-later

********************************
Logging, monitoring, diagnostics
********************************

To read service logs use commands usual for your distribution.
E.g. on distributions using systemd-journald use command ``journalctl -u kresd@* -f``.

Knot Resolver supports 6 logging levels - ``crit``, ``err``, ``warning``,
``notice``, ``info``, ``debug``. All levels with the same meaning as is defined
in ``syslog.h``. It is possible change logging level using
:func:`log_level` function.

Logging level ``notice`` is set after start by default,
so logs from Knot Resolver should contain only couple lines a day.
For debugging purposes it is possible to use the very verbose ``debug`` level.

In addition to levels, logging is also divided into the
:ref:`groups <config_log_groups>`. All groups
are logged by default, but you can enable ``debug`` level for selected groups using
:func:`log_groups` function. Other groups are logged to the log level
set by :func:`log_level`.

.. py:function:: log_level([level])

  :param: string ``'crit'``, ``'err'``, ``'warning'``, ``'notice'``,
   ``'info'`` or ``'debug'``
  :return: string Current logging level.

  Pass a string to set the global logging level.

  .. py:function:: verbose([true | false])

     .. deprecated:: 5.4.0
        Use :func:`log_level` instead.

     :param: ``true`` enable ``debug`` level, ``false`` switch to default level (``notice``).
     :return: boolean ``true`` when ``debug`` level is enabled.

     Toggle between ``debug`` and ``notice`` log level. Use only for debugging purposes.
     On busy systems vebose logging can produce several MB of logs per
     second and will slow down operation.

.. py:function:: log_target(target)

  :param: string ``'syslog'``, ``'stderr'``, ``'stdout'``
  :return: string Current logging target.

   Knot Resolver logs to standard error stream by default,
   but typical systemd units change that to ``'syslog'``.
   That setting logs directly through systemd's facilities
   (if available) to preserve more meta-data.

.. py:function:: log_groups([table])

  :param: table of string(s) representing ref:`log groups <config_log_groups>`
  :return: table of string with currently set log groups

  Use to turn-on debug logging for the selected groups regardless of the global
  log level. Calling with no argument lists the currently active log groups. To
  remove all log groups, call the function with an empty table.

  .. code-block:: lua

     log_groups({'io', 'tls'}  -- turn on debug logging for io and tls groups
     log_groups()              -- list active log groups
     log_groups({})            -- remove all log groups

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
