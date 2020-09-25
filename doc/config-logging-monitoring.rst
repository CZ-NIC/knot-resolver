.. SPDX-License-Identifier: GPL-3.0-or-later

********************************
Logging, monitoring, diagnostics
********************************

Knot Resolver logs to standard outputs, which is then captured by supervisor
and sent to logging system for further processing.
To read logs use commands usual for your distribution.
E.g. on distributions using systemd-journald use command ``journalctl -u kresd@* -f``.

During normal operation only errors and other very important events are logged,
so by default logs from Knot Resolver should contain only couple lines a day.
For debugging purposes it is possible to enable very verbose logging using
:func:`verbose` function.

.. py:function:: verbose([true | false])

   :param: ``true`` to enable, ``false`` to disable verbose logging.
   :return: boolean Current state of verbose logging.

   Toggle global verbose logging. Use only for debugging purposes.
   On busy systems vebose logging can produce several MB of logs per
   second and will slow down operation.

It is also possible to obtain verbose logs for *a single request*, see chapter :ref:`mod-http-trace`.

Less verbose logging for DNSSEC validation errors can be enabled using :ref:`mod-bogus_log` module.

Various statistics for monitoring purposes are available in :ref:`mod-stats` module, including export to central systems like Graphite, Metronome, InfluxDB, or Prometheus format.

Resolver :ref:`mod-watchdog` is tool to detect and recover from potential bugs that cause the resolver to stop responding properly to queries.

Additional monitoring and debugging methods are described below. If none of these options fits your deployment or if you have special needs you can configure your own checks and exports using :ref:`async-events`.

.. toctree::
   :maxdepth: 1

   modules-bogus_log
   modules-stats
   modules-nsid
   modules-http-trace
   modules-watchdog
   modules-dnstap
   modules-ta_sentinel
   modules-ta_signal_query
   modules-detect_time_skew
   modules-detect_time_jump
