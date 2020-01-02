**********
Monitoring
**********

Statistics for monitoring purposes are available in :ref:`mod-stats` module. If you want to export these statistics to a central system like Graphite, Metronome, InfluxDB or any other compatible storage see :ref:`mod-graphite`. Statistics can also be made available over HTTP protocol in Prometheus format, see module providing :ref:`mod-http`, Prometheus is supported by ``webmgmt`` endpoint.

.. note::

  Please remember that each Knot Resolver instance keeps its own statistics, and instances can be started and stopped dynamically. This might affect your data postprocessing procedures.

More extensive logging can be enabled using :ref:`mod-bogus_log` module.

Resolver watchdog is tool to detect and recover from potential bugs that cause the resolver to stop responding properly to queries. See :ref:`mod-watchdog` for more information about this functionality.

If none of these options fits your deployment or if you have special needs you can configure your own checks and exports using :ref:`async-events`.
