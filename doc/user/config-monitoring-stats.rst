.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-monitoring-stats:

Statistics collector
====================

This module gathers various counters from the query resolution
and server internals, and offers them as a key-value storage.

.. code-block:: yaml

   monitoring:
     enabled: always

These metrics can be either exported to :ref:`config-monitoring-graphite` or
exposed as :ref:`config-monitoring-prometheus`.

.. option:: monitoring:

   .. option:: metrics: manager-only|lazy|always

      :default: lazy

      Configures, whether statistics module will be loaded into resolver.

      * ``manager-only`` - Disables metrics/statistics collection in all `kresd` workers.
      * ``lazy`` - Metrics/statistics collection is enabled at the time of request.
      * ``always`` - Metrics/statistics collection is always on.

You can see all built-in statistics in `built-in statistics <./dev/modules-stats.html#mod-stats-list>`_ section.


.. _config-monitoring-prometheus:

Prometheus metrics endpoint
---------------------------

The :ref:`manager-api` exposes `/metrics` endpoint that serves agregated metrics from statistics collector in Prometheus text format.
You can use it as soon as the HTTP API is configured.

It is also possible to use the :ref:`manager-client` to obtain and save metrics:

.. code-block:: bash

   $ kresctl metrics ./metrics/data.txt


.. _config-monitoring-graphite:

Graphite/InfluxDB/Metronome
---------------------------

The Graphite module sends statistics over the Graphite_ protocol to either Graphite_, Metronome_, InfluxDB_ or any compatible storage.
This allows powerful visualization over metrics collected by Knot Resolver.

.. tip:: The Graphite server is challenging to get up and running, InfluxDB_ combined with Grafana_ are much easier, and provide richer set of options and available front-ends. Metronome_ by PowerDNS alternatively provides a mini-graphite server for much simpler setups.

Example configuration:

.. code-block:: yaml

   monitoring:
     graphite:
       enabled: true
       host: 127.0.0.1 # graphite server address
       port: 200       # optional graphite server port (2003 is default)
       interval: 5s    # optional publish interval (5s is default)

.. option:: monitoring/graphite:

   .. option:: enabled: true|false

      :default: false

      Enabled Graphite bridge module. It is disabled by default.
      Configured :option:`host <host: <address or hostname>>` is also required to enable Graphite bridge.

   .. option:: host: <address or hostname>

      Graphite server IP address or hostname.

   .. option:: port: <port>

      :default: 2003

      Optional, Graphite server port.

   .. option:: prefix: <string>

      :default: ""

      Optional prefix for all `kresd` workers.
      Worker ID is automatically added for each process.

   .. option:: interval: <time ms|s|m|h|d>

      :default: 5s

      Optional publishing interval.

   .. option:: tcp: true|false

      :default: false

      Optional, set to true if you want TCP mode.

.. _Graphite: https://graphite.readthedocs.io/en/latest/feeding-carbon.html
.. _InfluxDB: https://influxdb.com/
.. _Metronome: https://github.com/ahuPowerDNS/metronome
.. _Grafana: http://grafana.org/
