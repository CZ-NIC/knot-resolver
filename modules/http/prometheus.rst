.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-http-prometheus:

Prometheus metrics endpoint
---------------------------

.. note:: These statistics are per-instance. When multiple kresd instances
   bound to the same webmgmt port, any of them can answer the HTTP request,
   which may lead to unexpected results.  Use graphite module to collect
   statistics from multiple instances. For other possibilities, see `#620`_.

The :ref:`HTTP module <mod-http>` exposes ``/metrics`` endpoint that serves metrics
from :ref:`mod-stats` in Prometheus_ text format.
You can use it as soon as HTTP module is configured:

.. code-block:: bash

	$ curl -k https://localhost:8453/metrics | tail
	# TYPE latency histogram
	latency_bucket{le=10} 2.000000
	latency_bucket{le=50} 2.000000
	latency_bucket{le=100} 2.000000
	latency_bucket{le=250} 2.000000
	latency_bucket{le=500} 2.000000
	latency_bucket{le=1000} 2.000000
	latency_bucket{le=1500} 2.000000
	latency_bucket{le=+Inf} 2.000000
	latency_count 2.000000
	latency_sum 11.000000

You can namespace the metrics in configuration, using `http.prometheus.namespace` attribute:

.. code-block:: lua

        modules.load('http')
        -- Set Prometheus namespace
        http.prometheus.namespace = 'resolver_'

You can also add custom metrics or rewrite existing metrics before they are returned to Prometheus client.

.. code-block:: lua

        modules.load('http')
        -- Add an arbitrary metric to Prometheus
        http.prometheus.finalize = function (metrics)
        	table.insert(metrics, 'build_info{version="1.2.3"} 1')
        end

.. _Prometheus: https://prometheus.io
.. _`#620`: https://gitlab.nic.cz/knot/knot-resolver/-/issues/620
