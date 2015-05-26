.. _mod-graphite:

Graphite module
---------------

The module sends statistics over the Graphite_ protocol to either Graphite_, Metronome_, InfluxDB_ or any compatible storage. This allows powerful visualization over metrics collected by Knot DNS Resolver. 

.. tip:: The Graphite server is challenging to get up and running, InfluxDB_ combined with Grafana_ are much easier, and provide richer set of options and available front-ends. Metronome_ by PowerDNS alternatively provides a mini-graphite server for much simpler setups.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

Only the ``host`` parameter is mandatory.

.. warning:: It uses UDP so it doesn't guarantee the delivery, make sure the target server supports UDP.

.. code-block:: lua

	modules = {
		graphite = {
			prefix = hostname(), -- optional metric prefix
			host = '127.0.0.1',  -- graphite server address
			port = 2003,         -- graphite server port
			interval = 5 * sec   -- publish interval
		}
	}

The module supports sending data to multiple servers at once.

.. code-block:: lua

	modules = {
		graphite = {
			host = { '127.0.0.1', '1.2.3.4', '::1' },
		}
	}

Dependencies
^^^^^^^^^^^^

* `luasocket <http://w3.impa.br/~diego/software/luasocket/>`_ available in LuaRocks

    ``$ luarocks install luasocket``

.. _Graphite: http://graphite.readthedocs.org/en/latest/feeding-carbon.html
.. _InfluxDB: http://influxdb.com/
.. _Metronome: https://github.com/ahuPowerDNS/metronome
.. _Grafana: http://grafana.org/