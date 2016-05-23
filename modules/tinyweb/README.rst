.. _mod-tinyweb:

Web interface
-------------

This module provides an embedded web interface for resolver. It plots current performance in real-time,
including a feed of recent iterative queries. It also includes bindings_ to `MaxMind GeoIP`_, and presents a world map coloured by frequency of queries, so you can see where do your queries go.

The *stats* module is required for plotting query rate.
By default, it listens on ``localhost:8053``.

.. warning:: This is a proof of concept module for embedding Go, which has several drawbacks - it runs in separate threads, is relatively heavy-weight due to the nature of Go, and is opaque for other modules. Look at :ref:`http module <mod-http>` if you want to expose services over HTTP from other modules.

Examples
^^^^^^^^

.. code-block:: lua

  -- Load web interface
  modules = { 'tinyweb' }
  -- Listen on specific address/port
  modules = {
    tinyweb = {
      addr = 'localhost:8080', -- Custom address
      geoip = '/usr/local/var/GeoIP' -- Different path to GeoIP DB
    }
  }

Dependencies
^^^^^^^^^^^^

It depends on Go 1.5+, `github.com/abh/geoip <bindings>`_ package.

.. code-block:: bash

  $ <install> libgeoip
  $ go get github.com/abh/geoip

.. _`MaxMind GeoIP`: https://www.maxmind.com/en/home
.. _bindings: https://github.com/abh/geoip
