.. _mod-tinyweb:

Web interface
-------------

This module provides an embedded web interface for resolver. It plots current performance in real-time,
including a feed of recent iterative queries. It also includes bindings_ to `MaxMind GeoIP`_, and presents a world map coloured by frequency of queries, so you can see where do your queries go.

By default, it listens on ``localhost:8053``.

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