.. _mod-http:

HTTP interface
--------------

This module provides both DNS/HTTP(s) and web interface that cooperates with the internal
scheduler. It preloads all static assets, so nothing is read from disk after startup and
provides basic foundation for other services wishing to export services over HTTP endpoints.
The module supports HTTP/2, server push and all other shiny things thanks to lua-http.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

By default, the web interface starts at port 8053 if HTTP or 4453 if running on TLS.

.. code-block:: lua

	-- Load modules
	modules = {
		http = {
      host = 'localhost',
      port = 8080,
		}
	}

Dependencies
^^^^^^^^^^^^

* `lua-http <https://github.com/daurnimator/lua-http>`_ available in LuaRocks

    ``$ luarocks install --server=http://luarocks.org/dev http``