.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-http:

HTTP services
=============

.. tip:: In most distributions, the ``http`` module is available from a
   separate package ``knot-resolver-module-http``. The module isn't packaged
   for openSUSE.

This module does the heavy lifting to provide an HTTP and HTTP/2 enabled
server which provides few built-in services and also allows other
modules to export restful APIs and websocket streams.

One example is statistics module that can stream live metrics on the website,
or publish metrics on request for Prometheus scraper, and also :ref:`mod-http-doh`.

By default this module provides two kinds of endpoints,
and unlimited number of "used-defined kinds" can be added in configuration.

+--------------+---------------------------------------------------------------------------------+
| **Endpoint** | **Explanation**                                                                 |
+--------------+---------------------------------------------------------------------------------+
| doh          | :ref:`mod-http-doh`                                                             |
+--------------+---------------------------------------------------------------------------------+
| webmgmt      | :ref:`built-in web management <mod-http-built-in-services>` APIs (includes DoH) |
+--------------+---------------------------------------------------------------------------------+

Each network address and port combination can be configured to expose
one kind of endpoint. This is done using the same mechanisms as
network configuration for plain DNS and DNS-over-TLS,
see chapter :ref:`network-configuration` for more details.

.. warning:: Management endpoint (``webmgmt``) must not be directly exposed
             to untrusted parties. Use `reverse-proxy`_ like Apache_
             or Nginx_ if you need to authenticate API clients
             for the management API.

By default all endpoints share the same configuration for TLS certificates etc.
This can be changed using ``http.config()`` configuration call explained below.

.. _mod-http-example:

Example configuration
---------------------

This section shows how to configure HTTP module itself. For information how
to configure HTTP server's IP addresses and ports please see chapter
:ref:`network-configuration`.

.. code-block:: lua

        -- load HTTP module with defaults (self-signed TLS cert)
        modules.load('http')
        -- optionally load geoIP database for server map
        http.config({
                geoip = 'GeoLite2-City.mmdb',
                -- e.g. https://dev.maxmind.com/geoip/geoip2/geolite2/
                -- and install mmdblua library
        })

Now you can reach the web services and APIs, done!

.. code-block:: bash

	$ curl -k https://localhost:8453
	$ curl -k https://localhost:8453/stats

.. _mod-http-tls:

HTTPS (TLS for HTTP)
--------------------

By default, the web interface starts HTTPS/2 on specified port using an ephemeral
TLS certificate that is valid for 90 days and is automatically renewed. It is of
course self-signed. Why not use something like
`Let's Encrypt <https://letsencrypt.org>`_?

.. warning::

   If you use package ``luaossl < 20181207``, intermediate certificate is not sent to clients,
   which may cause problems with validating the connection in some cases.

You can disable unecrypted HTTP and enforce HTTPS by passing
``tls = true`` option for all HTTP endpoints:

.. code-block:: lua

        http.config({
                tls = true,
        })

It is also possible to provide different configuration for each
kind of endpoint, e.g. to enforce TLS and use custom certificate only for DoH:

.. code-block:: lua

	http.config({
		tls = true,
		cert = '/etc/knot-resolver/mycert.crt',
		key  = '/etc/knot-resolver/mykey.key',
	}, 'doh')

The format of both certificate and key is expected to be PEM, e.g. equivalent to
the outputs of following:

.. code-block:: bash

	openssl ecparam -genkey -name prime256v1 -out mykey.key
	openssl req -new -key mykey.key -out csr.pem
	openssl req -x509 -days 90 -key mykey.key -in csr.pem -out mycert.crt

It is also possible to disable HTTPS altogether by passing ``tls = false`` option.
Plain HTTP gets handy if you want to use `reverse-proxy`_ like Apache_ or Nginx_
for authentication to API etc.
(Unencrypted HTTP could be fine for localhost tests as, for example,
Safari doesn't allow WebSockets over HTTPS with a self-signed certificate.
Major drawback is that current browsers won't do HTTP/2 over insecure connection.)

.. warning::

   If you use multiple Knot Resolver instances with these automatically maintained ephemeral certificates,
   they currently won't be shared.
   It's assumed that you don't want a self-signed certificate for serious deployments anyway.

.. _mod-http-built-in-services:

Built-in services
-----------------

The HTTP module has several built-in services to use.

.. csv-table::
 :header: "Endpoint", "Service", "Description"

 "``/stats``", "Statistics/metrics", "Exported :ref:`metrics <mod-stats-list>` from :ref:`mod-stats` in JSON format."
 "``/metrics``", "Prometheus metrics", "Exported metrics for Prometheus_."
 "``/trace/:name/:type``", "Tracking", ":ref:`Trace resolution <mod-http-trace>` of a DNS query and return the verbose logs."
 "``/doh``", "DNS-over-HTTP", ":rfc:`8484` endpoint, see :ref:`mod-http-doh`."

Dependencies
------------

* `lua-http <https://github.com/daurnimator/lua-http>`_ (>= 0.3) available in LuaRocks

    If you're installing via Homebrew on OS X, you need OpenSSL too.

    .. code-block:: bash

       $ brew update
       $ brew install openssl
       $ brew link openssl --force # Override system OpenSSL

    Some other systems can install from LuaRocks directly:

    .. code-block:: bash

       $ luarocks --lua-version 5.1 install http

* (*optional*) `mmdblua <https://github.com/daurnimator/mmdblua>`_ available in LuaRocks

    .. code-block:: bash

       $ luarocks --lua-version 5.1 install --server=https://luarocks.org/dev mmdblua
       $ curl -O https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
       $ gzip -d GeoLite2-City.mmdb.gz

.. _Prometheus: https://prometheus.io
.. _reverse-proxy: https://en.wikipedia.org/wiki/Reverse_proxy
.. _Apache: https://httpd.apache.org/docs/2.4/howto/reverse_proxy.html
.. _Nginx: https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/
