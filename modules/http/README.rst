.. _mod-http:

HTTP/2 services
---------------

This module does the heavy lifting to provide an HTTP/2 enabled
server which provides few built-in services and also allows other
modules to export restful APIs and websocket streams.

One example is statistics module that can stream live metrics on the website,
or publish metrics on request for Prometheus scraper.

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
^^^^^^^^^^^^^^^^^^^^^

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

Configuring TLS
^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^

The HTTP module has several built-in services to use.

.. csv-table::
 :header: "Endpoint", "Service", "Description"

 "``/stats``", "Statistics/metrics", "Exported :ref:`metrics <mod-stats-list>` from :ref:`mod-stats` in JSON format."
 "``/metrics``", "Prometheus metrics", "Exported metrics for Prometheus_."
 "``/trace/:name/:type``", "Tracking", ":ref:`Trace resolution <mod-http-trace>` of a DNS query and return the verbose logs."
 "``/doh``", "DNS-over-HTTP", ":rfc:`8484` endpoint, see :ref:`mod-http-doh`."

Prometheus metrics endpoint
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The module exposes ``/metrics`` endpoint that serves internal metrics in Prometheus_ text format.
You can use it out of the box:

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

.. _mod-http-trace:

Tracing requests
^^^^^^^^^^^^^^^^

With the ``/trace`` endpoint you can trace various aspects of the request execution.
The basic mode allows you to resolve a query and trace verbose logs (and messages received):

.. code-block:: bash

   $ curl https://localhost:8453/trace/e.root-servers.net
   [ 8138] [iter] 'e.root-servers.net.' type 'A' created outbound query, parent id 0
   [ 8138] [ rc ] => rank: 020, lowest 020, e.root-servers.net. A
   [ 8138] [ rc ] => satisfied from cache
   [ 8138] [iter] <= answer received:
   ;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 8138
   ;; Flags: qr aa  QUERY: 1; ANSWER: 0; AUTHORITY: 0; ADDITIONAL: 0

   ;; QUESTION SECTION
   e.root-servers.net.		A

   ;; ANSWER SECTION
   e.root-servers.net. 	3556353	A	192.203.230.10

   [ 8138] [iter] <= rcode: NOERROR
   [ 8138] [resl] finished: 4, queries: 1, mempool: 81952 B


.. _mod-http-custom-endpoint:

How to expose custom services over HTTP
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each kind of endpoint provides table of HTTP endpoints, and the default table
can be replaced using ``http.config()`` configuration call
which allows your to provide your own HTTP endpoints.

It contains tables describing a triplet - ``{mime, on_serve, on_websocket}``.
In order to register a new `webmgmt` HTTP endpoint
add the new endpoint description to respective table:


.. code-block:: lua

	-- custom function to handle HTTP /health requests
	local on_health = {'application/json',
	function (h, stream)
		-- API call, return a JSON table
		return {state = 'up', uptime = 0}
	end,
	function (h, ws)
		-- Stream current status every second
		local ok = true
		while ok do
			local push = tojson('up')
			ok = ws:send(tojson({'up'}))
			require('cqueues').sleep(1)
		end
		-- Finalize the WebSocket
		ws:close()
	end}

	modules.load('http')
	-- copy all existing webmgmt endpoints
	my_mgmt_endpoints = http.configs._builtin.webmgmt.endpoints
	-- add custom endpoint to the copy
	my_mgmt_endpoints['/health'] = on_health
	-- use custom HTTP configuration for webmgmt
	http.config({
	        endpoints = my_mgmt_endpoints
	}, 'webmgmt')

Then you can query the API endpoint, or tail the WebSocket using curl.

.. code-block:: bash

	$ curl -k https://localhost:8453/health
	{"state":"up","uptime":0}
	$ curl -k -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Host: localhost:8453/health"  -H "Sec-Websocket-Key: nope" -H "Sec-Websocket-Version: 13" https://localhost:8453/health
	HTTP/1.1 101 Switching Protocols
	upgrade: websocket
	sec-websocket-accept: eg18mwU7CDRGUF1Q+EJwPM335eM=
	connection: upgrade

	?["up"]?["up"]?["up"]

Since the stream handlers are effectively coroutines, you are free to keep state
and yield using `cqueues library <http://www.25thandclement.com/~william/projects/cqueues.html>`_.

This is especially useful for WebSockets, as you can stream content in a simple loop instead of
chains of callbacks.

Last thing you can publish from modules are *"snippets"*. Snippets are plain pieces of HTML code that are rendered at the end of the built-in webpage. The snippets can be extended with JS code to talk to already
exported restful APIs and subscribe to WebSockets.

.. code-block:: lua

	http.snippets['/health'] = {'Health service', '<p>UP!</p>'}

How to expose custom RESTful services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A RESTful service is likely to respond differently to different type of methods and requests,
there are three things that you can do in a service handler to send back results.
First is to just send whatever you want to send back, it has to respect MIME type that the service
declared in the endpoint definition. The response code would then be ``200 OK``, any non-string
responses will be packed to JSON. Alternatively, you can respond with a number corresponding to
the HTTP response code or send headers and body yourself.

.. code-block:: lua

	-- Our upvalue
	local value = 42

	-- Expose the service
	local service = {'application/json',
	function (h, stream)
		-- Get request method and deal with it properly
		local m = h:get(':method')
		local path = h:get(':path')
		log('[service] method %s path %s', m, path)
		-- Return table, response code will be '200 OK'
		if m == 'GET' then
			return {key = path, value = value}
		-- Save body, perform check and either respond with 505 or 200 OK
		elseif m == 'POST' then
			local data = stream:get_body_as_string()
			if not tonumber(data) then
				return 500, 'Not a good request'
			end
			value = tonumber(data)
		-- Unsupported method, return 405 Method not allowed
		else
			return 405, 'Cannot do that'
		end
	end}
	modules.load('http')
	http.config({
		endpoints = { ['/service'] = service }
	}, 'myservice')
	-- do not forget to create socket of new kind using
	-- net.listen(..., { kind = 'myservice' })
	-- or configure systemd socket kresd-myservice.socket

In some cases you might need to send back your own headers instead of default provided by HTTP handler,
you can do this, but then you have to return ``false`` to notify handler that it shouldn't try to generate
a response.

.. code-block:: lua

	local headers = require('http.headers')
	function (h, stream)
		-- Send back headers
		local hsend = headers.new()
		hsend:append(':status', '200')
		hsend:append('content-type', 'binary/octet-stream')
		assert(stream:write_headers(hsend, false))
		-- Send back data
		local data = 'binary-data'
		assert(stream:write_chunk(data, true))
		-- Disable default handler action
		return false
	end

Dependencies
^^^^^^^^^^^^

* `lua-http <https://github.com/daurnimator/lua-http>`_ (>= 0.3) available in LuaRocks

    If you're installing via Homebrew on OS X, you need OpenSSL too.

    .. code-block:: bash

       $ brew update
       $ brew install openssl
       $ brew link openssl --force # Override system OpenSSL

    Any other system can install from LuaRocks directly:

    .. code-block:: bash

       $ luarocks install http

* `mmdblua <https://github.com/daurnimator/mmdblua>`_ available in LuaRocks

    .. code-block:: bash

       $ luarocks install --server=https://luarocks.org/dev mmdblua
       $ curl -O https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
       $ gzip -d GeoLite2-City.mmdb.gz

.. _Prometheus: https://prometheus.io
.. _reverse-proxy: https://en.wikipedia.org/wiki/Reverse_proxy
.. _Apache: https://httpd.apache.org/docs/2.4/howto/reverse_proxy.html
.. _Nginx: https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/
