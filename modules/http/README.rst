.. _mod-http:

HTTP/2 services
---------------

This is a module that does the heavy lifting to provide an HTTP/2 enabled
server that supports TLS by default and provides endpoint for other modules
in order to enable them to export restful APIs and websocket streams.
One example is statistics module that can stream live metrics on the website,
or publish metrics on request for Prometheus scraper.

The server allows other modules to either use default endpoint that provides
built-in webpage, restful APIs and websocket streams, or create new endpoints.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

By default, the web interface starts HTTPS/2 on port 8053 using an ephemeral
certificate that is valid for 90 days and is automatically renewed. It is of
course self-signed, so you should use your own judgement before exposing it
to the outside world. Why not use something like `Let's Encrypt <https://letsencrypt.org>`_
for starters?

.. code-block:: lua

	-- Load HTTP module with defaults
	modules = {
		http = {
			host = 'localhost',
			port = 8053,
			geoip = 'GeoLite2-City.mmdb' -- Optional, see
			-- e.g. https://dev.maxmind.com/geoip/geoip2/geolite2/
			-- and install mmdblua library
			endpoints = {},
		}
	}

Now you can reach the web services and APIs, done!

.. code-block:: bash

	$ curl -k https://localhost:8053
	$ curl -k https://localhost:8053/stats

It is possible to disable HTTPS altogether by passing ``cert = false`` option.
While it's not recommended, it could be fine for localhost tests as, for example,
Safari doesn't allow WebSockets over HTTPS with a self-signed certificate.
Major drawback is that current browsers won't do HTTP/2 over insecure connection.

.. code-block:: lua

	http = {
		host = 'localhost',
		port = 8053,
		cert = false,
	}

If you want to provide your own certificate and key, you're welcome to do so:

.. code-block:: lua

	http = {
		host = 'localhost',
		port = 8053,
		cert = 'mycert.crt',
		key  = 'mykey.key',
	}

The format of both certificate and key is expected to be PEM, e.g. equivallent to
the outputs of following: 

.. code-block:: bash

	openssl ecparam -genkey -name prime256v1 -out mykey.key
	openssl req -new -key mykey.key -out csr.pem
	openssl req -x509 -days 90 -key mykey.key -in csr.pem -out mycert.crt

Built-in services
^^^^^^^^^^^^^^^^^

The HTTP module has several built-in services to use.

.. csv-table::
 :header: "Endpoint", "Service", "Description"

 "``/stats``", "Statistics/metrics", "Exported metrics in JSON."
 "``/metrics``", "Prometheus metrics", "Exported metrics for Prometheus_"
 "``/feed``", "Most frequent queries", "List of most frequent queries in JSON."
  "``/trace/:name/:type``", "Tracking", "Trace resolution of the query and return the verbose logs."

Enabling Prometheus metrics endpoint
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The module exposes ``/metrics`` endpoint that serves internal metrics in Prometheus_ text format.
You can use it out of the box:

.. code-block:: bash

	$ curl -k https://localhost:8053/metrics | tail
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

	http = {
		host = 'localhost',
	}

	-- Set Prometheus namespace
	http.prometheus.namespace = 'resolver_'

Tracing requests
^^^^^^^^^^^^^^^^

With the ``/trace`` endpoint you can trace various aspects of the request execution.
The basic mode allows you to resolve a query and trace verbose logs (and messages received):

.. code-block:: bash

   $ curl http://localhost:8053/trace/e.root-servers.net
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

How to expose services over HTTP
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The module provides a table ``endpoints`` of already existing endpoints, it is free for reading and
writing. It contains tables describing a triplet - ``{mime, on_serve, on_websocket}``.
In order to register a new service, simply add it to the table:

.. code-block:: lua

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
	-- Load module
	modules = {
		http = {
			endpoints = { ['/health'] = on_health }
		}
	}

Then you can query the API endpoint, or tail the WebSocket using curl.

.. code-block:: bash

	$ curl -k http://localhost:8053/health
	{"state":"up","uptime":0}
	$ curl -k -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Host: localhost:8053/health"  -H "Sec-Websocket-Key: nope" -H "Sec-Websocket-Version: 13" https://localhost:8053/health
	HTTP/1.1 101 Switching Protocols
	upgrade: websocket
	sec-websocket-accept: eg18mwU7CDRGUF1Q+EJwPM335eM=
	connection: upgrade

	?["up"]?["up"]?["up"]

Since the stream handlers are effectively coroutines, you are free to keep state and yield using cqueues.
This is especially useful for WebSockets, as you can stream content in a simple loop instead of
chains of callbacks.

Last thing you can publish from modules are *"snippets"*. Snippets are plain pieces of HTML code that are rendered at the end of the built-in webpage. The snippets can be extended with JS code to talk to already
exported restful APIs and subscribe to WebSockets.

.. code-block:: lua

	http.snippets['/health'] = {'Health service', '<p>UP!</p>'}

How to expose RESTful services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
	-- Load the module
	modules = {
		http = {
			endpoints = { ['/service'] = service }
		}
	}

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

How to expose more interfaces
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Services exposed in the previous part share the same external interface. This means that it's either accessible to the outside world or internally, but not one or another. This is not always desired, i.e. you might want to offer DNS/HTTPS to everyone, but allow application firewall configuration only on localhost. ``http`` module allows you to create additional interfaces with custom endpoints for this purpose.

.. code-block:: lua

	http.interface('127.0.0.1', 8080, {
		['/conf'] = {'application/json', function (h, stream) print('configuration API') end},
		['/private'] = {'text/html', static_page},
	})

This way you can have different internal-facing and external-facing services at the same time.

Dependencies
^^^^^^^^^^^^

* `lua-http <https://github.com/daurnimator/lua-http>`_ (>= 0.1) available in LuaRocks

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
