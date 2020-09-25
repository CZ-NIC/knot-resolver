.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-http-custom-endpoint:

Custom HTTP services
====================

This chapter describes how to create custom HTTP services inside Knot Resolver.
Please read HTTP module basics in chapter :ref:`mod-http` before continuing.

Each network address+protocol+port combination configured using :func:`net.listen`
is associated with *kind* of endpoint, e.g. ``doh`` or ``webmgmt``.

Each of these *kind* names is associated with table of HTTP endpoints,
and the default table can be replaced using ``http.config()`` configuration call
which allows your to provide your own HTTP endpoints.

Items in the table of HTTP endpoints are small tables describing a triplet
- ``{mime, on_serve, on_websocket}``.
In order to register a new service in ``webmgmt`` *kind* of HTTP endpoint
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

Last thing you can publish from modules are *"snippets"*. Snippets are plain pieces of HTML code
that are rendered at the end of the built-in webpage. The snippets can be extended with JS code to talk to already
exported restful APIs and subscribe to WebSockets.

.. code-block:: lua

	http.snippets['/health'] = {'Health service', '<p>UP!</p>'}

Custom RESTful services
-----------------------

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

