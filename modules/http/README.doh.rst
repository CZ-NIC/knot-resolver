.. _mod-http-doh:

DNS-over-HTTP (DoH)
-------------------

.. warning:: DoH support was added in version 4.0.0 and is subject to change.
             Please note there is insufficient operational experience with
             this module and the DoH protocol in general.
             Knot Resolver developers do not endorse use of the DoH protocol.

Following section compares several options for running a DoH capable server.
Make sure you read through this chapter before exposing the DoH service to users.

DoH support in Knot Resolver
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The :ref:`HTTP module <mod-http>` in Knot Resolver also provides support for
binary DNS-over-HTTP protocol standardized in :rfc:`8484`.

This integrated DoH server has following properties:

:Scenario:
        HTTP module in Knot Resolver configured to provide ``/doh`` endpoint
        (as shown below).

:Advantages:
        - Integrated solution provides management and monitoring in one place.
        - Supports ACLs for DNS traffic based on client's IP address.

:Disadvantages:
        - Exposes Knot Resolver instance to attacks over HTTP.
        - Does not offer fine grained authorization and logging at HTTP level.
        - Let's Encrypt integration is not automated.


.. note:: For the time being it is recommended to run DoH endpoint
          on a separate machine which is not handling normal DNS operations.

Example configuration:

.. code-block:: lua

	-- Load HTTP module with defaults
        modules.load('http')
        http.config({
                host = 'hostname.example', -- change to your server name
                port = 443,         -- feel free to use any other port
                tls = true,
                -- use valid X.509 cert issued by a recognized Certificate authority
                cert = '/etc/knot-resolver/mycert.crt',
                key  = '/etc/knot-resolver/mykey.key',
        })

        -- disable all HTTP endpoints except DoH
        for endpoint, _ in pairs(http.endpoints) do
                if endpoint ~= '/doh' then
                        http.endpoints[endpoint] = nil
                end
        end

Now you can reach the DoH endpoint using URL ``https://hostname.example/doh``, done!

.. code-block:: bash

	# query for www.knot-resolver.cz AAAA
	$ curl -k https://hostname.example/doh?dns=l1sBAAABAAAAAAAAA3d3dw1rbm90LXJlc29sdmVyAmN6AAAcAAE

Please see section :ref:`mod-http-tls` for further details about TLS configuration.

Alternative configurations use HTTP proxies between clients and Knot Resolver instance:

Normal HTTP proxy
^^^^^^^^^^^^^^^^^
:Scenario:
        A standard HTTP-compliant proxy is configured to proxy `GET`
        and `POST` requests to HTTP endpoint `/doh` to a machine
        running Knot Resolver.

:Advantages:
        - Protects Knot Resolver instance from
          `some` types of attacks at HTTP level.
        - Allows fine-grained filtering and logging at HTTP level.
        - Let's Encrypt integration is readily available.
        - Is based on mature software.

:Disadvantages:
        - Fine-grained ACLs for DNS traffic are not available because
          proxy hides IP address of client sending DNS query.
        - More complicated setup with two components (proxy + Knot Resolver).

HTTP proxy with DoH support
^^^^^^^^^^^^^^^^^^^^^^^^^^^
:Scenario:
        HTTP proxy extended with a
        `special module for DNS-over-HTTP <https://github.com/facebookexperimental/doh-proxy>`_.
        The module transforms HTTP requests to standard DNS queries
        which are then processed by Knot Resolver.
        DNS replies from Knot Resolver are then transformed back to HTTP
        encoding by the proxy.

:Advantages:
        - Protects Knot Resolver instance from `all` attacks at HTTP level.
        - Allows fine-grained filtering and logging at HTTP level.
        - Let's Encrypt integration is readily available
          if proxy is based on a standard HTTP software.

:Disadvantages:
        - Fine-grained ACLs for DNS traffic are not available because
          proxy hides IP address of client sending DNS query.
          (Unless proxy and resolver are using non-standard packet extensions like
          `DNS X-Proxied-For <https://datatracker.ietf.org/doc/draft-bellis-dnsop-xpf/>`_.)
        - More complicated setup with three components (proxy + special module + Knot Resolver).

Client configuration
^^^^^^^^^^^^^^^^^^^^
Most common client today is web browser Firefox. Relevant configuration is described e.g. in following
`article <https://www.internetsociety.org/blog/2018/12/dns-privacy-support-in-mozilla-firefox/>`_.
To use your own DoH server just change ``network.trr.uri`` configuration option
to match URL of your DoH endpoint.

More detailed description of configuration options in Firefox can be found
`here <https://gist.github.com/bagder/5e29101079e9ac78920ba2fc718aceec>`_.
