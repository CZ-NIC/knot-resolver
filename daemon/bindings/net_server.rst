.. SPDX-License-Identifier: GPL-3.0-or-later

Addresses and services
----------------------

Addresses, ports, protocols, and API calls available for clients communicating
with resolver are configured using :func:`net.listen`.

First you need to decide what service should be available on given IP address
+ port combination.

.. csv-table::
  :header: "Protocol/service", "net.listen *kind*"

  "DNS (unencrypted UDP+TCP, :rfc:`1034`)","``dns``"
  "DNS (unencrypted UDP, :ref:`using XDP Linux API <dns-over-xdp>`)","``xdp``"
  ":ref:`dns-over-tls`","``tls``"
  ":ref:`dns-over-https`","``doh2``"
  ":ref:`Web management <mod-http-built-in-services>`","``webmgmt``"
  ":ref:`Control socket <control-sockets>`","``control``"
  ":ref:`mod-http-doh`","``doh_legacy``"

.. note:: By default, **unencrypted DNS and DNS-over-TLS** are configured to **listen
   on localhost**.

   Control sockets are created either in
   ``/run/knot-resolver/control/`` (when using systemd) or ``$PWD/control/``.

.. function:: net.listen(addresses, [port = 53, { kind = 'dns', freebind = false }])

   :return: ``true`` if port is bound, an error otherwise

   Listen on addresses; port and flags are optional.
   The addresses can be specified as a string or device.
   Port 853 implies ``kind = 'tls'`` but it is always better to be explicit.
   Freebind allows binding to a non-local or not yet available address.

.. csv-table::
  :header: "**Network protocol**", "**Configuration command**"

  "DNS (UDP+TCP, :rfc:`1034`)","``net.listen('192.0.2.123', 53)``"
  "DNS (UDP, :ref:`using XDP <dns-over-xdp>`)","``net.listen('192.0.2.123', 53, { kind = 'xdp' })``"
  ":ref:`dns-over-tls`","``net.listen('192.0.2.123', 853, { kind = 'tls' })``"
  ":ref:`dns-over-https`","``net.listen('192.0.2.123', 443, { kind = 'doh2' })``"
  ":ref:`Web management <mod-http-built-in-services>`","``net.listen('192.0.2.123', 8453, { kind = 'webmgmt' })``"
  ":ref:`Control socket <control-sockets>`","``net.listen('/tmp/kres.control', nil, { kind = 'control' })``"


Examples:

   .. code-block:: lua

	net.listen('::1')
	net.listen(net.lo, 53)
	net.listen(net.eth0, 853, { kind = 'tls' })
	net.listen('192.0.2.1', 53, { freebind = true })
	net.listen({'127.0.0.1', '::1'}, 53, { kind = 'dns' })
	net.listen('::', 443, { kind = 'doh2' })
	net.listen('::', 8453, { kind = 'webmgmt' }) -- see http module
	net.listen('/tmp/kresd-socket', nil, { kind = 'webmgmt' }) -- http module supports AF_UNIX
	net.listen('eth0', 53, { kind = 'xdp' })
	net.listen('192.0.2.123', 53, { kind = 'xdp', nic_queue = 0 })

.. warning:: On machines with multiple IP addresses avoid listening on wildcards
        ``0.0.0.0`` or ``::``. Knot Resolver could answer from different IP
        addresses if the network address ranges overlap,
        and clients would probably refuse such a response.


Features for scripting
^^^^^^^^^^^^^^^^^^^^^^
Following configuration functions are useful mainly for scripting or :ref:`runtime-cfg`.

.. function:: net.close(address, [port])

   :return: boolean (at least one endpoint closed)

   Close all endpoints listening on the specified address, optionally restricted by port as well.


.. function:: net.list()

   :return: Table of bound interfaces.

   Example output:

   .. code-block:: none

      [1] => {
          [kind] => tls
          [transport] => {
              [family] => inet4
              [ip] => 127.0.0.1
              [port] => 853
              [protocol] => tcp
          }
      }
      [2] => {
          [kind] => dns
          [transport] => {
              [family] => inet6
              [ip] => ::1
              [port] => 53
              [protocol] => udp
          }
      }
      [3] => {
          [kind] => dns
          [transport] => {
              [family] => inet6
              [ip] => ::1
              [port] => 53
              [protocol] => tcp
          }
      }
      [4] => {
          [kind] => xdp
          [transport] => {
              [family] => inet4+inet6
              [interface] => eth2
              [nic_queue] => 0
              [port] => 53
              [protocol] => udp
          }
      }

.. function:: net.interfaces()

   :return: Table of available interfaces and their addresses.

   Example output:

   .. code-block:: none

	[lo0] => {
	    [addr] => {
	        [1] => ::1
	        [2] => 127.0.0.1
	    }
	    [mac] => 00:00:00:00:00:00
	}
	[eth0] => {
	    [addr] => {
	        [1] => 192.168.0.1
	    }
	    [mac] => de:ad:be:ef:aa:bb
	}

   .. tip:: You can use ``net.<iface>`` as a shortcut for specific interface, e.g. ``net.eth0``

.. function:: net.tcp_pipeline([len])

   Get/set per-client TCP pipeline limit, i.e. the number of outstanding queries that a single client connection can make in parallel.  Default is 100.

   .. code-block:: lua

      > net.tcp_pipeline()
      100
      > net.tcp_pipeline(50)
      50

   .. warning:: Please note that too large limit may have negative impact on performance and can lead to increased number of SERVFAIL answers.

.. _`dnsproxy module`: https://www.knot-dns.cz/docs/2.7/html/modules.html#dnsproxy-tiny-dns-proxy


