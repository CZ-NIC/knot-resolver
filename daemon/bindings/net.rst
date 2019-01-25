
.. _network-configuration:

Network configuration
^^^^^^^^^^^^^^^^^^^^^

For when listening on ``localhost`` just doesn't cut it.

**Systemd socket configuration**

If you're using our packages with systemd with sockets support (not supported
on CentOS 7), network interfaces are configured using systemd drop-in files for
``kresd.socket`` and ``kresd-tls.socket``.

To configure kresd to listen on public interface, create a drop-in file:

.. code-block:: bash

   $ systemctl edit kresd.socket

.. code-block:: none

   # /etc/systemd/system/kresd.socket.d/override.conf
   [Socket]
   ListenDatagram=192.0.2.115:53
   ListenStream=192.0.2.115:53

.. _kresd-socket-override-port:

The default port can also be overriden by using an empty ``ListenDatagram=`` or ``ListenStream=`` directive. This can be useful if you want to use the Knot DNS with the `dnsproxy module`_ to have both resolver and authoritative server running on the same machine.

.. code-block:: none

   # /etc/systemd/system/kresd.socket.d/override.conf
   [Socket]
   ListenDatagram=
   ListenStream=
   ListenDatagram=127.0.0.1:53000
   ListenStream=127.0.0.1:53000
   ListenDatagram=[::1]:53000
   ListenStream=[::1]:53000

The ``kresd-tls.socket`` can also be configured to listen for TLS connections.

.. code-block:: bash

   $ systemctl edit kresd-tls.socket

.. code-block:: none

   # /etc/systemd/system/kresd-tls.socket.d/override.conf
   [Socket]
   ListenStream=192.0.2.115:853

**Daemon network configuration**

If you don't use systemd with sockets to run kresd, network interfaces are
configured in the config file.

.. tip:: Use declarative interface for network.

         .. code-block:: lua

            net = { '127.0.0.1', net.eth0, net.eth1.addr[1] }
            net.ipv4 = false

.. warning:: On machines with multiple IP addresses avoid binding to wildcard ``0.0.0.0`` or ``::`` (see example below). Knot Resolver could answer from different IP in case the ranges overlap and client will probably refuse such a response.

         .. code-block:: lua

            net = { '0.0.0.0' }


.. envvar:: net.ipv6 = true|false

   :return: boolean (default: true)

   Enable/disable using IPv6 for contacting upstream nameservers.

.. envvar:: net.ipv4 = true|false

   :return: boolean (default: true)

   Enable/disable using IPv4 for contacting upstream nameservers.

.. function:: net.listen(addresses, [port = 53, flags = {tls = (port == 853)}])

   :return: boolean

   Listen on addresses; port and flags are optional.
   The addresses can be specified as a string or device,
   or a list of addresses (recursively).
   The command can be given multiple times, but note that it silently skips
   any addresses that have already been bound.

   Examples:

   .. code-block:: lua

	net.listen('::1')
	net.listen(net.lo, 5353)
	net.listen({net.eth0, '127.0.0.1'}, 53853, {tls = true})

.. function:: net.close(address, [port = 53])

   :return: boolean

   Close opened address/port pair, noop if not listening.

.. function:: net.list()

   :return: Table of bound interfaces.

   Example output:

   .. code-block:: none

	[127.0.0.1] => {
	    [port] => 53
	    [tcp] => true
	    [udp] => true
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

.. function:: net.bufsize([udp_bufsize])

   Get/set maximum EDNS payload available. Default is 4096.
   You cannot set less than 512 (512 is DNS packet size without EDNS, 1220 is minimum size for DNSSEC) or more than 65535 octets.

   Example output:

   .. code-block:: lua

	> net.bufsize 4096
	> net.bufsize()
	4096

.. function:: net.tcp_pipeline([len])

   Get/set per-client TCP pipeline limit, i.e. the number of outstanding queries that a single client connection can make in parallel.  Default is 100.

   .. code-block:: lua

      > net.tcp_pipeline()
      100
      > net.tcp_pipeline(50)
      50

   .. warning:: Please note that too large limit may have negative impact on performance and can lead to increased number of SERVFAIL answers.

.. function:: net.outgoing_v4([string address])

   Get/set the IPv4 address used to perform queries.  There is also ``net.outgoing_v6`` for IPv6.
   The default is ``nil``, which lets the OS choose any address.


.. _tls-server-config:

TLS server configuration
^^^^^^^^^^^^^^^^^^^^^^^^
.. note:: Installations using systemd should be configured using systemd-specific procedures
          described in manual page ``kresd.systemd(7)``.

DNS-over-TLS server (:rfc:`7858`) can be enabled using ``{tls = true}`` parameter
in :c:func:`net.listen()` function call. For example:

.. code-block:: lua

      > net.listen("::", 53)  -- plain UDP+TCP on port 53 (standard DNS)
      > net.listen("::", 853, {tls = true})  -- DNS-over-TLS on port 853 (standard DoT)
      > net.listen("::", 443, {tls = true})  -- DNS-over-TLS on port 443 (non-standard)

By default an self-signed certificate will be generated. For serious deployments
it is strongly recommended to provide TLS certificates signed by a trusted CA
using :c:func:`net.tls()`.

.. function:: net.tls([cert_path], [key_path])

   Get/set path to a server TLS certificate and private key for DNS/TLS.

   Example output:

   .. code-block:: lua

      > net.tls("/etc/knot-resolver/server-cert.pem", "/etc/knot-resolver/server-key.pem")
      > net.tls()  -- print configured paths
      ("/etc/knot-resolver/server-cert.pem", "/etc/knot-resolver/server-key.pem")

.. function:: net.tls_padding([true | false])

   Get/set EDNS(0) padding of answers to queries that arrive over TLS
   transport.  If set to `true` (the default), it will use a sensible
   default padding scheme, as implemented by libknot if available at
   compile time.  If set to a numeric value >= 2 it will pad the
   answers to nearest *padding* boundary, e.g. if set to `64`, the
   answer will have size of a multiple of 64 (64, 128, 192, ...).  If
   set to `false` (or a number < 2), it will disable padding entirely.

.. function:: net.tls_sticket_secret([string with pre-shared secret])

   Set secret for TLS session resumption via tickets, by :rfc:`5077`.

   The server-side key is rotated roughly once per hour.
   By default or if called without secret, the key is random.
   That is good for long-term forward secrecy, but multiple kresd instances
   won't be able to resume each other's sessions.

   If you provide the same secret to multiple instances, they will be able to resume
   each other's sessions *without* any further communication between them.
   This synchronization works only among instances having the same endianess
   and time_t structure and size (`sizeof(time_t)`).

   **For good security** the secret must have enough entropy to be hard to guess,
   and it should still be occasionally rotated manually and securely forgotten,
   to reduce the scope of privacy leak in case the
   `secret leaks eventually <https://en.wikipedia.org/wiki/Forward_secrecy>`_.

   .. warning:: **Setting the secret is probably too risky with TLS <= 1.2**.
      GnuTLS stable release supports TLS 1.3 since 3.6.3 (summer 2018).
      Therefore setting the secrets should be considered experimental for now
      and might not be available on your system.

.. function:: net.tls_sticket_secret_file([string with path to a file containing pre-shared secret])

   The same as :func:`net.tls_sticket_secret`,
   except the secret is read from a (binary) file.

