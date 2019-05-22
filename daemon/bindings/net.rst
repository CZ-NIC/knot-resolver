.. _network-configuration:

Network configuration
^^^^^^^^^^^^^^^^^^^^^

Modern Linux distributions use so-called *Systemd socket activation*, which
effectively means that IP addresses and ports to listen on are configured
in Systemd configuration files.

Older Linux systems and all non-Linux systems do not support this modern method
and have to resort to old fashioned way of configuring network interfaces using
``net.listen()`` configuration call.
Most notable examples of such systems are CentOS 7 and macOS.

.. warning:: On machines with multiple IP addresses avoid listening on wildcards
        ``0.0.0.0`` or ``::``. Knot Resolver could answer from different IP
        addresses if the network address ranges overlap,
        and clients would probably refuse such a response.

**Network configuration using systemd**

If you're using our packages with systemd with sockets support (not supported
on CentOS 7), network interfaces are configured using systemd drop-in files.

Each protocol has its own configuration file. *By default, these are configured
to listen on localhost.*

.. csv-table::
  :header: "**Network protocol**", "**Socket file name**"

  "DNS (UDP+TCP, :rfc:`1034`)","``kresd.socket``"
  ":ref:`DNS-over-TLS (DoT) <tls-server-config>`","``kresd-tls.socket``"
  ":ref:`mod-http-doh`","``kresd-doh.socket``"
  ":ref:`Web management <mod-http-built-in-services>`","``kresd-webmgmt.socket``"

.. warning:: You MUST NOT repeat the localhost defaults in the following
   drop-in overrides, otherwise the socket will fail to start with "Address in
   use" error. To view the entire socket configuration, including any drop-ins,
   use systemctl cat.

To configure kresd to listen on a **public interface** using the original DNS protocol,
create a drop-in file:

.. code-block:: bash

   $ systemctl edit kresd.socket

.. code-block:: none

   # /etc/systemd/system/kresd.socket.d/override.conf
   # always listen on UDP (datagram) and TCP (stream) as well
   [Socket]
   ListenDatagram=192.0.2.115:53
   ListenStream=192.0.2.115:53

.. note:: If you change network interfaces of systemd sockets for already running
   kresd instance, make sure to call ``systemctl restart system-kresd.slice`` for
   these changes to take effect.

Configuration you provide is automatically merged with defaults from your
distribution. It is also possible to check resulting configuration using
``systemctl cat``:

.. code-block:: bash

   $ systemctl cat kresd.socket

.. code-block:: none

   # merged result: user configuration + distro defaults
   [Socket]
   FileDescriptorName=dns
   FreeBind=true
   BindIPv6Only=both
   ListenDatagram=[::1]:53
   ListenStream=[::1]:53
   ListenDatagram=127.0.0.1:53
   ListenStream=127.0.0.1:53
   ListenDatagram=192.0.2.115:53
   ListenStream=192.0.2.115:53


.. _kresd-socket-override-port:

The default localhost interface/port can also be removed/overriden by using an
empty ``ListenDatagram=`` or ``ListenStream=`` directive. This can be used when
you want to configure kresd to listen on all IPv4/IPv6 network interfaces (if
you've disabled IPv6 support in kernel, use ``0.0.0.0:port`` instead`` ).

.. code-block:: none

   # /etc/systemd/system/kresd.socket.d/override.conf
   [Socket]
   ListenDatagram=
   ListenStream=
   ListenDatagram=53
   ListenStream=53

.. note:: Using IPv6 to bind to IPv4 interfaces is currently not compatible
   with IPv4 syntax in ``view:addr()`` when using the ``view`` module. For
   possible workarounds, see
   https://gitlab.labs.nic.cz/knot/knot-resolver/issues/445

It can also be useful if you want to use the Knot DNS authoritative server
with the `dnsproxy module`_ to have both resolver and authoritative server
running on the same machine. This is not recommended configuration but it can
be done like this:

.. code-block:: none

   # /etc/systemd/system/kresd.socket.d/override.conf
   [Socket]
   ListenDatagram=
   ListenStream=
   ListenDatagram=127.0.0.1:53000
   ListenStream=127.0.0.1:53000
   ListenDatagram=[::1]:53000
   ListenStream=[::1]:53000

.. _kresd-tls-socket-override-port:

The ``kresd-tls.socket`` can also be configured in the same way to listen for
DNS-over-TLS connections (:rfc:`7858`).

.. code-block:: bash

   $ systemctl edit kresd-tls.socket

.. code-block:: none

   # /etc/systemd/system/kresd-tls.socket.d/override.conf
   # specify only TCP (stream), DTLS is not supported
   [Socket]
   ListenStream=192.0.2.115:853

When configuring sockets for :ref:`mod-http-doh`, make sure you have
``kresd-doh.socket`` installed, it might be part of a separate
``knot-resolver-module-http`` package.

.. warning:: Make sure you read section :ref:`mod-http-doh` before exposing
             the DoH protocol to outside.

For example, to remove the default localhost:44353 and listen on all interfaces
on port 443, create the following drop-in file for ``kresd-doh.socket``:

.. code-block:: bash

   $ systemctl edit kresd-doh.socket

.. code-block:: bash

   # /etc/systemd/system/kresd-doh.socket.d/override.conf
   [Socket]
   ListenStream=
   ListenStream=443

Make sure no other service is using port 443, as that will result in
unpredictable behaviour. Alternately, you can use port 44353 where a collision
is unlikely.

Also, don't forget to :ref:`load http module in configuration <mod-http-example>`
file, otherwise the socket won't work.

**Legacy network configuration using configuration file**

If you don't use systemd with sockets to run kresd, addresses and ports to listen
on are configured in the config file.

.. function:: net.listen(addresses, [port = 53, { kind = 'dns' }])

   :return: boolean

   Listen on addresses; port and flags are optional.
   The addresses can be specified as a string or device.
   The command can be given multiple times,
   but repeating an address-port combination is an error.
   Port 853 implies ``kind = 'tls'`` but it is always better to be explicit.

.. csv-table::
  :header: "**Network protocol**", "**Configuration command**"

  "DNS (UDP+TCP, :rfc:`1034`)","``net.listen('192.0.2.123', 53)``"
  ":ref:`DNS-over-TLS (DoT) <tls-server-config>`","``net.listen('192.0.2.123', 853, { kind = 'tls' })``"
  ":ref:`mod-http-doh`","``net.listen('192.0.2.123', 443, { kind = 'doh' })``"
  ":ref:`Web management <mod-http-built-in-services>`","``net.listen('192.0.2.123', 8453, { kind = 'webmgmt' })``"


Examples:

   .. code-block:: lua

	net.listen('::1')
	net.listen(net.lo, 53)
	net.listen(net.eth0, 853, { kind = 'tls' })
	net.listen('::', 443, { kind = 'doh' }) -- see http module
	net.listen('::', 8453, { kind = 'webmgmt' }) -- see http module

.. warning:: Make sure you read section :ref:`mod-http-doh` before exposing
             the DNS-over-HTTP protocol to outside.

.. function:: net.close(address, [port])

   :return: boolean (at least one endpoint closed)

   Close all endpoints listening on the specified address, optionally restricted by port as well.


**Additional network configuration options**

Following commands are useful in special situations and can be usef with and without systemd socket activation:

.. envvar:: net.ipv6 = true|false

   :return: boolean (default: true)

   Enable/disable using IPv6 for contacting upstream nameservers.

.. envvar:: net.ipv4 = true|false

   :return: boolean (default: true)

   Enable/disable using IPv4 for contacting upstream nameservers.

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
DNS-over-TLS server (:rfc:`7858`) is enabled by default on loopback interface port 853.
Information how to configure listening on specific IP addresses is in previous sections
:ref:`network-configuration`.

By default a self-signed certificate is generated. For serious deployments
it is strongly recommended to configure your own TLS certificates signed
by a trusted CA. This is done using function :c:func:`net.tls()`.

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
