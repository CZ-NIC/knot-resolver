.. SPDX-License-Identifier: GPL-3.0-or-later

.. _dns-over-xdp:

XDP for higher UDP performance
------------------------------

Using XDP allows significant speedup of UDP packet processing in recent Linux kernels,
especially with some network drivers that implement good support.
The basic idea is that for selected packets the Linux networking stack is bypassed,
and some drivers can even directly use the user-space buffers for reading and writing.

.. TODO perhaps some hint/link about how significant speedup one might get? (link to some talk video?)

Prerequisites
^^^^^^^^^^^^^
.. this is mostly copied from knot-dns doc/operations.rst

* Linux kernel 4.18+ (5.x+ is recommended for optimal performance) compiled with
  the `CONFIG_XDP_SOCKETS=y` option. XDP isn't supported in other operating systems.
* libknot compiled with XDP support
* A multiqueue network card with native XDP support is highly recommended,
  otherwise the performance gains will be much lower.
  Successfully tested cards:

  * Intel series 700 (driver `i40e`), maximum number of channels per interface is 64.
  * Intel series 500 (driver `ixgbe`), maximum number of channels per interface is 64.
    The number of CPUs available has to be at most 64!

Set up
^^^^^^
.. first parts are mostly copied from knot-dns doc/operations.rst

The server instances need additional Linux **capabilities** during startup.
(Or you could start them as `root`.)
Execute command

.. code-block:: bash

	systemctl edit kresd@.service #FIXME: verify

And insert these lines:

.. code-block:: ini

	[Service]
	CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_RESOURCE
	AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_RESOURCE

.. TODO suggest some way for ethtool -L?  Perhaps via systemd units?

You want the same number of kresd instances and network **queues** on your card;
you can use ``ethtool -L`` before the services start.
With XDP this is more important than with vanilla UDP, as we only support one instance
per queue and unclaimed queues will fall back to vanilla UDP.
Ideally you can set these numbers as high as the number of CPUs that you want kresd to use.

Modification of ``/etc/knot-resolver/kresd.conf`` may be quite simple:

.. code-block:: lua

	net.listen('eth0', 53, { kind = 'xdp', nic_queue = 0 })
	net.listen('192.0.2.1', 53, { kind = 'dns' })

Note that you want to also keep the vanilla DNS line to service TCP
and possibly any fallback UDP (e.g. from unclaimed queues).
XDP listening is in principle done on whole network interfaces
and the target addresses of incoming packets aren't checked in any way,
but you are still allowed to specify interface by an address (if it's unambiguous).

The default ``nic_queue`` value is tailored for the usual naming convention:
``kresd@1.service``, ``kresd@2.service``, ...

Optimizations
^^^^^^^^^^^^^
.. this is basically copied from knot-dns doc/operations.rst

Some helpful commands:

.. code-block:: text

	ethtool -N <interface> rx-flow-hash udp4 sdfn
	ethtool -N <interface> rx-flow-hash udp6 sdfn
	ethtool -L <interface> combined <?>
	ethtool -G <interface> rx <?> tx <?>
	renice -n 19 -p $(pgrep '^ksoftirqd/[0-9]*$')

.. TODO CPU affinities?  `CPUAffinity=%i` in systemd unit sounds good.

Limitations
^^^^^^^^^^^
.. this is basically copied from knot-dns doc/operations.rst

* VLAN segmentation is not supported.
* MTU higher than 1792 bytes is not supported.
* Multiple BPF filters per one network device are not supported.
* Symmetrical routing is required (query source MAC/IP addresses and
  reply destination MAC/IP addresses are the same).
* Systems with big-endian byte ordering require special recompilation of libknot.
* IPv4 header and UDP checksums are not verified on received DNS messages.
* DNS over XDP traffic is not visible to common system tools (e.g. firewall, tcpdump etc.).
* BPF filter is not automatically unloaded from the network device. Manual filter unload::

	ip link set dev <ETH> xdp off

* Knot Resolver only supports using XDP towards clients currently (not towards upstreams).
* When starting up an XDP socket you may get a harmless warning::

	libbpf: Kernel error message: XDP program already attached

