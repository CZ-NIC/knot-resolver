.. SPDX-License-Identifier: GPL-3.0-or-later

DNS protocol tweaks
-------------------

Following settings change low-level details of DNS protocol implementation.
Default values should not be changed except for very special cases.

.. function:: net.bufsize([udp_downstream_bufsize][, udp_upstream_bufsize])

   Get/set maximum EDNS payload size advertised in DNS packets. Default is 1232 bytes which was chosed to minimize risk of `issues caused by IP fragmentation <https://blog.apnic.net/2019/07/12/its-time-to-consider-avoiding-ip-fragmentation-in-the-dns/>`_.

   Minimal value allowed by standard :rfc:`6891` is 512 bytes, which is equal to DNS packet size without Extension Mechanisms for DNS. Value 1220 bytes is minimum size required by DNSSEC standard :rfc:`4035`.

   Example output:

   .. code-block:: lua

	-- set downstream and upstream bufsize to value 4096
	> net.bufsize(4096)
	> net.bufsize()
	4096
	4096

	-- set downstream bufsize to 4096 and upstream bufsize to 1232
	> net.bufsize(4096, 1232)
	> net.bufsize()
	4096
	1232

.. include:: ../modules/workarounds/README.rst
