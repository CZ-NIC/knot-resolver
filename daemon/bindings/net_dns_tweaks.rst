.. SPDX-License-Identifier: GPL-3.0-or-later

DNS protocol tweaks
-------------------

Following settings change low-level details of DNS protocol implementation.
Default values should not be changed except for very special cases.

.. function:: net.bufsize([udp_downstream_bufsize][, udp_upstream_bufsize])

   Get/set maximum EDNS payload size advertised in DNS packets. Different values can be configured for communication downstream (towards clients) and upstream (towards other DNS servers). Set and also get operations use values in this order.

   Default is 1232 bytes which was chosed to minimize risk of `issues caused by IP fragmentation <https://blog.apnic.net/2019/07/12/its-time-to-consider-avoiding-ip-fragmentation-in-the-dns/>`_. Further details can be found at `DNS Flag Day 2020 <https://dnsflagday.net/2020/>`_ web site.

   Minimal value allowed by standard :rfc:`6891` is 512 bytes, which is equal to DNS packet size without Extension Mechanisms for DNS. Value 1220 bytes is minimum size required by DNSSEC standard :rfc:`4035`.

   Example output:

   .. code-block:: lua

	-- set downstream and upstream bufsize to value 4096
	> net.bufsize(4096)
	-- get configured downstream and upstream bufsizes, respectively
	> net.bufsize()
	4096	-- result # 1
	4096	-- result # 2

	-- set downstream bufsize to 4096 and upstream bufsize to 1232
	> net.bufsize(4096, 1232)
	-- get configured downstream and upstream bufsizes, respectively
	> net.bufsize()
	4096	-- result # 1
	1232	-- result # 2

.. include:: ../modules/workarounds/README.rst
