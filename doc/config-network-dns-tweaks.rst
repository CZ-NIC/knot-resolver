.. SPDX-License-Identifier: GPL-3.0-or-later

DNS protocol tweaks
-------------------

Following settings change low-level details of DNS protocol implementation.
Default values should not be changed except for very special cases.

.. option:: network/edns-buffer-size: <options>

   Maximum EDNS payload size advertised in DNS packets.
   Different values can be configured for communication downstream (towards clients) and upstream (towards other DNS servers).

   .. option:: upstream <size B|K|M|G>

      :default: 1232B

   .. option:: downstream <size B|K|M|G>

      :default: 1232B

   Default 1232 bytes was chosen to minimize risk of `issues caused by IP fragmentation <https://blog.apnic.net/2019/07/12/its-time-to-consider-avoiding-ip-fragmentation-in-the-dns/>`_.
   Further details can be found at `DNS Flag Day 2020 <https://www.dnsflagday.net/2020/>`_ web site.

   Minimal value allowed by standard :rfc:`6891` is 512 bytes, which is equal to DNS packet size without Extension Mechanisms for DNS.
   Value 1220 bytes is minimum size required by DNSSEC standard :rfc:`4035`.

   .. code-block:: yaml

      network:
        edns-buffer-size:
          upstream: 4096B
          downstream: 1232B

.. .. include:: ../modules/workarounds/README.rst

.. option:: options/violators-workarounds: true|false

   :default: false

   Workarounds resolve behavior on specific broken sub-domains.
   Currently it mainly disables case randomization.

   .. code-block:: yaml

      options:
         violators-workarounds: true
