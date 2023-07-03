.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-cache-prefill:

Cache prefilling
================

This provides ability to periodically prefill the DNS cache by importing root zone data obtained over HTTPS.

Intended users of this module are big resolver operators which will benefit from decreased latencies and smaller amount of traffic towards DNS root servers.


.. option:: cache/prefill: <list>
   .. option:: origin: <zone name>

      Name of the zone, only root zone import is supported at the moment.

   .. option:: url: <url string>

      URL of a file in :rfc:`1035` zone file format.

   .. option:: refresh-interval: <time ms|s|m|h|d>
      :default: 1d

      Time between zone data refresh attempts.

   .. option:: ca-file: <path>

      Path to CA certificate bundle used to authenticate the HTTPS connection (optional, system-wide store will be used if not specified)

.. code-block:: yaml

   cache:
     prefill:
       - origin: "."
         url: https://www.internic.net/domain/root.zone
         refresh-interval: 12h
         ca-file: /etc/pki/tls/certs/ca-bundle.crt

This configuration downloads the zone file from URL `https://www.internic.net/domain/root.zone` and imports it into the cache every day. The HTTPS connection is authenticated using a CA certificate from file `/etc/pki/tls/certs/ca-bundle.crt` and signed zone content is validated using DNSSEC.

The root zone to be imported must be signed using DNSSEC and the resolver must have a valid DNSSEC configuration.


Dependencies
------------

Prefilling depends on the lua-http_ library.

.. _lua-http: https://luarocks.org/modules/daurnimator/http
