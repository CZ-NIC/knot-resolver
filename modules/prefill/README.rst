.. _mod-prefill:

Cache prefilling
================

This module provides ability to periodically prefill DNS cache by importing root zone data obtained over HTTPS.

Intended users of this module are big resolver operators which will benefit from decreased latencies and smaller amount of traffic towards DNS root servets.

Example configuration is:

.. code-block:: lua

	modules.load('prefill')
	prefill.config({
              ['.'] = {
                      url = 'https://www.internic.net/domain/root.zone',
                      interval = 86400  -- seconds
                      ca_file = '/etc/pki/tls/certs/ca-bundle.crt', -- optional
              }
        })

This configuration downloads zone file from URL `https://www.internic.net/domain/root.zone` and imports it into cache every 86400 seconds (1 day). The HTTPS connection is authenticated using CA certificate from file `/etc/pki/tls/certs/ca-bundle.crt` and signed zone content is validated using DNSSEC.

Root zone to import must be signed using DNSSEC and the resolver must have valid DNSSEC configuration.

.. csv-table::
 :header: "Parameter", "Description"

 "ca_file", "path to CA certificate bundle used to authenticate the HTTPS connection (optional, system-wide store will be used if not specified)"
 "interval", "number of seconds between zone data refresh attempts"
 "url", "URL of a file in :rfc:`1035` zone file format"

Only root zone import is supported at the moment.

Dependencies
------------

Prefilling depends on the lua-http_ library.

.. _lua-http: https://luarocks.org/modules/daurnimator/http
