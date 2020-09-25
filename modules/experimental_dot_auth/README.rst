.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-experimental_dot_auth:

Experimental DNS-over-TLS Auto-discovery
========================================

This experimental module provides automatic discovery of authoritative servers' supporting DNS-over-TLS.
The module uses magic NS names to detect SPKI_ fingerprint which is very similar to `dnscurve`_ mechanism.

.. warning:: This protocol and module is experimental and can be changed or removed at any time. Use at own risk, security properties were not analyzed!

How it works
------------

The module will look for NS target names formatted as:
``dot-{base32(sha256(SPKI))}....``

For instance, Knot Resolver will detect NS names formatted like this

.. code-block:: none

  example.com NS dot-tpwxmgqdaurcqxqsckxvdq5sty3opxlgcbjj43kumdq62kpqr72a.example.com

and automatically discover that example.com NS supports DoT with the base64-encoded SPKI digest of ``m+12GgMFIiheEhKvUcOynjbn3WYQUp5tVGDh7Snwj/Q=``
and will associate it with the IPs of ``dot-tpwxmgqdaurcqxqsckxvdq5sty3opxlgcbjj43kumdq62kpqr72a.example.com``.

In that example, the base32 encoded (no padding) version of the sha256 PIN is ``tpwxmgqdaurcqxqsckxvdq5sty3opxlgcbjj43kumdq62kpqr72a``, which when
converted to base64 translates to ``m+12GgMFIiheEhKvUcOynjbn3WYQUp5tVGDh7Snwj/Q=``.

Generating NS target names
--------------------------

To generate the NS target name, use the following command to generate the base32 encoded string of the SPKI fingerprint:

.. code-block:: bash

  openssl x509 -in /path/to/cert.pem  -pubkey -noout | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | \
  base32 | tr -d '=' | tr '[:upper:]' '[:lower:]'
  tpwxmgqdaurcqxqsckxvdq5sty3opxlgcbjj43kumdq62kpqr72a

Then add a target to your NS with: ``dot-${b32}.a.example.com``

Finally, map ``dot-${b32}.a.example.com`` to the right set of IPs.

.. code-block:: bash

  ...
  ...
  ;; QUESTION SECTION:
  ;example.com.      IN      NS

  ;; AUTHORITY SECTION:
  example.com. 3600  IN      NS      dot-tpwxmgqdaurcqxqsckxvdq5sty3opxlgcbjj43kumdq62kpqr72a.a.example.com.
  example.com. 3600  IN      NS      dot-tpwxmgqdaurcqxqsckxvdq5sty3opxlgcbjj43kumdq62kpqr72a.b.example.com.

  ;; ADDITIONAL SECTION:
  dot-tpwxmgqdaurcqxqsckxvdq5sty3opxlgcbjj43kumdq62kpqr72a.a.example.com. 3600 IN A 192.0.2.1
  dot-tpwxmgqdaurcqxqsckxvdq5sty3opxlgcbjj43kumdq62kpqr72a.b.example.com. 3600 IN AAAA 2001:DB8::1
  ...
  ...

Example configuration
---------------------

To enable the module, add this snippet to your config:

.. code-block:: lua

        -- Start an experiment, use with caution
	modules.load('experimental_dot_auth')

This module requires standard ``basexx`` Lua library which is typically provided by ``lua-basexx`` package.

Caveats
-------

The module relies on seeing the reply of the NS query and as such will not work
if Knot Resolver uses data from its cache. You may need to delete the cache before starting ``kresd`` to work around this.

The module also assumes that the NS query answer will return both the NS targets in the Authority section as well as the glue records in the Additional section.

Dependencies
------------

* `lua-basexx <https://github.com/aiq/basexx>`_ available in LuaRocks

.. _dnscurve: https://dnscurve.org/
.. _SPKI: https://en.wikipedia.org/wiki/Simple_public-key_infrastructure
