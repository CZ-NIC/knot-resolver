.. _mod-dot:

DNS-over-TLS (DoT) Auto-discovery
---------------------------------

DoT module enables automatic discovery of authoritative servers' SPKI
fingerprint via the use of magic NS names. It is very similar to `dnscurve`_ mechanism.

.. warning:: This module is experimental.

Requirements
^^^^^^^^^^^^

At the time of this writting, this module is to be built on top of the
`cloudflare`_ branch of knot-resolver.

How it works
^^^^^^^^^^^^

The module will look for NS target names formatted as:
``dot-{base32(sha256(SPKI))}....``

For instance:

.. code-block:: bash
  example.com NS dot-tpwxmgqdaurcqxqsckxvdq5sty3opxlgcbjj43kumdq62kpqr72a.example.com

will automatically discover that example.com NS supports DoT with the base64-encoded SPKI digest of ``m+12GgMFIiheEhKvUcOynjbn3WYQUp5tVGDh7Snwj/Q=``
and will associate it with the IPs of ``dot-tpwxmgqdaurcqxqsckxvdq5sty3opxlgcbjj43kumdq62kpqr72a.example.com``.

In that example, the base32 encoded (no padding) version of the sha256 PIN is ``tpwxmgqdaurcqxqsckxvdq5sty3opxlgcbjj43kumdq62kpqr72a``, which when
converted to base64 translates to ``m+12GgMFIiheEhKvUcOynjbn3WYQUp5tVGDh7Snwj/Q=``.

Generating NS targets
^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^

To enable the module, add this stanza to your config:

.. code-block:: lua

	-- Load the module
	modules.load('dot')

Caveats
^^^^^^^

The module relies on seeing the reply of the NS query and as such will not work
if knot-resolver use its cache. You may need to delete the cache before starting ``kresd`` to work around this.

The module also assumes that the NS query answer will return both the NS targets in the Authority section as well as the glue records in the Additional section.

.. _dnscurve: https://dnscurve.org/
.. _cloudflare: https://gitlab.labs.nic.cz/knot/knot-resolver/tree/cloudflare
