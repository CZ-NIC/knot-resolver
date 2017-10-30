.. _mod-ta_signal_query:

Signaling Trust Anchor Knowledge in DNSSEC
------------------------------------------

The module for Signaling Trust Anchor Knowledge in DNSSEC Using Key Tag Query,
implemented according to RFC 8145 section 5.

This feature allows validating resolvers to signal to authoritative servers
which keys are referenced in their chain of trust. The data from such
signaling allow zone administrators to monitor the progress of rollovers
in a DNSSEC-signed zone.

This mechanism serve to measure the acceptance and use of new DNSSEC
trust anchors and key signing keys (KSKs). This signaling data can be
used by zone administrators as a gauge to measure the successful deployment
of new keys. This is of particular interest for the DNS root zone in the event
of key and/or algorithm rollovers that rely on RFC 5011 to automatically
update a validating DNS resolver’s trust anchor.

.. tip:: It is recommended to always keep this module enabled.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: lua

	-- Signal trust anchor keys configured in the validator
	modules = { 'ta_signal_query' }
