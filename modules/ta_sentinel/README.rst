.. _mod-ta_sentinel:

Sentinel for Detecting Trusted Keys
-----------------------------------

The module implementing Sentinel for Detecting Trusted Keys in DNSSEC
according to `draft-ietf-dnsop-kskroll-sentinel-00`_.

This feature allows users of validating resolver to detect which root keys
are configured in their chain of trust. The data from such
signaling are necessary to monitor the progress of the DNSSEC root key rollover.

This module is enabled by default and we urge users not to disable it.
If it is absolutely necessary you may add ``modules.unload('ta_sentinel')``
to your configuration to disable it.

.. _`draft-ietf-dnsop-kskroll-sentinel-00`: https://tools.ietf.org/html/draft-ietf-dnsop-kskroll-sentinel-00
