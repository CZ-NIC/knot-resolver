.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-ta_sentinel:

Sentinel for Detecting Trusted Root Keys
========================================

The module ``ta_sentinel`` implements A Root Key Trust Anchor Sentinel for DNSSEC
according to standard :rfc:`8509`.

This feature allows users of DNSSEC validating resolver to detect which root keys
are configured in resolver's chain of trust. The data from such
signaling are necessary to monitor the progress of the DNSSEC root key rollover
and to detect potential breakage before it affect users. One example of research enabled by this module `is available here <https://www.potaroo.net/ispcol/2018-11/kskpm.html>`_.

This module is enabled by default and we urge users not to disable it.
If it is absolutely necessary you may add ``modules.unload('ta_sentinel')``
to your configuration to disable it.
