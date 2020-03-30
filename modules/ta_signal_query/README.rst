.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-ta_signal_query:

Signaling Trust Anchor Knowledge in DNSSEC
==========================================

The module for Signaling Trust Anchor Knowledge in DNSSEC Using Key Tag Query,
implemented according to :rfc:`8145#section-5`.

This feature allows validating resolvers to signal to authoritative servers
which keys are referenced in their chain of trust. The data from such
signaling allow zone administrators to monitor the progress of rollovers
in a DNSSEC-signed zone.

This mechanism serve to measure the acceptance and use of new DNSSEC
trust anchors and key signing keys (KSKs). This signaling data can be
used by zone administrators as a gauge to measure the successful deployment
of new keys. This is of particular interest for the DNS root zone in the event
of key and/or algorithm rollovers that rely on :rfc:`5011` to automatically
update a validating DNS resolver’s trust anchor.

.. attention::
   Experience from root zone KSK rollover in 2018 shows that this mechanism
   by itself is not sufficient to reliably measure acceptance of the new key.
   Nevertheless, some DNS researchers found it is useful in combination
   with other data so we left it enabled for now. This default might change
   once more information is available.

This module is enabled by default. You may use ``modules.unload('ta_signal_query')``
in your configuration.
