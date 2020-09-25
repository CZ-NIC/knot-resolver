.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-detect_time_skew:

System time skew detector
=========================

This module compares local system time with inception and expiration time
bounds in DNSSEC signatures for ``. NS`` records. If the local system time is
outside of these bounds, it is likely a misconfiguration which will cause
all DNSSEC validation (and resolution) to fail.

In case of mismatch, a warning message will be logged to help with
further diagnostics.

.. warning:: Information printed by this module can be forged by a network attacker!
  System administrator MUST verify values printed by this module and
  fix local system time using a trusted source.

This module is useful for debugging purposes. It runs only once during resolver
start does not anything after that. It is enabled by default.
You may disable the module by appending
``modules.unload('detect_time_skew')`` to your configuration.
