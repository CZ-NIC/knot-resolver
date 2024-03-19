.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-time-jump-detection:

Detect discontinuous jumps in the system time
=============================================

Detect discontinuous jumps in the system time when resolver
is running. It clears cache when a significant backward time jumps occurs.

Time jumps are usually created by NTP time change or by admin intervention.
These change can affect cache records as they store timestamp and TTL in real
time.

If you want to preserve cache during time travel you should disable it:

.. code-block:: yaml

    options:
      time-jump-detection: false

Due to the way monotonic system time works on typical systems,
suspend-resume cycles will be perceived as forward time jumps,
but this direction of shift does not have the risk of using records
beyond their intended TTL, so forward jumps do not cause erasing the cache.

