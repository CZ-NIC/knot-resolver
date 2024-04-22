.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-prefetch:

Expiring records
----------------

The ``prefetch`` module helps to keep the cache hot by prefetching expiring records.

This mechanism is activated when the module is loaded and it is not configurable.

.. code-block:: lua

	modules.load('prefetch')


Any time the resolver answers with records that are about to expire, they get refreshed. (see :c:func:`is_expiring`)
That improves latency for records which get frequently queried, relatively to their TTL.
