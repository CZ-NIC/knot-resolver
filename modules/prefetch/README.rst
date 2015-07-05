.. _mod-prefetch:

Prefetching records
-------------------

The module tracks expiring records (having less than 5% of original TTL) and batches them for prefetch.
This improves latency for frequently used records, as they are fetched in advance.

.. todo:: Learn usage patterns from browser history, track usage pattern over time.