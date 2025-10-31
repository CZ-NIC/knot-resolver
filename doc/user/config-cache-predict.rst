.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-cache-predict:

Prefetching cache records
=========================

Prefetching cache records helps to keep the cache hot.
You can use two independent mechanisms to select the records which should be refreshed.

Expiring records
----------------

Any time the resolver answers with records that are about to expire,
they get refreshed. Record is expiring if it has less than 1% TTL (or less than 5s).
That improves latency for records which get frequently queried, relatively to their TTL.

.. code-block:: yaml

   cache:
     prefetch:
       # enabling prefetching of expiring records, 'false' is default
       expiring: true


Prediction
----------

The resolver can learn usage patterns and repetitive queries,
though this mechanism is a prototype and **not recommended** for use in production or with high traffic.

.. code-block:: yaml

   cache:
     prefetch:
       # this mode is NOT RECOMMENDED for use in production
       prediction:
         enable: true
         # optionally, you can edit prediction configuration
         window: 15m  # default, 15 minutes sampling window
         period: 24   # default, track last 6 hours


Window length is in minutes, period is a number of windows that can be kept in memory.
e.g. if a ``window`` is 15 minutes, a ``period`` of "24" means 6 hours (360 minutes, 15*24=360).

For example, if it makes a query every day at 18:00,
the resolver expects that it is needed by that time and prefetches it ahead of time.
This is helpful to minimize the perceived latency and keeps the cache hot.

.. tip::

   The tracking window and period length determine memory requirements.
   If you have a server with relatively fast query turnover, keep the period low (hour for start) and shorter tracking window (5 minutes).
   For personal slower resolver, keep the tracking window longer (i.e. 30 minutes) and period longer (a day), as the habitual queries occur daily.
   Experiment to get the best results.


Exported metrics
****************

To visualize the efficiency of the predictions, following statistics are exported.

* ``/predict/epoch`` - current prediction epoch (based on time of day and sampling window)
* ``/predict/queue`` - number of queued queries in current window
* ``/predict/learned`` - number of learned queries in current window
