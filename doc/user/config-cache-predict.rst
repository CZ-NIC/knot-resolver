.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-cache-predict:

Prefetching records
===================

Prefetching records helps to keep the cache hot.
It can utilize two independent mechanisms to select the records which should be refreshed:
expiring records and prediction.

Expiring records
----------------

This mechanism is always active when the prefetching is enabled and it is not configurable.

Any time the resolver answers with records that are about to expire,
they get refreshed. Record is expiring if it has less than 1% TTL (or less than 5s).
That improves latency for records which get frequently queried, relatively to their TTL.

Prediction
----------

The resolver can also learn usage patterns and repetitive queries,
though this mechanism is a prototype and **not recommended** for use in production or with high traffic.

For example, if it makes a query every day at 18:00,
the resolver expects that it is needed by that time and prefetches it ahead of time.
This is helpful to minimize the perceived latency and keeps the cache hot.

You can disable prediction by configuring :option:`period <period: <int>>` to ``0``.

.. tip::

   The tracking window and period length determine memory requirements.
   If you have a server with relatively fast query turnover, keep the period low (hour for start) and shorter tracking window (5 minutes).
   For personal slower resolver, keep the tracking window longer (i.e. 30 minutes) and period longer (a day), as the habitual queries occur daily.
   Experiment to get the best results.


Configuration
-------------

.. option:: cache/prediction: true|false|<options>

   :default: false

   .. option:: window: <time ms|s|m|h|d>

      :default: 15m

   .. option:: period: <int>

      :default: 24

Reconfigure the predictor to given tracking window and period length. Both parameters are optional.
Window length is in minutes, period is a number of windows that can be kept in memory.
e.g. if a ``window`` is 15 minutes, a ``period`` of "24" means 6 hours (360 minutes, 15*24=360).

.. code-block:: yaml

   cache:
     # this mode is NOT RECOMMENDED for use in production
     prediction:
       window: 15m  # 15 minutes sampling window
       period: 24   # track last 6 hours

It is also possible to enable prediction with defaults for :option:`window <window: <time ms|s|m|h|d>>` and :option:`period <period: <int>>`.

.. code-block:: yaml

   cache:
     prediction: true

Exported metrics
----------------

To visualize the efficiency of the predictions, following statistics are exported.

* ``predict.epoch`` - current prediction epoch (based on time of day and sampling window)
* ``predict.queue`` - number of queued queries in current window
* ``predict.learned`` - number of learned queries in current window
