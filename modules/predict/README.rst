.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-predict:

Prefetching records
===================

The module refreshes records that are about to expire when they're used (having less than 1% of original TTL).
This improves latency for frequently used records, as they are fetched in advance.

It is also able to learn usage patterns and repetitive queries that the server makes. For example, if
it makes a query every day at 18:00, the resolver expects that it is needed by that time and prefetches it
ahead of time. This is helpful to minimize the perceived latency and keeps the cache hot.

.. tip:: The tracking window and period length determine memory requirements. If you have a server with relatively fast query turnover, keep the period low (hour for start) and shorter tracking window (5 minutes). For personal slower resolver, keep the tracking window longer (i.e. 30 minutes) and period longer (a day), as the habitual queries occur daily. Experiment to get the best results.

Example configuration
---------------------

.. code-block:: lua

	modules = {
		predict = {
			window = 15, -- 15 minutes sampling window
			period = 6*(60/15) -- track last 6 hours
		}
	}

Defaults are 15 minutes window, 6 hours period.

.. tip:: Use period 0 to turn off prediction and just do prefetching of expiring records.
    That works even without the :ref:`stats <mod-stats>` module.

.. note:: Otherwise this module requires :ref:`stats <mod-stats>` module and loads it if not present.

Exported metrics
----------------

To visualize the efficiency of the predictions, the module exports following statistics.

* ``predict.epoch`` - current prediction epoch (based on time of day and sampling window)
* ``predict.queue`` - number of queued queries in current window
* ``predict.learned`` - number of learned queries in current window


Properties
----------

.. function:: predict.config({ window = 15, period = 24})

  Reconfigure the predictor to given tracking window and period length. Both parameters are optional.
  Window length is in minutes, period is a number of windows that can be kept in memory.
  e.g. if a ``window`` is 15 minutes, a ``period`` of "24" means 6 hours.
