.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-defer:

Request prioritization (defer)
==============================

Defer tries to mitigate DoS attacks by measuring cpu time consumption of different hosts and networks
and deferring future requests from the same origin.
If there is not enough time to process all the requests, the lowest priority ones are dropped.

The time measurements are taken into account only for TCP-based queries (including DoT and DoH),
as the source address of plain UDP can be forged.
We aim to spend half of the time for UDP without prioritization
and half of the time for non-UDP with prioritization,
if there are enough requests of both types.

Detailed configuration is printed by ``defer`` group on ``info`` level on startup (unless disabled).

The limits can be adjusted for different packet origins using :option:`price-factor <price-factor: <float>` in :ref:`views <config-views>`.

.. note::

   The data of all deferred queries may occupy 64 MiB of memory per :ref:`worker <config-multiple-workers>`.

.. option:: defer/enable: true|false

    :default: false

    Enable request prioritization.

    If disabled, requests are processed in order of their arrival
    and their possible dropping in case of overloading
    is caused only by the overflow of kernel queues.


.. option:: defer/log-period: <time ms|s|m|h|d>

    :default: 0s

    Minimal time between two log messages, or ``0s`` to disable logging.

    If a response is dropped after being deferred for too long, the address is logged
    and logging is disabled for the :option:`log-period <defer/log-period: <time ms|s|m|h|d>`.
    As long as dropping is needed, one source is logged each period
    and sources with more dropped queries have greater probability to be chosen.


Implementation details
----------------------

Internally, defer uses similar approach as :ref:`rate limiting <config-rate-limiting>`,
except that cpu time is measured instead of counting requests.

There are four main priority levels with assigned rate and instant limits for individual hosts
and their multiples for networks -- the same prefix lengths and multipliers are used as for rate limiting.
Within a priority level, requests are ordered by the longest prefix length,
on which it falls into that level,
so that we first process requests that are on that level only as part of a larger network
and then requests that fall there also due to a smaller subnetwork,
which possibly caused deprioritization of the larger network.
Further ordering is according to the time of arrival.

If a request is deferred for too long, it gets dropped.
This can happen also for UDP requests,
which are stored in a single queue ordered by the time of their arrival.

