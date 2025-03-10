.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-defer:

Request prioritization (defer)
==============================

Defer tries to mitigate DoS attacks by measuring cpu time consumption of different hosts and networks
and deferring future requests from the same origin.
If there is not enough time to process all the requests, the lowest priority ones are dropped.
It also allows setting a hard timeout on a continuous computation on a single request.

The time measurements are taken into account only for TCP-based queries (including DoT and DoH),
except for hard timeout which is applied for both,
as the source address of plain UDP can be forged.
We aim to spend half of the time for UDP without prioritization
and half of the time for non-UDP with prioritization,
if there are enough requests of both types.

Detailed configuration is printed by ``defer`` group on ``info`` level on startup (unless disabled).

The limits can be adjusted for different packet origins using :option:`price-factor <price-factor: <float>` in :ref:`views <config-views>`.

.. note::

   The data of all deferred queries may occupy 64 MiB of memory per :ref:`worker <config-multiple-workers>`.

.. option:: defer/enabled: true|false

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


.. option:: defer/hard-timeout: <time ms|s|m|h|d>

    :default: 0s

    Time limit for a cpu time consumed continuously on a single request, or ``0s`` to disable.
    It causes crash of kresd if exceeded; use carefully.

    This is intended as a last resort defence against yet unknown bugs
    allowing an attacker to initiate very expensive computations by a single request
    resulting in freezing kresd process for several seconds or minutes.

    It is based on scheduling a SIGALRM to be delivered after the timeout (or up to 1s later),
    which then interrupts the computation.
    After interrupting the priority of the request's origin is decreased according to the duration (if non-UDP),
    the kresd process is terminated (dropping all pending, but probably already timeouted, requests)
    and started again by manager.
    To keep the data with measurements and priorities alive during restart,
    it is crucial to use :ref:`multiple workers <config-multiple-workers>`
    as those data are shared between them and disappear with the last one.

    A continuous work on a single request usually takes under 1 ms.
    Set the timeout to 1s or higher values to avoid random crashes.

.. option:: defer/coredump-period: <time ms|s|m|h|d>

    :defeult: 10m

    Minimal time between two coredumps caused by :option:`hard-timeout <defer/hard-timeout: <time ms|s|m|h|d>`,
    or ``0s`` to disable them.

    If kresd is to be terminated due to :option:`hard-timeout <defer/hard-timeout: <time ms|s|m|h|d>`,
    it calls ``abort``, which might cause coredump to be generated, and disables this behaviour
    for :option:`coredump-period <defer/coredump-period: <time ms|s|m|h|d>`.
    Subsequent terminations call just ``_exit``, so that kresd is terminated without coredump.

    The last abortion timestamp is stored along with other defer data
    in the memory shared between workers which disappears with the last one;
    it is thus needed to use :ref:`multiple workers <config-multiple-workers>`
    to keep the data alive during restart.
    Otherwise, :option:`coredump-period <defer/coredump-period: <time ms|s|m|h|d>` has no effect
    and coredumps are always enabled.


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
