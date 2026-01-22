.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-cache-gc-prefetch:

Cache GC and prefetch
=====================

These two components help maintaining the cache utilization.
While garbage collector evicts old and less useful records,
prefetch updates expiring records which are frequently accessed.
They have in some sense opposite goals,
so see the last section of this page to recognize possible clashes.

To compare the usefulness of the records,
both of them use statistics on accesses to individual records
stored in the KRU data structure beside the cache data.
In particular, we store exponentially decreasing counters of accesses to the records
which are for the purposes of garbage collector divided by the sizes of the records;
we multiply them back for use in the prefetch.
The higher the value is, the more useful is the record.
The reason for the difference in the metrics of GC and prefetch is
that GC maintains space as the limited resource, so accesses per byte are used;
prefetch on the other hand considers only the access frequency.
The exponential decay makes the value halve in 5 hours.


.. _config-cache-gc:

Garbage collector
-----------------

Garbage collector keeps free space in cache for new records
by evicting existing ones.

The garbage collection process is spawned in a regular time intervals,
each time checking whether the occupied space exceeded a threshold.
If the threshold is exceeded, the content of the cache is analysed
and a set percentage of the occupied space is released.
Furthermore, if prefetch is enabled, a higher percentage of the occupied space is considered
and scheduled updates are cancelled in this area.
In both cases, the records with the lowest frequency of accesses per byte are chosen.

The analysis is performed by two linear scans of the whole cache.
We assign an integer category number (0--99) to each record
according to its access frequency per byte stored in the KRU table;
the higher the frequency the lower the category number.
In the first pass, the space occupied by individual categories is calculated.
In the second pass, we remove all from a computed limit category to higher numbers
and cancel prefetch from another limit category to higher ones.
Different statistics are computed and logged during the analysis
as described in the :ref:`last section <config-cache-gc-prefetch-clashes>` of this page.

If you experience issues with GC analysis being run too often or similar,
you probably need to increase the :ref:`cache size <config-cache-sizing>`.
The options below allow fine-tuning of GC in non-standard cases;
usually, it is not needed and not recommended to change them.

.. warning::

   Misconfiguration of these options may lead to loosing all the cached data periodically.

   If it happens that the cache is filled up completely,
   kresd will remove all its data as an emergency way how to continue using it.
   This may be caused by too high time interval,
   too high utilization threshold, too low release percentage,
   using dry-run mode or disabling the GC completely.


.. option:: cache/garbage-collector/enable: true|false

   :default: true

   This allows disabling the GC completely;
   nothing will ever be removed from cache until it is filled up and cleared.


.. option:: cache/garbage-collector/interval: <time ms|s|m|h|d>

   :default: 1s

   Time interval how often GC is spawned.

   Usually, GC just checks percentual cache utilization and immediatelly exits,
   so it is recommended to keep the value small.
   Using a large interval may lead to not freeing space in time.


.. option:: cache/garbage-collector/threshold: <0-100>

   :default: 80

   The threshold on the percentual cache utilization;
   if exceeded, cache analysis and follow-up freeing is initiated.
   You have to keep there some margin so that some free space is kept until the next GC cycle.


.. option:: cache/garbage-collector/release: <0-100>

   :default: 10

   Percents of used cache to be released if the analysis is spawned.


.. option:: cache/garbage-collector/unschedule: <0-100>

   :default: 20

   Percents of used cache (incl. the released) for which prefetch is cancelled.


.. option:: cache/garbage-collector/dry-run: true|false

   :default: false

   Perform the analysis if needed, but don't remove anything.

   This may lead to running the potentially expensive cache analysis each time interval
   as nothing is ever removed until filling up.

   If you need to run the analysis only once in this mode,
   you can also spawn the garbage collector binary ``kres-cache-gc`` by yourself;
   execute it with ``-h`` to see the options.


Other options are recognized,
but they only affect some implementation details
and they are generally not useful;
we may also remove/change them anytime.


.. _config-cache-prefetch:

Prefetching expiring records
----------------------------

Prefetching cache records helps to keep the cache hot
by refreshing the records shortly before their expiration.

.. note::

   If you use resolver in :ref:`forwarding mode <config-forward>`, prefetching will probably *not* work well,
   because updating records before expiration might not increase their TTL due to upstream caching.

The current mechanism uses access frequencies to the individual records stored in KRU
to determine which records are useful enough to be updated.
The old mechanisms provided by Lua modules prefetch and predict are now considered obsolete
and cannot be activated from YAML.


.. option:: cache/prefetch/expiring: true|false

   :default: false

   Enables prefetching.


There are two configurable conditions on the access frequency of a record,
both of which have to be met to consider the record eligible for prefetching.


.. option:: cache/prefetch/max-access-period: <time s|m|h|d>

   :default: 1h

   Prefetch only records which are accessed at least once per the given time period.


.. option:: cache/prefetch/min-accesses-per-update: <float>

   :default: 4

   Require at least this number of accesses to the record per automatic update.
   It serves as a guarantee that prefetching will not significantly increase the traffic to authoritative servers.

   Let us denote the min-accesses-per-update by k.
   If we refresh the record for the first time,
   it means that at most one of those k accesses caused a normal update
   and we initiate the other one.
   For successive refreshes, we again require at least other k accesses,
   but this time, there is no need for normal updates, and so only the one refresh is incurred.

If the accesses are regular, their exponentially decreasing counter will converge to the equilibrium,
where the increase in time is the same as the decay.
Each of the last two configuration options gives us the lower bound on this value,
which is checked both at the time of scheduling the update while inserting the record into cache
and just before the update.

Specifically, for the accesses per update requirement we seek a counter value
such that its decrease between the time of insertion and time of update (5s before expiration)
is at least the configured value.
Satisfying this lower bound during insertion assures us
that we will not count the same accesses again during further updates.
For the other condition, we require decrease by one access per the given time period.
As different records have different TTLs,
sometimes one condition may be stricter, sometimes the other.

Prefetch can benefit from activated defer,
in which case it will better recognize when no work is waiting to be processed
and so automatic updates may be invoked.

.. option:: cache/prefetch/prediction/...

   Obsolete, this settings is not used anymore.


.. _config-cache-gc-prefetch-clashes:

Recognizing small cache or too extensive prefetch
-------------------------------------------------

If the cache is not large enough, it may lead to evictions of useful valid RRs,
followed by repetitive queries to upstream even before expiration of original answers
and so to increasing the traffic, cpu consumption and latencies of answers to clients.
Moreover garbage collector may possibly clash with too extensively configured prefetch;
in an extreme case causing alternating updates and evictions of the same RRs.

To recognize these issues, see the output of garbage collector in logs:

.. code-block:: none

   Canceling prefetch for
         #.## MB of kept valid RRs eligible for prefetch (limit category #),
         #.## MB of expired RRs (not updated in time, incl. those for removal);
   removing (limit category #)
         #.## MB /     #.## MB of valid RRs eligible for prefetch,
         #.## MB /     #.## MB of other valid RRs,
         #.## MB /     #.## MB of expired RRs,
         #.## MB /     #.## MB of RTT entries,
         #.## MB /     #.## MB of prefetch entries (incl. cancellation),
         #.## MB /     #.## MB (# records) in total.

Here we see, what is actually removed during garbage collection --
besides resource records,
there are prefetch entries serving as time-ordered pointers to RRs planned for update
and RTT entries allowing comparisons of round-trip times to alternative authoritative servers.

Ideally, we would like to remove only expired RRs,
which are not much useful anymore (unless serving stale answers).
Removing valid RRs may be suboptimal if they are needed in the future,
but we still first remove the less useful ones,
so removing some fraction of them may be also healthy.
If the fraction is higher, consider increasing the cache size.

The real issue is if we are removing valid RRs which are eligible for prefetch,
i.e. they passed the conditions at insertion and still meet the computed lower bound on accesses.
In this case, we need either to increase the cache size or make the prefetch conditions more strict,
not to update so many records.

We may be cautious even if GC cancels scheduled prefetch for valid RRs which are not yet being removed.
In the default settings,
GC frees up 10 % of the occupied capacity and for another 10 % prefetch is cancelled.
This serves as a buffer between records for prefetching and records for removal,
which helps mitigating the clashes.
We however still recommend to adjust the settings if this happens.

Another warning arises from canceling prefetch of expired RRs.
This means that resolver had not enough cpu time
to initiate update of those RRs within 5s time period before their expiration.
If this happens, resolver normally removes those prefetch entries by itself
immediately after entering the prefetch stage when idle, which also wasn't the case.
If you are under DoS attack, this is correct behavior:
defer (if activated) will prioritize client's requests and prefetch will not be used at all.
If this happens repeatedly under normal load,
make prefetch conditions more strict.
These prefetch entries may also be a relict after disabling prefetch,
in which case resolver just ignores them, or after some period of not running the resolver at all.
