.. SPDX-License-Identifier: GPL-3.0-or-later

Scripting worker
^^^^^^^^^^^^^^^^

Worker is a service over event loop that tracks and schedules outstanding queries,
you can see the statistics or schedule new queries. It also contains information about
specified worker count and process rank.

.. envvar:: worker.id

   Value from environment variable ``SYSTEMD_INSTANCE``,
   or if it is not set, :envvar:`PID <worker.pid>` (string).

.. envvar:: worker.pid

   Current worker process PID (number).

.. function:: worker.stats()

   Return table of statistics.  See member descriptions in :c:type:`worker_stats`.
   A few fields are added, mainly from POSIX ``getrusage()``:

   * ``usertime`` and ``systime`` -- CPU time used, in seconds
   * ``pagefaults`` -- the number of hard page faults, i.e. those that required I/O activity
   * ``swaps`` -- the number of times the process was “swapped” out of main memory; unused on Linux
   * ``csw`` -- the number of context switches, both voluntary and involuntary
   * ``rss`` -- current memory usage in bytes, including whole cache (resident set size)

   Example:

   .. code-block:: lua

	print(worker.stats().concurrent)

