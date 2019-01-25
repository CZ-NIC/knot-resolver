
Scripting worker
^^^^^^^^^^^^^^^^

Worker is a service over event loop that tracks and schedules outstanding queries,
you can see the statistics or schedule new queries. It also contains information about
specified worker count and process rank.

.. envvar:: worker.count

   Return current total worker count (e.g. `1` for single-process)

.. envvar:: worker.id

   Return current worker ID (starting from `0` up to `worker.count - 1`)


.. envvar:: worker.pid

   Current worker process PID (number).


.. function:: worker.stats()

   Return table of statistics.

   * ``udp`` - number of outbound queries over UDP
   * ``tcp`` - number of outbound queries over TCP
   * ``ipv6`` - number of outbound queries over IPv6
   * ``ipv4`` - number of outbound queries over IPv4
   * ``timeout`` - number of timeouted outbound queries
   * ``concurrent`` - number of concurrent queries at the moment
   * ``queries`` - number of inbound queries
   * ``dropped`` - number of dropped inbound queries

   Example:

   .. code-block:: lua

	print(worker.stats().concurrent)

