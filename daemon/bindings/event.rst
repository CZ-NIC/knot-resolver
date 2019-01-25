
Timers and events
^^^^^^^^^^^^^^^^^

The timer represents exactly the thing described in the examples - it allows you to execute closures
after specified time, or event recurrent events. Time is always described in milliseconds,
but there are convenient variables that you can use - ``sec, minute, hour``.
For example, ``5 * hour`` represents five hours, or 5*60*60*100 milliseconds.

.. function:: event.after(time, function)

   :return: event id

   Execute function after the specified time has passed.
   The first parameter of the callback is the event itself.

   Example:

   .. code-block:: lua

      event.after(1 * minute, function() print('Hi!') end)

.. function:: event.recurrent(interval, function)

   :return: event id

   Similar to :func:`event.after()`, periodically execute function after ``interval`` passes.

   Example:

   .. code-block:: lua

      msg_count = 0
      event.recurrent(5 * sec, function(e)
         msg_count = msg_count + 1
         print('Hi #'..msg_count)
      end)

.. function:: event.reschedule(event_id, timeout)

   Reschedule a running event, it has no effect on canceled events.
   New events may reuse the event_id, so the behaviour is undefined if the function
   is called after another event is started.

   Example:

   .. code-block:: lua

      local interval = 1 * minute
      event.after(1 * minute, function (ev)
         print('Good morning!')
         -- Halven the interval for each iteration
         interval = interval / 2
         event.reschedule(ev, interval)
      end)

.. function:: event.cancel(event_id)

   Cancel running event, it has no effect on already canceled events.
   New events may reuse the event_id, so the behaviour is undefined if the function
   is called after another event is started.

   Example:

   .. code-block:: lua

      e = event.after(1 * minute, function() print('Hi!') end)
      event.cancel(e)

Watch for file descriptor activity. This allows embedding other event loops or simply
firing events when a pipe endpoint becomes active. In another words, asynchronous
notifications for daemon.

.. function:: event.socket(fd, cb)

   :param number fd: file descriptor to watch
   :param cb: closure or callback to execute when fd becomes active
   :return: event id

   Execute function when there is activity on the file descriptor and calls a closure
   with event id as the first parameter, status as second and number of events as third.

   Example:

   .. code-block:: lua

      e = event.socket(0, function(e, status, nevents)
         print('activity detected')
      end)
      e.cancel(e)

Asynchronous function execution
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The `event` package provides a very basic mean for non-blocking execution - it allows running code when activity on a file descriptor is detected, and when a certain amount of time passes. It doesn't however provide an easy to use abstraction for non-blocking I/O. This is instead exposed through the `worker` package (if `cqueues` Lua package is installed in the system).

.. function:: worker.coroutine(function)

   Start a new coroutine with given function (closure). The function can do I/O or run timers without blocking the main thread. See cqueues_ for documentation of possible operations and synchronization primitives. The main limitation is that you can't wait for a finish of a coroutine from processing layers, because it's not currently possible to suspend and resume execution of processing layers.

   Example:

   .. code-block:: lua

      worker.coroutine(function ()
        for i = 0, 10 do
          print('executing', i)
          worker.sleep(1)
        end
      end)

.. function:: worker.sleep(seconds)

   Pause execution of current function (asynchronously if running inside a worker coroutine).

When daemon is running in forked mode, each process acts independently. This is good because it reduces software complexity and allows for runtime scaling, but not ideal because of additional operational burden.
For example, when you want to add a new policy, you'd need to add it to either put it in the configuration, or execute command on each process independently. The daemon simplifies this by promoting process group leader which is able to execute commands synchronously over forks.

   Example:

   .. code-block:: lua

      worker.sleep(1)

.. function:: map(expr)

   Run expression synchronously over all forks, results are returned as a table ordered as forks. Expression can be any valid expression in Lua.


   Example:

   .. code-block:: lua

      -- Current instance only
      hostname()
      localhost
      -- Mapped to forks
      map 'hostname()'
      [1] => localhost
      [2] => localhost
      -- Get worker ID from each fork
      map 'worker.id'
      [1] => 0
      [2] => 1
      -- Get cache stats from each fork
      map 'cache.stats()'
      [1] => {
          [hit] => 0
          [delete] => 0
          [miss] => 0
          [insert] => 0
      }
      [2] => {
          [hit] => 0
          [delete] => 0
          [miss] => 0
          [insert] => 0
      }

