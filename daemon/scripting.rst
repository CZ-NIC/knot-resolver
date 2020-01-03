Run-time reconfiguration
========================

Knot Resolver offers several ways to modify its configuration at run-time:

  - Using control socket driven by an external system
  - Using Lua script embeded in Resolver's configuration file

Control sockets
---------------
Control socket acts like "an interactive configuration file" so all actions available in configuration file can be executed interactively using the control socket. One possible use-case is reconfiguring Resolver instances from another program, e.g. your maintenance script.

.. note::

        Each instance of Knot Resolver exposes its own control socket. Take that into account when scripting deployments with `Multiple instances`_.

When Knot Resolver is started using Systemd (see section :ref:`startup`) it creates a control socket in path ``/run/knot-resolver/control@$INSTANCENAME``. Connection to the socket can be made from command line using e.g. ``netcat`` or ``socat``:

.. code-block:: bash

   $ nc -U /run/knot-resolver/control@1
   or
   $ socat - UNIX-CONNECT:/run/knot-resolver/control@1

When successfully connected to a socket, the command line should change to something like ``>``.
Then you can interact with kresd to see configuration or set a new one.
There are some basic commands to start with.

.. code-block:: lua

   > help()            -- shows help
   > net.interfaces()  -- lists available interfaces
   > net.list()        -- lists running network services


The *direct output* of the CLI command is captured and sent over the socket, while also printed to the daemon standard outputs (for accountability). This gives you an immediate response on the outcome of your command.
Error or debug logs aren't captured, but you can find them in the daemon standard outputs.

Control sockets are also a way to enumerate and test running instances, the list of sockets corresponds to the list
of processes, and you can test the process for liveliness by connecting to the UNIX socket.

Lua scripts
-----------

As it was mentioned in section :ref:`config-syntax`, Resolver's configuration file contains program in Lua programming language. This allows you to write dynamic rules and helps you to avoid repetitive templating that is unavoidable with static configuration. For example parts of configuration can depend on hostname of the machine:

.. code-block:: lua

	if hostname() == 'hidden' then
		net.listen(net.eth0, 5353)
	else
		net.listen('127.0.0.1')
                net.listen(net.eth1.addr[1])
	end

Another example would show how it is possible to bind to all interfaces, using iteration.

.. code-block:: lua

	for name, addr_list in pairs(net.interfaces()) do
		net.listen(addr_list)
	end

.. tip:: Some users observed a considerable, close to 100%, performance gain in Docker containers when they bound the daemon to a single interface:ip address pair. One may expand the aforementioned example with browsing available addresses as:

	.. code-block:: lua

		addrpref = env.EXPECTED_ADDR_PREFIX
		for k, v in pairs(addr_list["addr"]) do
			if string.sub(v,1,string.len(addrpref)) == addrpref then
				net.listen(v)
		...

You can also use third-party Lua libraries (available for example through
LuaRocks_) as on this example to download cache from parent,
to avoid cold-cache start.

.. code-block:: lua

	local http = require('socket.http')
	local ltn12 = require('ltn12')

        local cache_size = 100*MB
        local cache_path = '/var/cache/knot-resolver'
        cache.open(cache_size, 'lmdb://' .. cache_path)
	if cache.count() == 0 then
                cache.close()
		-- download cache from parent
		http.request {
			url = 'http://parent/data.mdb',
			sink = ltn12.sink.file(io.open(cache_path .. '/data.mdb', 'w'))
		}
		-- reopen cache with 100M limit
                cache.open(cache_size, 'lmdb://' .. cache_path)
	end

.. _async-events:

Asynchronous events
-------------------

Lua language used in configuration file allows you to script actions upon
various events, for example publish statistics each minute. Following example uses built-in function :func:`event.recurrent()` which calls user-supplied anonymous function:

.. code-block:: lua

        modules.load('stats')

	-- log statistics every second
	local stat_id = event.recurrent(1 * second, function(evid)
            log(table_print(stats.list()))
	end)

        -- stop printing statistics after first minute
        event.after(1 * minute, function(evid)
                event.cancel(stat_id)
        end)


Note that each scheduled event is identified by a number valid for the duration of the event, you may use it to cancel the event at any time.

To persist state between two invocations of a fuction Lua uses concept called closures_. In the following example function ``speed_monitor()`` is a closure function, which provides persistent variable called ``previous``.

.. code-block:: lua

        modules.load('stats')

	-- make a closure, encapsulating counter
        function speed_monitor()
                local previous = stats.list()
                -- monitoring function
                return function(evid)
                        local now = stats.list()
                        local total_increment = now['answer.total'] - previous['answer.total']
                        local slow_increment = now['answer.slow'] - previous['answer.slow']
                        if slow_increment / total_increment > 0.05 then
                                log('WARNING! More than 5 %% of queries was slow!')
                        end
                        previous = now  -- store current value in closure
                 end
        end

        -- monitor every minute
        local monitor_id = event.recurrent(1 * minute, speed_monitor())

Another type of actionable event is activity on a file descriptor. This allows you to embed other event loops or monitor open files and then fire a callback when an activity is detected.
This allows you to build persistent services like monitoring probes that cooperate well with the daemon internal operations. See :func:`event.socket()`.


Filesystem watchers are possible with :func:`worker.coroutine()` and cqueues_, see the cqueues documentation for more information. Here is an simple example:

.. code-block:: lua

  local notify = require('cqueues.notify')
  local watcher = notify.opendir('/etc')
  watcher:add('hosts')

  -- Watch changes to /etc/hosts
  worker.coroutine(function ()
    for flags, name in watcher:changes() do
      for flag in notify.flags(flags) do
        -- print information about the modified file
        print(name, notify[flag])
      end
    end
  end)

.. include:: ../daemon/bindings/event.rst

.. _closures: https://www.lua.org/pil/6.1.html
.. _cqueues: https://25thandclement.com/~william/projects/cqueues.html
.. _LuaRocks: https://luarocks.org/
