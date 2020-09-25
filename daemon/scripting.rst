.. SPDX-License-Identifier: GPL-3.0-or-later

.. _runtime-cfg:

Run-time reconfiguration
========================

Knot Resolver offers several ways to modify its configuration at run-time:

  - Using control socket driven by an external system
  - Using Lua program embeded in Resolver's configuration file

Both ways can also be combined: For example the configuration file can contain
a little Lua function which gathers statistics and returns them in JSON string.
This can be used by an external system which uses control socket to call this
user-defined function and to retrieve its results.


.. _control-sockets:

Control sockets
---------------
Control socket acts like "an interactive configuration file" so all actions
available in configuration file can be executed interactively using the control
socket. One possible use-case is reconfiguring Resolver instances from another
program, e.g. a maintenance script.

.. note:: Each instance of Knot Resolver exposes its own control socket. Take
   that into account when scripting deployments with
   :ref:`systemd-multiple-instances`.

When Knot Resolver is started using Systemd (see section
:ref:`quickstart-startup`) it creates a control socket in path
``/run/knot-resolver/control/$ID``. Connection to the socket can
be made from command line using e.g. ``netcat`` or ``socat``:

.. code-block:: bash

   $ nc -U /run/knot-resolver/control/1
   or
   $ socat - UNIX-CONNECT:/run/knot-resolver/control/1

When successfully connected to a socket, the command line should change to
something like ``>``.  Then you can interact with kresd to see configuration or
set a new one.  There are some basic commands to start with.

.. code-block:: lua

   > help()            -- shows help
   > net.interfaces()  -- lists available interfaces
   > net.list()        -- lists running network services


The *direct output* of commands sent over socket is captured and sent back,
while also printed to the daemon standard outputs (in :func:`verbose` mode).
This gives you an immediate response on the outcome of your command.  Error or
debug logs aren't captured, but you can find them in the daemon standard
outputs.

Control sockets are also a way to enumerate and test running instances, the
list of sockets corresponds to the list of processes, and you can test the
process for liveliness by connecting to the UNIX socket.

Lua scripts
-----------

As it was mentioned in section :ref:`config-syntax`, Resolver's configuration
file contains program in Lua programming language. This allows you to write
dynamic rules and helps you to avoid repetitive templating that is unavoidable
with static configuration. For example parts of configuration can depend on
:func:`hostname` of the machine:

.. code-block:: lua

	if hostname() == 'hidden' then
		net.listen(net.eth0, 5353)
	else
		net.listen('127.0.0.1')
                net.listen(net.eth1.addr[1])
	end

Another example would show how it is possible to bind to all interfaces, using
iteration.

.. code-block:: lua

	for name, addr_list in pairs(net.interfaces()) do
		net.listen(addr_list)
	end

.. tip:: Some users observed a considerable, close to 100%, performance gain in
   Docker containers when they bound the daemon to a single interface:ip
   address pair. One may expand the aforementioned example with browsing
   available addresses as:

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

Helper functions
^^^^^^^^^^^^^^^^
Following built-in functions are useful for scripting:

.. envvar:: env (table)

   Retrieve environment variables.

   Example:

   .. code-block:: lua

	env.USER -- equivalent to $USER in shell

.. function:: fromjson(JSONstring)

   :return: Lua representation of data in JSON string.

   Example:

      .. code-block:: lua

        > fromjson('{"key1": "value1", "key2": {"subkey1": 1, "subkey2": 2}}')
        [key1] => value1
        [key2] => {
            [subkey1] => 1
            [subkey2] => 2
        }


.. function:: hostname([fqdn])

   :return: Machine hostname.

   If called with a parameter, it will set kresd's internal
   hostname. If called without a parameter, it will return kresd's
   internal hostname, or the system's POSIX hostname (see
   gethostname(2)) if kresd's internal hostname is unset.

   This also affects ephemeral (self-signed) certificates generated by kresd
   for DNS over TLS.

.. function:: package_version()

   :return: Current package version as string.

   Example:

      .. code-block:: lua

         > package_version()
         2.1.1

.. function:: resolve(name, type[, class = kres.class.IN, options = {}, finish = nil, init = nil])

   :param string name: Query name (e.g. 'com.')
   :param number type: Query type (e.g. ``kres.type.NS``)
   :param number class: Query class *(optional)* (e.g. ``kres.class.IN``)
   :param strings options: Resolution options (see :c:type:`kr_qflags`)
   :param function finish: Callback to be executed when resolution completes (e.g. `function cb (pkt, req) end`). The callback gets a packet containing the final answer and doesn't have to return anything.
   :param function init: Callback to be executed with the :c:type:`kr_request` before resolution starts.
   :return: boolean, ``true`` if resolution was started

   The function can also be executed with a table of arguments instead. This is
   useful if you'd like to skip some arguments, for example:

   .. code-block:: lua

      resolve {
         name = 'example.com',
         type = kres.type.AAAA,
         init = function (req)
         end,
      }

   Example:

   .. code-block:: lua

      -- Send query for root DNSKEY, ignore cache
      resolve('.', kres.type.DNSKEY, kres.class.IN, 'NO_CACHE')

      -- Query for AAAA record
      resolve('example.com', kres.type.AAAA, kres.class.IN, 0,
      function (pkt, req)
         -- Check answer RCODE
         if pkt:rcode() == kres.rcode.NOERROR then
            -- Print matching records
            local records = pkt:section(kres.section.ANSWER)
            for i = 1, #records do
               local rr = records[i]
               if rr.type == kres.type.AAAA then
                  print ('record:', kres.rr2str(rr))
               end
            end
         else
            print ('rcode: ', pkt:rcode())
         end
      end)


.. function:: tojson(object)

   :return: JSON text representation of `object`.

   Example:

   .. code-block:: lua

      > testtable = { key1 = "value1", "key2" = { subkey1 = 1, subkey2 = 2 } }
      > tojson(testtable)
      {"key1":"value1","key2":{"subkey1":1,"subkey2":2}}


.. _async-events:

Asynchronous events
-------------------

Lua language used in configuration file allows you to script actions upon
various events, for example publish statistics each minute. Following example
uses built-in function :func:`event.recurrent()` which calls user-supplied
anonymous function:

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


Note that each scheduled event is identified by a number valid for the duration
of the event, you may use it to cancel the event at any time.

To persist state between two invocations of a fuction Lua uses concept called
closures_. In the following example function ``speed_monitor()`` is a closure
function, which provides persistent variable called ``previous``.

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

Another type of actionable event is activity on a file descriptor. This allows
you to embed other event loops or monitor open files and then fire a callback
when an activity is detected.  This allows you to build persistent services
like monitoring probes that cooperate well with the daemon internal operations.
See :func:`event.socket()`.

Filesystem watchers are possible with :func:`worker.coroutine()` and cqueues_,
see the cqueues documentation for more information. Here is an simple example:

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

.. include:: ../modules/etcd/README.rst

.. _closures: https://www.lua.org/pil/6.1.html
.. _cqueues: https://25thandclement.com/~william/projects/cqueues.html
.. _LuaRocks: https://luarocks.org/
