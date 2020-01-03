.. _daemon:

Daemon
======

The server is in the `daemon` directory, it works out of the box without any configuration.

.. code-block:: bash

   $ kresd -v  # run with defaults in verbose mode
   $ kresd -h  # Get help

If you're using our packages, they also provide systemd integration. To start the resolver under systemd, you can use the ``kresd@1.service`` service. By default, the resolver only binds to local interfaces.

.. code-block:: bash

   $ man kresd.systemd  # Help for systemd integration configuration
   $ systemctl start kresd@1.service


Configuration
-------------

.. contents::
   :depth: 2
   :local:

In its simplest form the server requires just a working directory in which it can set up persistent files like
cache and the process state. If you don't provide the working directory by parameter, it is going to make itself
comfortable in the current working directory.

.. code-block:: sh

	$ kresd /var/cache/knot-resolver

And you're good to go for most use cases! If you want to use modules or configure daemon behavior, read on.

There are several choices on how you can configure the daemon, a RPC interface, a CLI, and a configuration file.
Fortunately all share common syntax and are transparent to each other.


Configuration reference
-----------------------

This is a reference for variables and functions available to both configuration file and CLI.

.. contents::
   :depth: 1
   :local:

Environment
^^^^^^^^^^^

.. envvar:: env (table)

   Return environment variable.

   .. code-block:: lua

	env.USER -- equivalent to $USER in shell

.. function:: hostname([fqdn])

   :return: Machine hostname.

   If called with a parameter, it will set kresd's internal
   hostname. If called without a parameter, it will return kresd's
   internal hostname, or the system's POSIX hostname (see
   gethostname(2)) if kresd's internal hostname is unset.

   This affects ephemeral certificates for kresd serving DNS over TLS.

.. function:: verbose(true | false)

   :return: Toggle verbose logging.

.. function:: mode('strict' | 'normal' | 'permissive')

   :return: Change resolver strictness checking level.

   By default, resolver runs in *normal* mode. There are possibly many small adjustments
   hidden behind the mode settings, but the main idea is that in *permissive* mode, the resolver
   tries to resolve a name with as few lookups as possible, while in *strict* mode it spends much
   more effort resolving and checking referral path. However, if majority of the traffic is covered
   by DNSSEC, some of the strict checking actions are counter-productive.

   .. csv-table::
    :header: "Glue type", "Modes when it is accepted",   "Example glue [#example_glue]_"

    "mandatory glue",     "strict, normal, permissive",  "ns1.example.org"
    "in-bailiwick glue",  "normal, permissive",          "ns1.example2.org"
    "any glue records",   "permissive",                  "ns1.example3.net"

   .. [#example_glue] The examples show glue records acceptable from servers
        authoritative for `org` zone when delegating to `example.org` zone.
        Unacceptable or missing glue records trigger resolution of names listed
        in NS records before following respective delegation.

.. function:: reorder_RR([true | false])

   :param boolean value: New value for the option *(optional)*
   :return: The (new) value of the option

   If set, resolver will vary the order of resource records within RR-sets.
   It is disabled by default.

.. function:: user(name, [group])

   :param string name: user name
   :param string group: group name (optional)
   :return: boolean

   Drop privileges and run as given user (and group, if provided).

   .. tip:: Note that you should bind to required network addresses before changing user. At the same time, you should open the cache **AFTER** you change the user (so it remains accessible). A good practice is to divide configuration in two parts:

      .. code-block:: lua

         -- privileged
         net = { '127.0.0.1', '::1' }
         -- unprivileged
         cache.size = 100*MB
         trust_anchors.add_file('root.key')

   Example output:

   .. code-block:: lua

      > user('baduser')
      invalid user name
      > user('knot-resolver', 'netgrp')
      true
      > user('root')
      Operation not permitted

.. function:: resolve(name, type[, class = kres.class.IN, options = {}, finish = nil, init = nil])

   :param string name: Query name (e.g. 'com.')
   :param number type: Query type (e.g. ``kres.type.NS``)
   :param number class: Query class *(optional)* (e.g. ``kres.class.IN``)
   :param strings options: Resolution options (see :c:type:`kr_qflags`)
   :param function finish: Callback to be executed when resolution completes (e.g. `function cb (pkt, req) end`). The callback gets a packet containing the final answer and doesn't have to return anything.
   :param function init: Callback to be executed with the :c:type:`kr_request` before resolution starts.
   :return: boolean

   The function can also be executed with a table of arguments instead. This is useful if you'd like to skip some arguments, for example:

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

.. function:: package_version()

   :return: Current package version.

   This returns current package version (the version of the binary) as a string.

      .. code-block:: lua

         > package_version()
         2.1.1


.. include:: ../daemon/bindings/modules.rst

CLI interface
=============

The daemon features a CLI interface, type ``help()`` to see the list of available commands.

.. code-block:: bash

   $ kresd /var/cache/knot-resolver
   [system] started in interactive mode, type 'help()'
   > cache.count()
   53

.. role:: lua(code)
   :language: lua

Verbose output
--------------

If the verbose logging is compiled in, i.e. not turned off by
``verbose_log=disabled``, you can turn on verbose tracing of server operation
with the ``-v`` option.  You can also toggle it on runtime with
``verbose(true|false)`` command.

.. code-block:: bash

   $ kresd -v

To run the daemon by hand, such as under ``nohup``, use ``-f 1`` to start a single fork. For example:

.. code-block:: bash

   $ nohup ./daemon/kresd -a 127.0.0.1 -f 1 -v &

.. _`JSON-encoded`: http://json.org/example
.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/scripting/
.. _libuv: https://github.com/libuv/libuv
.. _Lua: https://www.lua.org/about.html
.. _LuaJIT: http://luajit.org/luajit.html
.. _`real process managers`: http://blog.crocodoc.com/post/48703468992/process-managers-the-good-the-bad-and-the-ugly
.. _`socket activation`: http://0pointer.de/blog/projects/socket-activation.html
.. _`dnsproxy module`: https://www.knot-dns.cz/docs/2.7/html/modules.html#dnsproxy-tiny-dns-proxy
.. _`lua-http`: https://luarocks.org/modules/daurnimator/http
