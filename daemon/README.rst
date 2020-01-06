.. _daemon:

TODO: Environment
=================

.. function:: user(name, [group])

   :param string name: user name
   :param string group: group name (optional)
   :return: boolean

   Drop privileges and start running as given user (and group, if provided).

   .. tip:: Note that you should bind to required network addresses before changing user. At the same time, you should open the cache **AFTER** you change the user (so it remains accessible). A good practice is to divide configuration in two parts:

      .. code-block:: lua

         -- privileged
         net.listen('127.0.0.1')
         net.listen('::1')
         user('knot-resolver', 'netgrp')
         -- unprivileged
         cache.size = 100*MB

   Example output:

   .. code-block:: lua

      > user('baduser')
      invalid user name
      > user('knot-resolver', 'netgrp')
      true
      > user('root')
      Operation not permitted


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


.. _`JSON-encoded`: http://json.org/example
.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/scripting/
.. _libuv: https://github.com/libuv/libuv
.. _Lua: https://www.lua.org/about.html
.. _LuaJIT: http://luajit.org/luajit.html
.. _`real process managers`: http://blog.crocodoc.com/post/48703468992/process-managers-the-good-the-bad-and-the-ugly
.. _`socket activation`: http://0pointer.de/blog/projects/socket-activation.html
.. _`dnsproxy module`: https://www.knot-dns.cz/docs/2.7/html/modules.html#dnsproxy-tiny-dns-proxy
