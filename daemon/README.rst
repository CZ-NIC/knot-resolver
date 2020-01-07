.. _daemon:

TODO: Basics
============

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


.. _`JSON-encoded`: http://json.org/example
.. _`PowerDNS Recursor`: https://doc.powerdns.com/md/recursor/scripting/
.. _libuv: https://github.com/libuv/libuv
.. _Lua: https://www.lua.org/about.html
.. _LuaJIT: http://luajit.org/luajit.html
.. _`real process managers`: http://blog.crocodoc.com/post/48703468992/process-managers-the-good-the-bad-and-the-ugly
.. _`socket activation`: http://0pointer.de/blog/projects/socket-activation.html
.. _`dnsproxy module`: https://www.knot-dns.cz/docs/2.7/html/modules.html#dnsproxy-tiny-dns-proxy
