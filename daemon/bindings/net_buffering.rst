.. SPDX-License-Identifier: GPL-3.0-or-later

Buffering tweaks
----------------

We (can) set various server-side socket options that affect buffering.
The values are stored in C structures without real Lua bindings,
so setting them is a bit long.

.. py:data:: (require 'ffi').C.the_worker.engine.net.tcp.user_timeout
 
   On TCP-based server-side sockets we set ``TCP_USER_TIMEOUT`` option if available (~Linux).
   We use default 1000, i.e. one second.  For details see the definition in ``man tcp.7``.

.. py:data:: (require 'ffi').C.the_worker.engine.net.listen_tcp_buflens.snd
.. py:data:: (require 'ffi').C.the_worker.engine.net.listen_tcp_buflens.rcv
.. py:data:: (require 'ffi').C.the_worker.engine.net.listen_udp_buflens.snd
.. py:data:: (require 'ffi').C.the_worker.engine.net.listen_udp_buflens.rcv

   If overridden to nonzero, these variables instruct the OS to modify kernel-space buffers
   for server-side sockets.  We split the setting for UDP vs. TCP and sending vs. receiving.

   For details see ``SO_SNDBUF`` and ``SO_RCVBUF`` in ``man socket.7``.
   There is no user-space buffering beyond immediate manipulation, only the OS keeps some.

