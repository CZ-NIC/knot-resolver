.. SPDX-License-Identifier: GPL-3.0-or-later

Debugging options
=================

In case the resolver crashes, it is often helpful to collect a coredump from
the crashed process. Configuring the system to collect coredump from crashed
process is out of the scope of this documentation, but some tips can be found
`here <https://lists.nic.cz/pipermail/knot-resolver-users/2019/000239.html>`_.

Kresd uses *assumptions*, which are checks that should always pass and indicate
some weird or unexpected state if they don't. In such cases, they show up in
the log as errors. By default, the process recovers from those states, but the
behaviour can be changed with the following options to aid further debugging.

.. envvar:: debugging.assumption_abort = false|true

   :return: boolean (default: false)

   Allow the process to be aborted in case it encounters a failed assumption.

.. envvar:: debugging.assumption_fork = true|false

   :return: boolean (default: true)

   If a proccess should be aborted, it can be done in two ways. When this is
   set to true (default), a child is forked and aborted to obtain a coredump,
   while the parent process recovers and keeps running. This can be useful to
   debug a rare issue that occurs in production, since it doesn't affect the
   main process.
