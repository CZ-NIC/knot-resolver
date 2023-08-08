.. SPDX-License-Identifier: GPL-3.0-or-later

Debugging options
=================

In case the resolver crashes, it is often helpful to collect a coredump from
the crashed process. Configuring the system to collect coredump from crashed
process is out of the scope of this documentation, but some tips can be found
`here <https://lists.nic.cz/hyperkitty/list/knot-resolver-users@lists.nic.cz/message/GUHW4JSDXZ6SZUAYYQ3U2WWOZEIVVF2S/>`_.

Kresd uses its own mechanism for assertions. They are checks that should always
pass and indicate some weird or unexpected state if they don't. In such cases,
they show up in the log as errors. By default, the process recovers from those
states if possible, but the behaviour can be changed with the following options
to aid further debugging.

.. option:: logging/debugging:

   .. option:: assertion-abort: true|false

      :default: false

      Allow the process to be aborted in case it encounters a failed assertion.
      (Some critical conditions always lead to abortion, regardless of settings.)

   .. option:: assertion-fork: <time ms|s|m|h|d>

      :default: 5m

      If a process should be aborted, it can be done in two ways. When this is
      set to nonzero (default), a child is forked and aborted to obtain a coredump,
      while the parent process recovers and keeps running. This can be useful to
      debug a rare issue that occurs in production, since it doesn't affect the
      main process.

      As the dumping can be costly, the value is a lower bound on delay between
      consecutive coredumps of each process. It is randomized by +-25% each time.

.. code-block:: yaml

   logging:
     debugging:
       assertion-abort: true
       assertion-fork: 10m
