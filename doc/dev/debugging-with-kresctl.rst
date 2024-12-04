.. SPDX-License-Identifier: GPL-3.0-or-later

.. _debugging-with-kresctl:

**********************
Debugging with kresctl
**********************

Knot Resolver is made up of several independent components,
so it can be difficult to debug the individual parts.
To help with this, there is an option in the kresctl utility
that can run GDB-compatible debugger on a specific component of the resolver, see the ``debug`` command.

.. program:: kresctl

.. option:: pids

    Lists the PIDs of the Manager's subprocesses, separated by newlines.

    .. option:: --json

        Makes the output more verbose, in JSON. In addition to the subprocesses'
        PIDs, it also prints their types and statuses.

    .. option:: [proc_type]

        :default: all

        Optional. The type of process to query. See :ref:`Subprocess types
        <debugging-with-kresctl-subprocess-types>` for more info.


.. option:: debug

    Executes a GDB-compatible debugger and attaches it to the Manager's
    subprocesses. By default, the debugger is ``gdb`` and the subprocesses are
    only the ``kresd`` workers.

    .. warning::

        The ``debug`` command is a utility for Knot Resolver developers and is
        not intended to be used by end-users. Running this command **will** make
        your resolver unresponsive.

    .. note::

        Modern kernels will prevent debuggers from tracing processes that are
        not their descendants, which is exactly the scenario that happens with
        ``kresctl debug``. There are three ways to work around this, listed in
        the order in which they are preferred in terms of security:

          1. Grant the debugger the ``cap_sys_ptrace`` capability
             (**recommended**)

              * For ``gdb``, this may be achieved by using the ``setcap``
                command like so:

                .. code-block:: bash

                    sudo setcap cap_sys_ptrace=eip /usr/bin/gdb

          2. Run the debugger as root

              * You may use the ``--sudo`` option to achieve this

          3. Set ``/proc/sys/kernel/yama/ptrace_scope`` to ``0``

              * This will allow **all** programs in your current session to
                trace each other. Handle with care!

    .. note::

        This command will only work if executed on the same machine where Knot
        Resolver is running. Remote debugging is currently not supported.

    .. option:: [proc_type]

        :default: kresd

        Optional. The type of process to debug. See :ref:`Subprocess types
        <debugging-with-kresctl-subprocess-types>` for more info.

    .. option:: --sudo

        Run the debugger with sudo.

    .. option:: --gdb <command>

        Use a custom GDB executable. This may be a command on ``PATH``, or an
        absolute path to an executable.

    .. option:: --print-only

        Prints the GDB command line into ``stderr`` as a Python array, does not
        execute GDB.


.. _debugging-with-kresctl-subprocess-types:

Subprocess types
----------------

Some of ``kresctl``'s commands (like :option:`pids` and :option:`debug`) take a subprocess
type value determining which subprocesses will be affected by them. The possible
values are as follows:

* ``kresd`` -- the worker daemons
* ``gc`` -- the cache garbage collector
* ``all`` -- all of the Manager's subprocesses
