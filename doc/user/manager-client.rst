.. SPDX-License-Identifier: GPL-3.0-or-later

.. _manager-client:

***************
kresctl utility
***************

.. program:: kresctl

A command line utility that communicates with the
:ref:`management API <manager-api>`. It also provides tooling to work with
the declarative configuration (:option:`validate`, :option:`convert`).

.. option:: -h, --help

    Shows the help message.
    It can be also used with each :ref:`command <manager-client-commands>` to
    show its help message.


================================
Connecting to the management API
================================

Most :ref:`commands <manager-client-commands>` require connection to the
:ref:`management API <manager-api>`. With a standard Knot Resolver installation
from :ref:`distribution packages <gettingstarted-install>`, ``kresctl`` should
communicate with the running resolver without any additional configuration. For
non-standard installations and deployments, you may need to use either the
:option:`--config <-c <config>, --config <config>>` or
:option:`--socket <-s <socket>, --socket <socket>>` option to tell ``kresctl``
where to look for the API.

If the :ref:`management <manager-api>` key is not present in the configuration
file, ``kresctl`` attempts to connect to the
``/var/run/knot-resolver/manager.sock`` Unix-domain socket, which is the
Manager's default communication channel.

By default, ``kresctl`` tries to find the correct communication channel in
``/etc/knot-resolver/config.yaml`` or, if present, the file specified by the
``KRES_MANAGER_CONFIG`` environment variable.

.. option:: -s <socket>, --socket <socket>

    Path to the :ref:`management API <manager-api>` Unix-domain socket or
    network interface.

    Cannot be used together with
    :option:`--config <-c <config>, --config <config>>`.

    .. code-block:: bash

        $ kresctl --socket http://localhost:5000 {command} # network interface, port 5000
        $ kresctl --socket /path/to/socket.sock {command}  # unix-domain socket location

.. option:: -c <config>, --config <config>

    Path to Knot Resolver's declarative configuration to retrieve the management
    API's Unix-domain socket or network interface.

    Cannot be used together with
    :option:`--socket <-s <socket>, --socket <socket>>`.

    .. code-block:: bash

        $ kresctl --config /path/to/config.yaml {command}

.. _manager-client-commands:

========
Commands
========

The following positional arguments determine what kind of command will be
executed. Only one of these arguments may be selected during the execution of a
single ``kresctl`` command.


.. option:: config

    Performs operations on the running resolver's configuration. Requires a
    connection to the management API.


    Operations
    ----------

    The following operations may be performed on the configuration:


    .. option:: get

        Get current configuration from the resolver.

        .. option:: -p <path>, --path <path>

            Path (JSON pointer, :rfc:`6901`) to the configuration resources.
            By default, the entire configuration tree is selected.

        .. option:: --json, --yaml

            :default: :option:`--json`

            Get configuration data in JSON or YAML format.

        .. option:: [file]

            Optional. The path to the file where the exported configuration data
            will be saved. If not specified, the data will be printed into
            ``stdout``.


    .. option:: set

        Set new configuration for the resolver.

        .. option:: -p <path>, --path <path>

            Path (JSON pointer, :rfc:`6901`) to the configuration resources.
            By default, the entire configuration tree is selected.

        .. option:: --json, --yaml

            :default: :option:`--json`

            Set configuration data in JSON or YAML format.

        .. option:: [file|value]

            Optional. The path to file with the new configuration, or the new
            configuration value. If not specified, the value will be read from
            ``stdin``.


    .. option:: delete

        Delete the given configuration property or list item at the given index.

        .. option:: -p <path>, --path <path>

            Path (JSON pointer, :rfc:`6901`) to the configuration resources.
            By default, the entire configuration tree is selected.


    The following command reads the current :ref:`network <config-network>`
    configuration subtree from the resolver and exports it to a file in YAML
    format:

    .. code-block:: bash

        $ kresctl config get --yaml -p /network ./network-config.yaml

    The following command changes the ``workers`` configuration to ``8``:

    .. code-block:: bash

        $ kresctl config set -p /workers 8

.. option:: metrics

    Get aggregated metrics from the running resolver in JSON format (default) or optionally in Prometheus format.
    The ``prometheus-client`` Python package needs to be installed if you wish to use the Prometheus format.

    Requires a connection to the management HTTP API.

    .. option:: --prometheus

        Get metrics in Prometheus format if dependencies are met in the resolver.

    .. option:: [file]

        Optional. The file into which metrics will be exported.
        If not specified, the metrics are printed into ``stdout``.

    .. code-block:: bash

        $ kresctl metrics ./kres-metrics.json
        $ kresctl metrics --prometheus

.. option:: cache clear

        Purge cache records matching the specified criteria.

    .. option:: --exact-name

        If set, only records with the exact same name are removed, not the whole subtree.

    .. option:: --rr-type <rr-type>

        The record type to remove. Only supported together with :option:`--exact-name`.

        Optional.

    .. option:: --chunk-size <chunk-size>

        :default: 100

        The number of records to remove in a single round.

        The purpose is to prevent the resolver from blocking for too long. The
        resolver repeats the command after at least one millisecond, until all
        the matching data is cleared.

    .. option:: [name]

        The subtree to purge.

        If not provided, the whole cache is purged (and all other parameters to
        this command are ignored).

    .. code-block:: bash

        $ kresctl cache clear
        $ kresctl cache clear example.com.
        $ kresctl cache clear --exact-name example.com.


.. option:: schema

    Shows a JSON-schema representation of Knot Resolver's configuration.

    .. option:: -l, --live

        Get the configuration JSON-schema from the running resolver.

        Requires a connection to the management API.

    .. option:: [file]

        The target file, where the schema is to be exported.

        If not specified, the schema is printed into ``stdout``.

    .. code-block:: bash

        $ kresctl schema --live ./mydir/config-schema.json


.. option:: validate

    Validate declarative configuration.

    .. option:: --no-strict

        Ignore strict rules during validation, e.g. path/file existence.

    .. option:: <input_file>

        File with the declarative configuration in YAML or JSON format.

    .. code-block:: bash

        $ kresctl validate input-config.json


.. option:: convert

    Convert declarative configuration to a Lua script.

    .. option:: --no-strict

        Ignore strict rules during validation, e.g. path/file existence.

    .. option:: <input_file>

        File with the declarative configuration in YAML or JSON format.

    .. option:: [output_file]

        Optional. The output file for converted Lua configuration.

        If not specified, the converted configuration is printed into
        ``stdout``.

    .. code-block:: bash

        $ kresctl convert input-config.yaml output-script.lua


.. option:: reload

    Tells the resolver to reload the declarative configuration file.

    Old subprocesses are replaced by new ones (with updated configuration) using
    rolling restarts, ensuring that the DNS service is not disrupted during the
    reload operation.

    Requires a connection to the management API.


.. option:: stop

    Tells the resolver to shut down. All processes will be stopped after this
    command is run.

    Requires a connection to the management API.


.. option:: pids

    Lists the PIDs of the Manager's subprocesses, separated by newlines.

    .. option:: --json

        Makes the output more verbose, in JSON. In addition to the subprocesses'
        PIDs, it also prints their types and statuses.

    .. option:: [proc_type]

        :default: ``all``

        Optional. The type of process to query. See :ref:`Subprocess types
        <manager-client-subprocess-types>` for more info.


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

        :default: ``kresd``

        Optional. The type of process to debug. See :ref:`Subprocess types
        <manager-client-subprocess-types>` for more info.

    .. option:: --sudo

        Run the debugger with sudo.

    .. option:: --gdb <command>

        Use a custom GDB executable. This may be a command on ``PATH``, or an
        absolute path to an executable.


.. _manager-client-subprocess-types:

Subprocess types
----------------

Some of ``kresctl``'s commands (like :option:`pids` and :option:`debug`) take a subprocess
type value determining which subprocesses will be affected by them. The possible
values are as follows:

* ``kresd`` -- the worker daemons
* ``gc`` -- the cache garbage collector
* ``all`` -- all of the Manager's subprocesses
