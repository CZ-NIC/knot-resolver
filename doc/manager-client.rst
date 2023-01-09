.. SPDX-License-Identifier: GPL-3.0-or-later

.. _manager-client:

***************
kresctl utility
***************

.. program:: kresctl

Command-line utility that helps communicate with the :ref:`management API <manager-api>`.
It also provides tooling to work with declarative configuration (:option:`validate`, :option:`convert`).

.. option:: -h, --help

    Shows help message.
    It can be also used with every :ref:`command <manager-client-commands>` for its help message.


================================
Connecting to the management API
================================

Most :ref:`commands <manager-client-commands>` require connection to the :ref:`management API <manager-api>`.
With default Knot Resolver configuration, ``kresctl`` should communicate with the resolver withou need to specify :option:`--socket` option.
If not, this option must be set for each command.

.. option:: -s <socket>, --socket <socket>

    :default: "./manager.sock"

    Optional, path to Unix-domain socket or network interface of the :ref:`management API <manager-api>`.

.. code-block:: bash

    $ kresctl --socket http://127.0.0.1@5000 {command} # network interface, port 5000
    $ kresctl --socket /path/to/socket.sock {command}  # unix-domain socket location

.. _manager-client-commands:

========
Commands
========

The following possitional arguments determine what kind of command will be executed.
Only one of these arguments can be selected during the execution of a single ``krestctl`` command.


.. option:: config

    Performs operations on the running resolver's configuration.
    Requires connection to the management API.

    .. option:: <path>

        Path (JSON pointer, RFC6901) to the configuration resources to work with.

    .. option:: <value_or_file>

        Optional, new configuration value, path to file with new configuraion or path to file where to save exported configuration data.
        If not specified, the configuration is printed.


    **Operations:**

        One of the following operations is always performed on the configuration.
        Default operation is :option:`--get`.

        .. option:: -g, --get

            Get current configuration from the resolver.

        .. option:: -s, --set

            Set new configuration for the resolver.

        .. option:: -d, --delete

            Delete given configuration property or list item at the given index.

    .. option:: --json, --yaml

        :default: :option:`--json`

        Expected format for input configuration or required format for exported configuration.

    .. option:: --stdin

        Read config values from stdin.

    This command reads current ``network`` configuration subtree from the resolver and exports it to file in YAML format

    .. code-block:: bash

        $ kresctl config --yaml --get /network ./network-config.yaml

    Next command changes workers configuration to ``8``.

    .. code-block:: bash

        $ kresctl config --set /workers 8

.. option:: metrics

    Reads agregated metrics data in Propmetheus format directly from the running resolver.
    Requires connection to the management API.

    .. option:: <file>

        Optional, file where to export Prometheus metrics.
        If not specified, the metrics are printed.

    .. code-block:: bash

        $ kresctl metrics ./metrics/data.txt


.. option:: schema


    Shows JSON-schema repersentation of the Knot Resolver's configuration.

    .. option:: -l, --live

        Get current configuration JSON-schema directly from the running resolver.
        Requires connection to the management API.

    .. option:: <file>

        Optional, file where to export JSON-schema.
        If not specified, the JSON-schema is printed.

    .. code-block:: bash

        $ kresctl schema --live ./mydir/config-schema.json


.. option:: validate

    Validates configuration in JSON or YAML format.

    .. option:: <input_file>

        File with configuration in YAML or JSON format.

    .. code-block:: bash

        $ kresctl validate input-config.json


.. option:: convert

    Converts JSON or YAML configuration to Lua script.

    .. option:: <input_file>

        File with configuration in YAML or JSON format.

    .. option:: <output_file>

        Optional, output file for converted configuration in Lua script.
        If not specified, converted configuration is printed.

    .. option:: --stdin

        Read config values from stdin.

    .. code-block:: bash

        $ kresctl convert input-config.yaml output-script.lua


.. option:: reload

    Tells the resolver to reload YAML configuration file.
    Old processes are replaced by new ones (with updated configuration) using rolling restarts.
    So there will be no DNS service unavailability during reload operation.
    Requires connection to the management API.


.. option:: stop

    Tells the resolver to shutdown everthing.
    No process will run after this command.
    Requires connection to the management API.
