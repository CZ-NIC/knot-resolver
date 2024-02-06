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

Most :ref:`commands <manager-client-commands>` require connection to the
:ref:`management API <manager-api>`. With a standard Knot Resolver installation
using :ref:`distribution packages <gettingstarted-install>`, ``kresctl``
should communicate with the running resolver without any additional configuration.
For nonstandard installations and deployments, you may need to use either
the :option:`--config <-c <config>, --config <config>>` or
:option:`--socket <-s <socket>, --socket <socket>>` option to tell
``kresctl`` where to look for the API.

If the :ref:`management <manager-api>` key is not present in the configuration file,
``kresctl`` attempts to connect to the ``/var/run/knot-resolver/manager.sock``
Unix-domain socket, which is the Manager's default communication channel.

By default, ``kresctl`` tries to find the correct communication channel in
``/etc/knot-resolver/config.yaml``, or, if present, the file specified by the
``KRES_MANAGER_CONFIG`` environment variable.

.. option:: -s <socket>, --socket <socket>

    Optional, path to Unix-domain socket or network interface of the
    :ref:`management API <manager-api>`. Cannot be used together with
    :option:`--config <-c <config>, --config <config>>`.

.. code-block:: bash

    $ kresctl --socket http://localhost:5000 {command} # network interface, port 5000
    $ kresctl --socket /path/to/socket.sock {command}  # unix-domain socket location

.. option:: -c <config>, --config <config>

    Optional, path to Knot Resolver declarative configuration to retrieve
    Unix-domain socket or network interface of the management API from. Cannot
    be used together with :option:`--socket <-s <socket>, --socket <socket>>`.

.. code-block:: bash

    $ kresctl --config /path/to/config.yaml {command}

.. _manager-client-commands:

========
Commands
========

The following possitional arguments determine what kind of command will be executed.
Only one of these arguments can be selected during the execution of a single ``krestctl`` command.


.. option:: config

    Performs operations on the running resolver's configuration.
    Requires connection to the management API.


    **Operations:**

    Use one of the following operations to be performed on the configuration.


    .. option:: get

        Get current configuration from the resolver.

        .. option:: -p <path>, --path <path>

            Optional, path (JSON pointer, RFC6901) to the configuration resources.
            By default, the entire configuration is selected.

        .. option:: --json, --yaml

            :default: :option:`--json`

            Get configuration data in JSON or YAML format.

        .. option:: <file>

            Optional, path to the file where to save exported configuration data.
            If not specified, data will be printed.


    .. option:: set

        Set new configuration for the resolver.

        .. option:: -p <path>, --path <path>

            Optional, path (JSON pointer, RFC6901) to the configuration resources.
            By default, the entire configuration is selected.

        .. option:: --json, --yaml

            :default: :option:`--json`

            Set configuration data in JSON or YAML format.

        .. option:: [ <file> | <value> ]

            Optional, path to file with new configuraion or new configuration value.
            If not specified, value will be readed from stdin.


    .. option:: delete

        Delete given configuration property or list item at the given index.

        .. option:: -p <path>, --path <path>

            Optional, path (JSON pointer, RFC6901) to the configuration resources.
            By default, the entire configuration is selected.


    This command reads current ``network`` configuration subtree from the resolver and exports it to file in YAML format.

    .. code-block:: bash

        $ kresctl config get --yaml -p /network ./network-config.yaml

    Next command changes workers configuration to ``8``.

    .. code-block:: bash

        $ kresctl config set -p /workers 8

.. option:: metrics

    Reads agregated metrics data in Propmetheus format directly from the running resolver.
    Requires connection to the management API.

    .. option:: <file>

        Optional, file where to export Prometheus metrics.
        If not specified, the metrics are printed.

    .. code-block:: bash

        $ kresctl metrics ./metrics/data.txt

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
        The purpose is not to block the resolver for too long.
        The resolver repeats the command after at least one millisecond, until all the matching data is cleared.

    .. option:: [name]

        The subtree to purge.
        If not provided, the whole cache is purged (and any other parameters are disregarded).

    .. code-block:: bash

        $ kresctl cache clear
        $ kresctl cache clear example.com.
        $ kresctl cache clear --exact-name example.com.


.. option:: schema


    Shows JSON-schema repersentation of the Knot Resolver's configuration.

    .. option:: -l, --live

        Get configuration JSON-schema from the running resolver.
        Requires connection to the management API.

    .. option:: <file>

        Optional, file where to export JSON-schema.
        If not specified, the JSON-schema is printed.

    .. code-block:: bash

        $ kresctl schema --live ./mydir/config-schema.json


.. option:: validate

    Validates configuration in JSON or YAML format.

    .. option:: --no-strict

        Ignore strict rules during validation, e.g. path/file existence.

    .. option:: <input_file>

        File with configuration in YAML or JSON format.

    .. code-block:: bash

        $ kresctl validate input-config.json


.. option:: convert

    Converts JSON or YAML configuration to Lua script.

    .. option:: --no-strict

        Ignore strict rules during validation, e.g. path/file existence.

    .. option:: <input_file>

        File with configuration in YAML or JSON format.

    .. option:: <output_file>

        Optional, output file for converted configuration in Lua script.
        If not specified, converted configuration is printed.

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
