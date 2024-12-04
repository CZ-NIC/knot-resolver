.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-overview:

**********************
Configuration Overview
**********************

By default, Knot Resolver configuration is located in the ``/etc/knot-resolver/config.yaml`` file.
The configuration file uses declarative format `YAML version 1.1 <https://yaml.org/spec/1.1/>`_,
but you can also write the same as JSON.
To quickly learn about the format, you can have a look at `Learn YAML in Y minutes <https://learnxinyminutes.com/docs/yaml/>`_.

.. note::

    You can see some configuration examples in :ref:`Getting Started <gettingstarted-config>` chapter.


Validation
==========

The configuration has to pass a validation step before being used in the resolver.
The validation checks for conformance in predefined configuration datamodel.
You can use :ref:`kresctl validate <manager-client>` to check your configuration before using it in the resolver.

.. warning::

    Some validation steps are however dynamic (for example resolving of interface names) and can not be premodeled for validation and even completed without running the resolver.

.. tip::

    Whenever a configuration is loaded and the validation fails, we attempt to log a detailed
    error message explaining what the problem was. For example, it could look like the following.

    .. code-block:: bash

        ERROR:knot_resolver_manager.server:multiple configuration errors detected:
                [/management/interface] invalid port number 66000
                [/logging/level] 'noticed' does not match any of the expected values ('crit', 'err', 'warning', 'notice', 'info', 'debug')

    If you happen to find a rejected configuration with unhelpful or confusing error message, please report it as a bug.


JSON Schema
===========

While originally the configuration is modeled in Python source code, it can be represented as a `JSON schema <https://json-schema.org/>`_.
JSON schema is NOT used to validate the configuration, it is the other way to help understand the configuration structure.
An easy way to see the complete configuration.


Getting the JSON Schema
-----------------------

* The JSON schema can be `downloaded here <_static/config.schema.json>`_ (valid only for the version of the resolver this documentation was generated for).
* The :ref:`kresctl schema <manager-client>` command outputs the JSON schema of the currently installed version as well. It does not require a running resolver.
* The JSON schema can also be obtained from a running resolver by sending a HTTP GET request to the path ``/schema`` on the :ref:`management API <manager-api>` (by default a Unix socket at ``/run/knot-resolver/kres-api.sock``).

.. tip::

    For the schema readability, some graphical visualizer can be used, for example `this one <https://json-schema.app/>`_.


Interactive visualization
-------------------------

The following visualization is interactive and offers good overview of the configuration structure.

.. raw:: html

    <a href="_static/schema_doc.html" target="_blank">Open in a new tab.</a>
    <iframe src="_static/schema_doc.html" width="100%" style="height: 30vh;"></iframe>
