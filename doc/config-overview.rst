.. SPDX-License-Identifier: GPL-3.0-or-later

**********************
Configuration Overview
**********************

Configuration file is by default named ``/etc/knot-resolver/config.yml``.
Different configuration file can be loaded by using command line option
``-c / --config``.


Syntax
======

The configuration file uses `YAML format version 1.1 <https://yaml.org/spec/1.1/>`_.
To quickly learn about the format, you can have a look at `Learn YAML in Y minutes <https://learnxinyminutes.com/docs/yaml/>`_.


Schema
======

The configuration has to pass a validation step before being used. The validation mainly
checks for conformance to our :ref:`configuration-schema`.


.. tip::
    Whenever a configuration is loaded and the validation fails, we attempt to log a detailed
    error message explaining what the problem was. For example, it could look like the following:

    .. code_block::
        ERROR:knot_resolver_manager.server:multiple configuration errors detected:
                [/management/interface] invalid port number 66000
                [/logging/level] 'noticed' does not match any of the expected values ('crit', 'err', 'warning', 'notice', 'info', 'debug')
    
    If you happen to find a rejected configuration with unhelpful or confusing error message, please report it as a bug.

