.. SPDX-License-Identifier: GPL-3.0-or-later

**********************
Configuration Overview
**********************

Configuration file is named ``/etc/knot-resolver/kresd.conf`` and is read when
you execute Knot Resolver using systemd commands described in section
:ref:`quickstart-startup`. [#]_

.. _config-syntax:

Syntax
======

The configuration file syntax allows you to specify different kinds of data:

  - ``group.option = 123456``
  - ``group.option = "string value"``
  - ``group.command(123456, "string value")``
  - ``group.command({ key1 = "value1", key2 = 222, key3 = "third value" })``
  - ``globalcommand(a_parameter_1, a_parameter_2, a_parameter_3, etc)``
  - ``-- any text after -- sign is ignored till end of line``

Following **configuration file snippet** starts listening for unencrypted and also encrypted DNS queries on IP address 192.0.2.1, and sets cache size.

.. code-block:: lua

        -- this is a comment: listen for unencrypted queries
        net.listen('192.0.2.1')
        -- another comment: listen for queries encrypted using TLS on port 853
        net.listen('192.0.2.1', 853, { kind = 'tls' })
        -- 10 MB cache is suitable for a very small deployment
        cache.size = 10 * MB

.. tip::
   When copy&pasting examples from this manual please pay close
   attention to brackets and also line ordering - order of lines matters.

   The configuration language is in fact Lua script, so you can use full power
   of this programming language. See article
   `Learn Lua in 15 minutes`_ for a syntax overview.

When you modify configuration file on disk restart resolver process to get
changes into effect. See chapter :ref:`systemd-zero-downtime-restarts` if even short
outages are not acceptable for your deployment.

.. [#] If you decide to run binary ``/usr/sbin/kresd`` manually (instead of
   using systemd) do not forget to specify ``-c`` option with path to
   configuration file, otherwise ``kresd`` will read file named ``config`` from
   its current working directory.

Documentation Conventions
=========================

Besides text configuration file, Knot Resolver also supports interactive and dynamic configuration using scripts or external systems, which is described in chapter :ref:`runtime-cfg`. Through this manual we present examples for both usage types - static configuration in a text file (see above) and also the interactive mode.

The **interactive prompt** is denoted by ``>``, so all examples starting with ``>`` character are transcripts of user (or script) interaction with Knot Resolver and resolver's responses. For example:

.. code-block:: lua

        > -- this is a comment entered into interactive prompt
        > -- comments have no effect here
        > -- the next line shows a command entered interactively and its output
        > log_level()
        'notice'
        > -- the previous line without > character is output from log_level() command

Following example demonstrates how to interactively list all currently loaded modules, and includes multi-line output:

.. code-block:: lua

        > modules.list()
        {
            'iterate',
            'validate',
            'cache',
            'ta_update',
            'ta_signal_query',
            'policy',
            'priming',
            'detect_time_skew',
            'detect_time_jump',
            'ta_sentinel',
            'edns_keepalive',
            'refuse_nord',
            'watchdog',
        }


Before we dive into configuring features, let us explain modularization basics.

.. include:: ../daemon/bindings/modules.rst

Now you know what configuration file to modify, how to read examples and what modules are so you are ready for a real configuration work!

.. _`Learn Lua in 15 minutes`: http://tylerneylon.com/a/learn-lua/

