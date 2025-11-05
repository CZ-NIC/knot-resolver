.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-lua:

*************
Lua Scripting
*************

Knot Resolver can be configured declaratively by using YAML configuration file.
The actual worker processes (the ``kresd`` executable) speaks a different configuration language, it internally uses the Lua runtime.

Essentially, the declarative configuration is only used for validation and as an external interface.
After validation, a Lua configuration is generated and passed into individual ``kresd`` workers.

You can see the generated configuration files within the resolver's working directory or you can manualy run the conversion of declarative configuration with the :ref:`kresctl convert <manager-client>` command.
In the declarative configuration there is a ``lua`` section where you can insert your own Lua configuration scripts.

.. warning::

   While there are no plans of ever removing the Lua configuration, we do not guarantee absence of backwards incompatible changes.
   Starting with Knot Resolver version 6 and later, we consider the Lua interface internal and a subject to change.
   While we don't have any breaking changes planned for the foreseeable future, they might come.

   **Therefore, use this only when you don't have any other option.
   And please let us know about it and we might try to accomodate your usecase in the declarative configuration.**

   A reference to many internals like Lua options can be found in
   `the developer documentation <./dev/index.html>`_.
   The Lua layer and this docs are very similar to what they were in Knot Resolver 5.x.

.. option:: lua/script-only: true|false

   :default: false

   Ignore declarative configuration for ``kresd`` workers and use only Lua script or script file configured in this section.

.. option:: lua/script: <script string>

   Custom Lua configuration script.

   .. code-block:: yaml

      lua:
        script: |
          -- Network interface configuration
          net.listen('127.0.0.1', 53, { kind = 'dns' })
          net.listen('::1', 53, { kind = 'dns', freebind = true })

          -- Load useful modules
          modules = {
              'hints > iterate',  -- Allow loading /etc/hosts or custom root hints
              'stats',            -- Track internal statistics
              'predict',          -- Prefetch expiring/frequent records
          }

          -- Cache size
          cache.size = 100 * MB

.. option:: lua/script-file: <path>

   Path to the file that contains Lua configuration script.

.. note::

   The script is applied after the declarative configuration, so it can change the configuration defined in it.
