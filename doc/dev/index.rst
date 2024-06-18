.. SPDX-License-Identifier: GPL-3.0-or-later

.. warning::

   **This documentation is intended to help with advanced fine-tuning and
   development of Knot Resolver!** If you are looking for help with day-to-day
   use without the need to involve yourself with C and/or Lua programming
   languages, please see the `user documentation <../index.html>`_.

#####################################
Knot Resolver developer documentation
#####################################

Welcome to Knot Resolver's documentation for developers and advanced users!

.. toctree::
   :caption: Building from sources
   :name: build-chapter
   :maxdepth: 1

   build
   manager-dev-env

.. toctree::
   :caption: Architecture
   :name: architecture-chapter
   :maxdepth: 1

   architecture
   manager-dev-code

.. toctree::
   :caption: Lua configuration
   :name: configuration-lua-chapter
   :maxdepth: 1

   config-lua-overview
   config-lua-network
   config-lua-performance
   config-lua-policy
   config-lua-logging-monitoring
   config-lua-dnssec
   config-lua-experimental
   modules-http-custom-services

.. toctree::
   :caption: C API
   :name: c-api-chapter
   :maxdepth: 1

   lib
   modules_api
   worker_api
   logging_api

.. toctree::
   :caption: Infrastructure
   :name: infra-chapter
   :maxdepth: 1

   infra-pages

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

