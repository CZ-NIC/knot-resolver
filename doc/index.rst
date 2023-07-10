.. SPDX-License-Identifier: GPL-3.0-or-later

#############
Knot Resolver
#############

Welcome to Knot Resolver's documentation!
Knot Resolver is an opensource implementation of a caching validating DNS resolver.
Modular architecture keeps the core tiny and efficient, and it also provides a state-machine like API for extensions.

If you are a new user, please start with chapter for :ref:`getting started <gettingstarted>`.

.. toctree::
   :caption: Getting Started
   :name: gettingstarted-chapter
   :maxdepth: 1

   gettingstarted-install
   gettingstarted-startup
   gettingstarted-config

.. toctree::
   :caption: Configuration
   :name: configuration-chapter
   :maxdepth: 3

   config-overview
   usecase-network-interfaces
   config-policy-new
   config-logging-monitoring
   config-dnssec
   config-lua

.. toctree::
   :caption: Deployment
   :name: deployment-chapter
   :maxdepth: 1

   deployment-systemd
   deployment-manual
   deployment-docker
   deployment-advanced

.. toctree::
   :caption: Management
   :name: management-chapter
   :maxdepth: 1

   manager-api
   manager-client

.. toctree::
   :caption: For operators
   :name: operators-chapter
   :maxdepth: 1

   upgrading-to-6
   upgrading
   NEWS


.. toctree::
   :caption: For developers
   :name: developers-chapter
   :maxdepth: 2

   manager-dev
   architecture
   build
   lib
   modules_api
   worker_api
   modules-http-custom-services


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

