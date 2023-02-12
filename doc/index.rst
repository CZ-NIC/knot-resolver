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

   gettingstarted-intro
   gettingstarted-install
   gettingstarted-startup
   gettingstarted-config


.. toctree::
   :caption: Use Cases
   :name: usecases-chapter
   :maxdepth: 1

   advanced-no-manager
   usecase-personal-resolver
   usecase-internal-resolver
   usecase-isp-resolver
   usecase-network-interfaces


.. toctree::
   :caption: Features
   :name: features-chapter
   :maxdepth: 1

   manager-api
   manager-client


.. toctree::
   :caption: Configuration
   :name: configuration-chapter
   :maxdepth: 3

   config-overview
   config-schema
   config-no-systemd
   config-lua


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

