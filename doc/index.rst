.. SPDX-License-Identifier: GPL-3.0-or-later

#############
Knot Resolver
#############

Knot Resolver is a minimalistic implementation of a caching validating DNS resolver.
Modular architecture keeps the core tiny and efficient,
and it provides a state-machine like API for extensions.

.. toctree::
   :caption: Getting Started
   :name: gettingstarted
   :maxdepth: 1

   gettingstarted-intro
   gettingstarted-install
   gettingstarted-config
   gettingstarted-startup


.. toctree::
   :caption: Scenarios (Use Cases)
   :name: usecases
   :maxdepth: 1

   usecase-internal-resolver
   usecase-isp-resolver
   usecase-personal-resolver


.. _configuration-chapter:

.. toctree::
   :caption: Configuration
   :name: users
   :maxdepth: 3

   config-overview
   config-network
   config-performance
   config-policy
   config-logging-monitoring
   config-dnssec
   config-experimental
   config-no-systemd

.. _operation-chapter:

.. toctree::
   :caption: Operation
   :maxdepth: 1

   upgrading
   NEWS

.. toctree::
   :caption: Developers
   :name: developers
   :maxdepth: 2

   build
   modules-http-custom-services
   lib
   modules_api
   worker_api


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

