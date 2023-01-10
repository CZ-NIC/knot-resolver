.. SPDX-License-Identifier: GPL-3.0-or-later

#############
Knot Resolver
#############

Knot Resolver is a minimalistic implementation of a caching validating DNS resolver.
Modular architecture keeps the core tiny and efficient,
and it provides a state-machine like API for extensions.


.. toctree::
   :caption: Getting Started
   :name: gettingstarted-chapter
   :maxdepth: 1

   gettingstarted-intro
   gettingstarted-install
   gettingstarted-startup
   gettingstarted-config


.. toctree::
   :caption: Common Use Cases
   :name: usecases-chapter
   :maxdepth: 1

   usecase-network-interfaces
   usecase-internal-resolver
   usecase-isp-resolver
   usecase-personal-resolver


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
   config-network
   config-performance
   config-policy
   config-logging-monitoring
   config-dnssec
   config-experimental
   config-no-systemd


.. toctree::
   :caption: For operators
   :name: operators-chapter
   :maxdepth: 1

   upgrading
   NEWS


.. toctree::
   :caption: For developers
   :name: developers-chapter
   :maxdepth: 2

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

