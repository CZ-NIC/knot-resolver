.. SPDX-License-Identifier: GPL-3.0-or-later

###########################
Knot Resolver documentation
###########################

Welcome to Knot Resolver's documentation!
Knot Resolver is an open-source implementation of a caching validating DNS resolver.
Modular architecture keeps the core tiny and efficient, and it also provides a state-machine like API for extensions.

If you are a completely new user or new to version 6, please start with chapters for :ref:`getting started <gettingstarted-chapter>` and :ref:`upgrading guide <upgrading-to-6>`.

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
   config-network
   config-performance
   config-policy-new
   config-logging-monitoring
   config-dnssec
   config-lua
   config-experimental

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

   upgrading
   upgrading-to-6
   NEWS
   rfc-list
.. maybe find a better location for rfc-list

.. toctree::
   :caption: For developers
   :name: developer-chapter
   :maxdepth: 1

   developer

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

