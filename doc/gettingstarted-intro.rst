.. SPDX-License-Identifier: GPL-3.0-or-later

.. _gettingstarted:

Welcome to Knot Resolver's documentation for getting started!
This chapter will introduce Knot Resolver and will guide you through :ref:`installation <gettingstarted-install>` to first :ref:`startup <gettingstarted-startup>` and basic insight into :ref:`configuration <gettingstarted-config>`.


.. _gettingstarted-intro:

************
Introduction
************

==================
Basic architecture
==================

The resolver is made up of several singlethread processes:

:kresd:
    The resolving daemon that is the core of the resolver, written in C.
    Most of its functionalities are implemented in a separate modules written in C or Lua.

:kres-cache-gc:
    Garbage collector that takes care of maintaining the resolver's cache, written in C.

:kres-manager:
    A new process since version ``6.x`` that is used to manage other processes, written in Python.
    The manager starts and setups other processes based on the configuration.
    It is the only process that a user should directly interact with.

For a detailed info see :ref:`internal architectire <architecture>`.
