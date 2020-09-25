.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-priming:

Priming module
==============

The module for Initializing a DNS Resolver with Priming Queries implemented
according to :rfc:`8109`. Purpose of the module is to keep up-to-date list of
root DNS servers and associated IP addresses.

Result of successful priming query replaces root hints distributed with
the resolver software. Unlike other DNS resolvers, Knot Resolver caches
result of priming query on disk and keeps the data between restarts until
TTL expires.

This module is enabled by default and it is not recommended to disable it.
For debugging purposes you may disable the module by appending
``modules.unload('priming')`` to your configuration.
