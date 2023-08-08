.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-priming:

Priming
=======

Initializing a DNS Resolver with Priming Queries implemented
according to :rfc:`8109`. Purpose of this is to keep up-to-date list of
root DNS servers and associated IP addresses.

Result of successful priming query replaces root hints distributed with
the resolver software. Unlike other DNS resolvers, Knot Resolver caches
result of priming query on disk and keeps the data between restarts until
TTL expires.

Priming is enabled by default; you may disable it in configuration file.

.. code-block:: yaml

   options:
     priming: false
