.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-refuse-no-rd:

Refuse queries without RD bit
=============================

This module ensures all queries without RD (recursion desired) bit set in query
are answered with REFUSED. This prevents snooping on the resolver's cache content.

It is enabled by default. If you don't like this behavior, you can disable it:

.. code-block:: yaml

   options:
     refuse-no-rd: false
