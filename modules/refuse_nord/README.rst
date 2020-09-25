.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-refuse_nord:

Refuse queries without RD bit
=============================

This module ensures all queries without RD (recursion desired) bit set in query
are answered with REFUSED. This prevents snooping on the resolver's cache content.

The module is loaded by default. If you'd like to disable this behavior, you can
unload it:

.. code-block:: lua

   modules.unload('refuse_nord')
