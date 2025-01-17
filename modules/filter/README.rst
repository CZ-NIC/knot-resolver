.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-filter:

Filter
======

This module blocks queries that contain suspicious characters.
When loaded, any queries containing forbidden ascii (see RFC 1035 2.3.1.
Preferred name syntax), or UTF-8 characters that aren't whitelisted,
shall result in ``NXDOMAIN``. Current default whitelist consists of
UTF-8 characters native to some central European languages.
As of yet no configuration utility for this module is provided, therefore any
changes to the whitelist must be performed in ``modules/filter/filter.c``.

This module is not loaded by default. If you'd like to enable it you can load it like so:

.. code-block:: lua

   modules.load('filter')

.. note:: Avoid writing advanced regular expressions into the whitelist,
   this is not the intended use and might exhibit undefined behaviour.
