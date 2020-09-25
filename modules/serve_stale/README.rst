.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-serve_stale:

Serve stale
===========

Demo module that allows using timed-out records in case kresd is
unable to contact upstream servers.

By default it allows stale-ness by up to one day,
after roughly four seconds trying to contact the servers.
It's quite configurable/flexible; see the beginning of the module source for details.
See also the RFC draft_ (not fully followed) and :any:`cache.ns_tout`.

Running
-------
.. code-block:: lua

    modules = { 'serve_stale < cache' }

.. _draft: https://tools.ietf.org/html/draft-ietf-dnsop-serve-stale-00

