.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-serve-stale:

Serve stale
===========

This allows using timed-out records in case the resolver is unable to contact upstream servers.

By default it allows stale-ness by up to one day,
after roughly four seconds trying to contact the servers.
It's quite configurable/flexible; see the beginning of the module source for details.
See also the RFC draft_ (not fully followed) and :option:`cache/ns-timeout <cache/ns-timeout: <time ms|s|m|h|d>>`.

Running
-------

.. code-block:: yaml

    options:
      serve-stale: true

.. _draft: https://tools.ietf.org/html/draft-ietf-dnsop-serve-stale-00
