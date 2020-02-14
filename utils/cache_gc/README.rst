.. SPDX-License-Identifier: GPL-3.0-or-later

.. _garbage-collector:

Garbage Collector
-----------------

.. note:: When using systemd, ``kres-cache-gc.service`` is enabled by default
   and does not need any manual configuration.

Knot Resolver employs a separate garbage collector daemon which periodically
trims the cache to keep its size below size limit configured using
:envvar:`cache.size`.

To execute the daemon manually, you can use the following command to run it
every second:

.. code-block:: bash

   $ kres-cache-gc -c /var/cache/knot-resolver -d 1000
