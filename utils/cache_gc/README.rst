Garbage Collector
-----------------

Knot Resolver employs a separate garbage collector daemon (process ``kres-cache-gc``) which periodically trims the cache to keep its size below a configured size limit.

Systemd service ``kres-cache-gc.service`` is enabled by default and does not need any manual intervention.

If you decide to experiment with garbage collector configuration you can execute the daemon manually and configure it to run every second:

.. code-block:: bash

   $ kres-cache-gc -c /var/cache/knot-resolver -d 1000

