.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-multiple-workers:

Multiple workers
================

Knot Resolver can utilize multiple CPUs running multiple independent workers (processes), where each process utilizes at most single CPU core on your machine.
If your machine handles a lot of DNS traffic, configure multiple workers.

All workers typically share the same configuration and cache, and incoming queries are automatically distributed by operating system among all workers.

Advantage of using multiple workers is that a problem in a single worker will not affect others, so a single worker crash will not bring the whole resolver service down.

.. tip::

   For maximum performance, there should be as many worker processes as there are available CPU threads.

To run multiple workers, configure its number in configuration file.

.. code-block:: yaml

   workers: 4

You can try let the resolver get number of available CPU threads automatically.
If there is a problem, configuration should not pass the validation process.

.. code-block:: yaml

   workers: auto
