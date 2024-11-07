.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-performance:

**************************
Performance and resiliency
**************************

For DNS resolvers, the most important parameter from performance perspective
is cache hit rate, i.e. percentage of queries answered from resolver's cache.
Generally the higher cache hit rate the better.

Performance tunning should start with cache :ref:`config-cache-sizing`
and :ref:`config-cache-persistence`.

.. It is also recommended to run :ref:`systemd-multiple-instances` (even on a
.. single machine!) because it allows to utilize multiple CPU threads and
.. increases overall resiliency.

Other features described in this section can be used for fine-tunning
performance and resiliency of the resolver but generally have much smaller
impact than cache settings and number of instances.

.. toctree::
   :maxdepth: 1

   config-cache
   config-multiple-workers
   config-cache-predict
   config-cache-prefill
   config-serve-stale
   config-rfc7706
   config-priming
   config-edns-keepalive
   config-rate-limiting
