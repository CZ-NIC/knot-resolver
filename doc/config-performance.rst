.. SPDX-License-Identifier: GPL-3.0-or-later

.. _performance:

**************************
Performance and resiliency
**************************

For DNS resolvers, the most important parameter from performance perspective
is cache hit rate, i.e. percentage of queries answered from resolver's cache.
Generally the higher cache hit rate the better.

Performance tunning should start with cache :ref:`cache_sizing`
and :ref:`cache_persistence`.

It is also recommended to run :ref:`systemd-multiple-instances` (even on a
single machine!) because it allows to utilize multiple CPU threads and
increases overall resiliency.

Other features described in this section can be used for fine-tunning
performance and resiliency of the resolver but generally have much smaller
impact than cache settings and number of instances.

.. toctree::
   :maxdepth: 1

   daemon-bindings-cache
   systemd-multiinst
   modules-predict
   modules-prefill
   modules-serve_stale
   modules-rfc7706
   modules-priming
   modules-edns_keepalive

