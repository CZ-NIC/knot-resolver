.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-http-trace:

Debugging a single request
==========================

Using query policies
--------------------

Query policies :any:`policy.DEBUG_ALWAYS`, :any:`policy.DEBUG_CACHE_MISS` or
:any:`policy.DEBUG_IF` can be used to enable verbose logging for selected
subdomains or queries matching specific conditions. Please refer to their
documentation for usage.

Using HTTP module
-----------------

The :ref:`http module <mod-http>` provides ``/trace`` endpoint which allows to trace various
aspects of the request execution. The basic mode allows you to resolve a query
and trace verbose logs for it (and messages received):

.. code-block:: bash

   $ curl https://localhost:8453/trace/e.root-servers.net
   [ 8138] [iter] 'e.root-servers.net.' type 'A' created outbound query, parent id 0
   [ 8138] [ rc ] => rank: 020, lowest 020, e.root-servers.net. A
   [ 8138] [ rc ] => satisfied from cache
   [ 8138] [iter] <= answer received:
   ;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 8138
   ;; Flags: qr aa  QUERY: 1; ANSWER: 0; AUTHORITY: 0; ADDITIONAL: 0

   ;; QUESTION SECTION
   e.root-servers.net.		A

   ;; ANSWER SECTION
   e.root-servers.net. 	3556353	A	192.203.230.10

   [ 8138] [iter] <= rcode: NOERROR
   [ 8138] [resl] finished: 4, queries: 1, mempool: 81952 B

See chapter about :ref:`mod-http` for further instructions how to load ``webmgmt``
endpoint into HTTP module, it is a prerequisite for using ``/trace``.
