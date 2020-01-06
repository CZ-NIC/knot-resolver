.. _mod-http-trace:

Tracing requests
----------------

The `HTTP module <mod-http>`_ provides ``/trace`` endpoint which allows to trace various
aspects of the request execution. The basic mode allows you to resolve a query
and trace verbose logs (and messages received):

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

See chapter about `HTTP module <mod-http>`_ for further instructions how to load HTTP module.
