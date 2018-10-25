.. _mod-nsid:

Name Server Identifier (NSID)
-----------------------------

This module provides server-side support for :rfc:`5001`
and is not enabled by default.

DNS clients can request resolver to send back its NSID along with reply
to a DNS request. This is useful tool for debugging as it reveals which
particular resolver instance being anycast or a load balancer sent
particular reply.

NSID value can be configured in resolver configuration file:

.. code-block:: lua

   modules.load('nsid')
   nsid.name('instance 1')

You can also obtain configured NSID value:

.. code-block:: lua

   nsid.name()
   instance 1

The module can be disabled at run-time:

.. code-block:: lua

   modules.unload('nsid')
