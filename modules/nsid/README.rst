.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-nsid:

Name Server Identifier (NSID)
=============================

Module ``nsid`` provides server-side support for :rfc:`5001`
which allows DNS clients to request resolver to send back its NSID
along with the reply to a DNS request.
This is useful for debugging larger resolver farms
(e.g. when using :ref:`systemd-multiple-instances`, anycast or load balancers).

NSID value can be configured in the resolver's configuration file:

.. code-block:: lua

   modules.load('nsid')
   nsid.name('instance 1')

.. tip:: When dealing with Knot Resolver running in `multiple instances`
        managed with systemd see :ref:`instance-specific-configuration`.

You can also obtain configured NSID value:

.. code-block:: lua

   > nsid.name()
   'instance 1'

The module can be disabled at run-time:

.. code-block:: lua

   modules.unload('nsid')
