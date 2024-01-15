.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-nsid:

Name Server Identifier (NSID)
=============================

Knot Resolver provides server-side support for :rfc:`5001`
which allows DNS clients to request resolver to send back its NSID
along with the reply to a DNS request.
This is useful for debugging larger resolver farms
(e.g. when using multiple instances of Knot Resolver, anycast or load balancers).

NSID value can be configured in the resolver's configuration file:

.. code-block:: yaml

   nsid: kres1

.. note::

   When running with multiple workers, each worker adds its own identifier to the end of the NSID.
