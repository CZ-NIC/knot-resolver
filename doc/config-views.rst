.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-views:

Views and ACLs
==============

Views allow to match clients based on source subnets, e.g. "who asked the query".
This allows you to achieve access control, personalized blacklists and filters based on where a DNS request came from.

Views allow you to combine query source information with other policy rules using :ref:`tags <config-policy-new-tags>`.

The :option:`views <views: <list>>` defines a list of rules.  For each request, the resolver chooses the rule with the most specific subnet matching the client's address (at most one rule may be chosen).
Such a rule may tell the resolver to refuse to answer, set some additional options, or choose which groups of content rules would apply (see :ref:`tags <config-policy-new-tags>`).

.. option:: views: <list>

   .. option:: subnets: <list of subnets>

      Identifies the client based on his subnet.

   .. option:: tags: <list of tags>

      Tags to link view with other policy. Read more about tags :ref:`here <config-policy-new-tags>`.

   .. option:: answer: allow|refused|noanswer

      Optional, direct approach how to handle request from clients identified by a view.

      * **allow** - Clients query resolution is allowed.
      * **refused** - Terminate query resolution and return REFUSED to the requestor.
      * **noanswer** - Terminate query resolution and do not return any answer to the requestor.

      .. warning::

         During normal operation, an answer should always be returned.
         Deliberate query drops are indistinguishable from packet loss and may cause problems as described in :rfc:`8906`.
         Only use **noanswer** on very specific occasions, e.g. as a defense mechanism during an attack, and prefer other actions (e.g. **refused**) for normal operation.

   .. option:: options:

      Specific options for clients identified by the view.

      .. option:: minimize: true|false

         Send minimum amount of information in recursive queries to enhance privacy.

      .. option:: dns64: true|false

         Enable/disable DNS64.

.. code-block:: yaml

   views:
     # only allow answering to specific subnets
     - subnets: [ 0.0.0.0/0, "::/0" ] # words starting with :: need quoting
       answer: refused
     - subnets: [ 10.0.10.0/24, 127.0.0.1, "::1" ]
       answer: allow

.. code-block:: yaml

   views:
     - subnets: [ 2001:db8:1::/56 ]
       tags: [ malware localnames ]
       options:
         dns64: true

.. _RPZ: https://dnsrpz.info/
