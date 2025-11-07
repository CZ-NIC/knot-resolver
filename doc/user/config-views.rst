.. SPDX-License-Identifier: GPL-3.0-or-later

.. _config-views:

Views and ACLs
==============

Views allow to differentiate resolver behavior based on "who asked the query".
This allows you to achieve access control, personalized blocklists and filters based on how the DNS request arrived.

.. code-block:: yaml

   views:
     # only allow answering to specific subnets
     - subnets: [ 0.0.0.0/0, "::/0" ] # words starting with :: need quoting
       answer: refused
     - subnets: [ 10.0.10.0/24, 127.0.0.1, "::1" ]
       answer: allow

Views allow you to combine query source information with other policy rules using :ref:`tags <config-policy-new-tags>`.

.. code-block:: yaml

   views:
     # Apply `malware` and `localnames` rules to these clients and turn off dns64.
     # We'd also need to use these tags inside local-data: to really change anything.
     - subnets: [ 2001:db8:1::/56 ]
       tags: [ malware, localnames ]
       options:
         dns64: false

-----

.. option:: views: <list>

Views define a list of rules where each rule contains some matching condition(s) and some action(s).

For each request, the resolver chooses a single rule matching all of its conditions.
Rules with more precise client subnets have preference, but other priorities are undefined.
The chosen rule may tell the resolver to refuse to answer, set some additional options, or choose which groups of content rules would apply.

Conditions
----------

   .. option:: subnets: <list of subnets>

      Identifies the client based on their source address.
      This is the only mandatory part of each rule.
      You may use ``[ 0.0.0.0/0, "::/0" ]`` to match all external requests.

   .. option:: dst-subnet: <string>

      Destination subnet, i.e. restricting the IP address that accepted the query.

      .. warning::

         If you configured listening on wildcards `0.0.0.0` or `::`,
         the destination address for UDP queries will be just that
         instead of the real address.

   .. option:: protocols: <list of strings>

      List of protocols for the query; subset of:
      ``udp53``, ``tcp53``, ``dot``, ``doh``, ``doq``.

Actions
-------

   .. option:: tags: <list of tags>

      Tags to link view with other policy. Read more about tags :ref:`here <config-policy-new-tags>`.

   .. option:: answer: allow|refused|noanswer

      Direct approach how to handle request from clients identified by a view.

      * **refused** - Terminate query resolution and return REFUSED to the requestor.
      * **allow** - Query resolution is allowed.
        This option is useful for cutting exceptions inside larger disallowed subnets.
      * **noanswer** - Terminate query resolution and do not return any answer to the requestor.

      .. warning::

         During normal operation, an answer should always be returned.
         Deliberate query drops are indistinguishable from packet loss and may cause problems as described in :rfc:`8906`.
         Only use **noanswer** on very specific occasions, e.g. as a defense mechanism during an attack, and prefer other actions (e.g. **refused**) for normal operation.

   .. option:: options:

      Specific options for clients identified by the view.

      .. option:: minimize: true|false

         Send minimum amount of information in recursive queries to enhance privacy.
         Enabled by default.

      .. option:: dns64: true|false

         Disable DNS64 if enabled globally.

      .. option:: fallback: true|false

         Disable fallback on resolution failure, if enabled globally.

      .. option:: price-factor: <float>

          :default: 1.0

          Multiplies prices of operations in :ref:`rate limiting <config-rate-limiting>` and :ref:`defer <config-defer>`;
          i.e. the number of queries is multiplied by the value for rate limiting and the measured time for defer.
          In other words, we can say that
          both :option:`instant-limit <rate-limiting/instant-limit: <int>` and :option:`rate-limit <rate-limiting/rate-limit: <int>`
          are divided by the value and similarly all limits are divided for defer.

          Use ``0.0`` to never use rate limiting and always assign the highest priority level in defer.

          .. warning::

            The effect on defer may be currently limited,
            because some of the measured operations on incoming data occur before processing views
            and the default :option:`price-factor <price-factor: <float>` value is thus used for them.
