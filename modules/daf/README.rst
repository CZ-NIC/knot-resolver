.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-daf:

DNS Application Firewall
========================

This module is a high-level interface for other powerful filtering modules and DNS views. It provides an easy interface to apply and monitor DNS filtering rules and a persistent memory for them. It also provides a restful service interface and an HTTP interface.

Example configuration
---------------------

Firewall rules are declarative and consist of filters and actions. Filters have ``field operator operand`` notation (e.g. ``qname = example.com``), and may be chained using AND/OR keywords. Actions may or may not have parameters after the action name.

.. code-block:: lua

    -- Let's write some daft rules!
    modules = { 'daf' }

    -- Block all queries with QNAME = example.com
    daf.add 'qname = example.com deny'

    -- Filters can be combined using AND/OR...
    -- Block all queries with QNAME match regex and coming from given subnet
    daf.add 'qname ~ %w+.example.com AND src = 192.0.2.0/24 deny'

    -- We also can reroute addresses in response to alternate target
    -- This reroutes 1.2.3.4 to localhost
    daf.add 'src = 127.0.0.0/8 reroute 192.0.2.1-127.0.0.1'

    -- Subnets work too, this reroutes a whole subnet
    -- e.g. 192.0.2.55 to 127.0.0.55
    daf.add 'src = 127.0.0.0/8 reroute 192.0.2.0/24-127.0.0.0'

    -- This rewrites all A answers for 'example.com' from
    -- whatever the original address was to 127.0.0.2
    daf.add 'src = 127.0.0.0/8 rewrite example.com A 127.0.0.2'

    -- Mirror queries matching given name to DNS logger
    daf.add 'qname ~ %w+.example.com mirror 127.0.0.2'
    daf.add 'qname ~ example-%d.com mirror 127.0.0.3@5353'

    -- Forward queries from subnet
    daf.add 'src = 127.0.0.1/8 forward 127.0.0.1@5353'
    -- Forward to multiple targets
    daf.add 'src = 127.0.0.1/8 forward 127.0.0.1@5353,127.0.0.2@5353'

    -- Truncate queries based on destination IPs
    daf.add 'dst = 192.0.2.51 truncate'

    -- Disable a rule
    daf.disable 2
    -- Enable a rule
    daf.enable 2
    -- Delete a rule
    daf.del 2

If you're not sure what firewall rules are in effect, see ``daf.rules``:

.. code-block:: text

    -- Show active rules
    > daf.rules
    [1] => {
        [rule] => {
            [count] => 42
            [id] => 1
            [cb] => function: 0x1a3eda38
        }
        [info] => qname = example.com AND src = 127.0.0.1/8 deny
        [policy] => function: 0x1a3eda38
    }
    [2] => {
        [rule] => {
            [suspended] => true
            [count] => 123522
            [id] => 2
            [cb] => function: 0x1a3ede88
        }
        [info] => qname ~ %w+.facebook.com AND src = 127.0.0.1/8 deny...
        [policy] => function: 0x1a3ede88
    }

Web interface
-------------

If you have :ref:`HTTP/2 <mod-http>` loaded, the firewall automatically loads as a snippet.
You can create, track, suspend and remove firewall rules from the web interface.
If you load both modules, you have to load `daf` after `http`.

RESTful interface
-----------------

The module also exports a RESTful API for operations over rule chains.


.. csv-table::
    :header: "URL", "HTTP Verb", "Action"

    "/daf", "GET", "Return JSON list of active rules."
    "/daf", "POST", "Insert new rule, rule string is expected in body. Returns rule information in JSON."
    "/daf/<id>", "GET", "Retrieve a rule matching given ID."
    "/daf/<id>", "DELETE", "Delete a rule matching given ID."
    "/daf/<id>/<prop>/<val>", "PATCH", "Modify given rule, for example /daf/3/active/false suspends rule 3."

This interface is used by the web interface for all operations, but you can also use it directly
for testing.

.. code-block:: bash

    # Get current rule set
    $ curl -s -X GET http://localhost:8453/daf | jq .
    {}

    # Create new rule
    $ curl -s -X POST -d "src = 127.0.0.1 pass" http://localhost:8453/daf | jq .
    {
      "count": 0,
      "active": true,
      "info": "src = 127.0.0.1 pass",
      "id": 1
    }

    # Disable rule
    $ curl -s -X PATCH http://localhost:8453/daf/1/active/false | jq .
    true

    # Retrieve a rule information
    $ curl -s -X GET http://localhost:8453/daf/1 | jq .
    {
      "count": 4,
      "active": true,
      "info": "src = 127.0.0.1 pass",
      "id": 1
    }

    # Delete a rule
    $ curl -s -X DELETE http://localhost:8453/daf/1 | jq .
    true
