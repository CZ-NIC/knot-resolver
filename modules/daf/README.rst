.. _mod-daf:

DNS Application Firewall
------------------------

This module is a high-level interface for other powerful filtering modules and DNS views. It provides an easy interface to apply and monitor DNS filtering rules and a persistent memory for them. It also provides a restful service interface and an HTTP interface.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

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
    daf.add 'qname ~ %w+.example.com MIRROR 127.0.0.2'

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
