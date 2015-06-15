.. _mod-block:

Query blocking
--------------

This module can block queries (and subqueries) based on user-defined policies.
By default, it blocks queries to reverse lookups in private subnets as per :rfc:`1918`,:rfc:`5735` and :rfc:`5737`.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

