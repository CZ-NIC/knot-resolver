.. _mod-workarounds:

Workarounds
-----------

A simple module that alters resolver behavior on specific broken sub-domains.
Currently it mainly disables case randomization on them.

Running
^^^^^^^
.. code-block:: lua

    modules = { 'workarounds < iterate' }

