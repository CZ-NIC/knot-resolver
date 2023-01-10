===============
kresctl utility
===============

This command-line utility allows you to configure and control running Knot Resolver.
For that it uses the above mentioned HTTP API.

For example, folowing command changes the number of ``kresd`` workers to 4.

.. code-block::

    $ kresctl config /workers 4

The utility can also help with configuration **validation** and with configuration format **conversion**.
For more information read full :ref:`kresctl documentation <manager-client>` or use ``kresctl --help`` command.

.. note::

    With no changes in management configuration, ``kresctl`` should work out of the box.
    In other case there is ``-s`` argument to specify path to HTTP API endpoint.