=====================
Legacy daemon startup
=====================

Legacy way to run single instance of Knot Resolver daemon is to use ``kresd@`` systemd integration:

.. code-block:: bash

   $ sudo systemctl start kresd@1.service


========================
Legacy Lua configuration
========================

Legacy way to configure Knot Resolver daemon is to paste your configuration into configuration file ``/etc/knot-resolver/kresd.conf``.
When using this configuration approach, the daemon must be started using legacy systemd service ``kresd@``.

.. note::

    When copy&pasting examples from this manual please pay close
    attention to brackets and also line ordering - order of lines matters.

    The configuration language is in fact Lua script, so you can use full power
    of this programming language. See article
    `Learn Lua in 15 minutes <http://tylerneylon.com/a/learn-lua/>`_ for a syntax overview.