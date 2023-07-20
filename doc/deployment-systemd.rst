*******
Systemd
*******

In the default installation, Knot Resolver contains systemd integration and starting it on such system usually involves only one command.

.. code-block:: bash

    systemctl enable --now knot-resolver.service


If you don't have systemd service file for Knot Resolver already installed in your system, you can create one manually with the folling content:


.. literalinclude:: ../systemd/knot-resolver.service.in
    :language: bash

.. note::

    Replace words surrounded by ``@`` to some real values (i.e. ``@user@`` to a user you want Knot Resolver to run as).