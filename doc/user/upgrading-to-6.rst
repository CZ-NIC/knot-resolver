.. SPDX-License-Identifier: GPL-3.0-or-later

.. _upgrading-to-6:

************************
Upgrading to version 6.x
************************

The new version 6.x of Knot Resolver brings many major and minor changes.
The most significant one is the introduction of a new process called ``knot-resolver-manager``, which represents a new way of interaction with Knot Resolver:

* easier process management that hides complexities of running multiple instances of the ``kresd`` process (``kresd@1``, ``kresd@2``, ...)
* new :ref:`declarative configuration <config-overview>` in YAML that can be validated before running
* :ref:`manager-api` to change configuration on the fly without downtime
* new :ref:`manager-client` to help with configuration validation and more

Starting with version 6, Knot Resolver uses the new systemd integration ``knot-resolver.service`` instead of ``kresd@.service``.
You can now control the resolver using this systemd service:

.. code-block:: bash

      $ systemctl start knot-resolver # you can also use: stop, restart, reload or enable/disable

There is no need for managing multiple instances of ``kresd@.service`` like before version 6.
However, ``kresd`` processes still run in the background as separate workers and are managed by the new ``knot-resolver-manager`` process.

The number of ``kresd`` workers can be configured directly in the new declarative configuration file.
Knot Resolver's new configuration is located in ``/etc/knot-resolver/config.yaml`` by default.

.. code-block:: yaml

   # /etc/knot-resolver/config.yaml

   workers: 4

See more in :ref:`multiple workers <config-multiple-workers>` documentation.

.. note::

   You might be worried about the future of ``kresd``.
   No worries, you can still use ``kresd`` directly the same way you did before, nothing changes there right now.
   However, in the long run, we can make major changes to the way ``kresd`` is configured and using it directly is considered an advanced practice from now on.

Configuration
=============

Knot Resolver is able to run without any additional configuration, i.e. the configuration file ``/etc/knot-resolver/config.yaml`` may be empty.
The resolver then listens on ``localhost`` with the standard unencrypted DNS protocol port 53.

To write your own configuration, you can start with the :ref:`getting started chapter for configuration <gettingstarted-config>`.

Conversion to |yaml|
--------------------

Lua configuration is considered internal as of version 6 and can be found in the `developer documentation`_, which is separate from the user documentation.

To switch from your old Lua configuration, it is a good idea to open this `developer documentation`_ and find the Lua option you want to convert.
Also open the :ref:`new declarative configuration <configuration-chapter>` documentation. The equivalent |yaml| option will very likely in a similar place.
The documentation structure is basically the same.
Otherwise, you will have to search for the option in the documentation separately.

If you have some custom Lua code in your configuration, you can use it in the :ref:`lua section <config-lua>` of the declarative configuration.
However, it has some limitations and we cannot guarantee 100% functionality.
For example, a configuration that uses the systemd instance name will not work.

Reconfiguration
---------------

To load the modified configuration, use the ``reload`` command.
All running workers will be restarted sequentially, resulting in a zero-downtime configuration reload.
This was not possible before version 6, as it was necessary to manually restart all running ``kresd@`` instances.

.. code-block:: bash

   $ systemctl reload knot-resolver

It is also possible to use :ref:`manager-api` and :ref:`manager-client` for runtime reconfiguration.

Some configuration changes (e.g. changes to the ``management`` key) are not safe to load at runtime, and the resolver then needs to be fully restarted.
You should get a relevant error message if this happens during the resolver reload process.

.. code-block:: bash

   $ systemctl restart knot-resolver

Useful commands rosetta
=======================

In the table below, you can compare the way Knot Resolver was used before and how it can be used now.

==========================================  ===========================================================================================  ==================================================================
Task                                        How to do it now                                                                             How it was done before
==========================================  ===========================================================================================  ==================================================================
start resolver                              ``systemctl start knot-resolver``                                                            ``systemctl start kresd@1``
stop resolver                               ``systemctl stop knot-resolver``                                                             ``systemctl stop kresd@1``
start resolver with 4 worker processes      set ``/workers`` to 4 in the config file                                                     manually start 4 services by ``systemctl start kresd@{1,2,3,4}``
rolling restart after updating config       ``systemctl reload knot-resolver`` (or use API or ``kresctl``)                               manually restart individual ``kresd@`` services one by one
open logs of all instances                  ``journalctl -u knot-resolver``                                                              ``journalctl -u system-kresd.slice``
open log of a single kresd instances        ``journalctl -u knot-resolver _PID=xxx``                                                     ``journalctl -u kresd@1``
updating config programmatically            use HTTP API or ``kresctl`` command                                                          write a custom tool to generate new config and restart ``kresd``'s
handling errors during config changes       HTTP API just reports error, resolver keeps running with previous config                     custom tools for every user
validate new config                         ``kresctl validate path/to/new/config.yaml`` (not fully bullet proof), then try to run it     run ``kresd`` with the config and see if it fails
look at the Lua config                      ``kresctl convert path/to/new/config.yaml``                                                   ``cat /path/to/config.conf``
gather metrics                              point Prometheus etc. at the single HTTP API                                                 collect metrics manually from all individual processes
==========================================  ===========================================================================================  ==================================================================

.. _`developer documentation`: ./dev/index.html
