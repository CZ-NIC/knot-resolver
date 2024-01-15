*******************
System architecture
*******************

Knot Resolver is split into several components, namely the manager, ``kresd`` and the garbage collector. In addition to these custom components, we also rely on `supervisord <http://supervisord.org/>`_.

.. image:: architecture-supervisor.svg
    :width: 100%
    :alt: Diagram showing process tree and contol relationship between Knot Resolver components. Supervisord is a parent to all processes, namely manager, kresd instances and gc. Manager on the other hand controls every other component and what it does.


There are two different control structures in place. Semantically, the manager controls every other component in Knot Resolver. It processes configuration and passes it onto every other component. As a user you will always interact with the manager (or kresd). At the same time though, the manager is not the root of the process hierarchy, Supervisord sits at the top of the process tree and runs everything else.

.. note::
    The rationale for this inverted process hierarchy is mainly stability. Supervisord sits at the top because it is a reliable and stable software we can depend upon. It also does not process user input and its therefore shielded from data processing bugs. This way, any component in Knot Resolver can crash and restart without impacting the rest of the system.


Knot Resolver startup
=====================

The inverted process hierarchy complicates Resolver's launch procedure. You might notice it when reading manager's logs just after start. What happens on cold start is:

1. Manager starts, reads its configuration and generates new supervisord configuration. Then, it starts supervisord by using ``exec``.
2. Supervisord loads it's configuration, loads our extensions and start a new instance of manager.
3. Manager starts again, this time as a child of supervisord. As this is desired state, it loads the configuration again and commands supervisord that it should start new instances of ``kresd``.


Failure handling
================

Knot Resolver is designed to handle failures automatically. Anything except for supervisord will automatically restart. If a failure is irrecoverable, all processes will stop and nothing will be left behind in a half-broken state. While a total failure like this should never happen, it is possible and you should not rely on single instance of Knot Resolver for a highly-available system.

.. note::
    The ability to restart most of the components without downtime means, that Knot Resolver is able to transparently apply updates while running.


Individual components
=====================

You can learn more about architecture of individual Resolver components in the following chapters.

.. toctree::
    :titlesonly:
    :maxdepth: 1

    architecture-manager
    architecture-kresd
    architecture-gc