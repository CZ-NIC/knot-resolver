.. SPDX-License-Identifier: GPL-3.0-or-later

.. include:: deployment-warning.rst

.. _deployment-no-systemd:

*********************
Usage without systemd
*********************

This page is meant for experienced users, primarily packagers for a deployment without systemd.

.. TODO: we could make this page more detailed, but there won't be many users for it, probably.

Sice version 6.0.0 there is a ``knot-resolver`` process which (indirectly) takes care
of coordinating individual processes of the service,
so that deployments without systemd can be run very similarly to deployments with systemd.


Privileges and capabilities
===========================

The kresd daemon requires privileges when it is configured to bind to
well-known ports. There are multiple ways to achieve this.
(In a container you typically do not need to address this problem.)

Using capabilities
^^^^^^^^^^^^^^^^^^

The most secure and recommended way is to use capabilities and execute kresd as
an unprivileged user.

* ``CAP_NET_BIND_SERVICE`` is required to bind to well-known ports.
* ``CAP_SETPCAP`` when this capability is available, kresd drops any extra
  capabilities after the daemon successfully starts when running as
  a non-root user.

Running as non-privileged user
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Another possibility is to start the process as privileged user and then switch
to a non-privileged user after binding to network interfaces.
On Lua level there's command:

.. function:: user(name, [group])

   :param string name: user name
   :param string group: group name (optional)
   :return: boolean

   Drop privileges and start running as given user (and group, if provided).

   .. tip:: Note that you should bind to required network addresses before
      changing user. At the same time, you should open the cache **AFTER** you
      change the user (so it remains accessible). A good practice is to divide
      configuration in two parts:

      .. code-block:: lua

         -- privileged
         net.listen('127.0.0.1')
         net.listen('::1')
         user('knot-resolver', 'netgrp')
         -- unprivileged
         cache.size = 100*MB

   Example output:

   .. code-block:: lua

      > user('baduser')
      invalid user name
      > user('knot-resolver', 'netgrp')
      true
      > user('root')
      Operation not permitted

Running as root
^^^^^^^^^^^^^^^

.. warning:: Executing processes as root is generally insecure, as these
   processes have unconstrained access to the complete system at runtime.

While not recommended, it is also possible to run kresd directly as root.
