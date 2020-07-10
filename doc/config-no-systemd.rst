.. SPDX-License-Identifier: GPL-3.0-or-later

.. _usage-without-systemd:

*********************
Usage without systemd
*********************

.. tip:: Our upstream packages use systemd integration, which is the recommended
   way to run kresd. This section is only relevant if you choose to use kresd
   without systemd integration.

Knot Resolver is designed to be a single process without the use of threads.
While the cache is shared, the individual processes are independent.  This
approach has several benefits, but it also comes with a few downsides, in
particular:

* Without the use of threads or forking (deprecated, see `#529`_), multiple
  processes aren't managed in any way by kresd.
* There is no maintenance thread and these tasks have to be handled by separate
  daemon(s) (such as :ref:`garbage-collector`).

To offset these these disadvantages without implementing process management in
kresd (and reinventing the wheel), Knot Resolver provides integration with
systemd, which is widely used across GNU/Linux distributions.

If your use-case doesn't support systemd (e.g. using macOS, FreeBSD, Docker,
OpenWrt, Turris), this section describes the differences and things to keep in
mind when configuring and running kresd without systemd integration.

.. toctree::
   :maxdepth: 2

   config-no-systemd-processes
   config-no-systemd-privileges

.. _`#529`: https://gitlab.nic.cz/knot/knot-resolver/issues/529
