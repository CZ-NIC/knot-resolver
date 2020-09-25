.. SPDX-License-Identifier: GPL-3.0-or-later

Notes for packagers
-------------------

*  kresd.target should be enabled by default by linking it to systemd lib/
   directory. Instances of kresd@.service are then added manually to
   kresd.target when the user enables them.
*  Distributions using systemd-sysv-generator should mask kresd.service to
   be consistent with other distributions. Any use of kresd.service instead of
   kresd@N.service is discouraged to avoid confusing the users.
