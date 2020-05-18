# SPDX-License-Identifier: GPL-3.0-or-later

dnf install -y wget

dnf config-manager --add-repo https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-build/CentOS_8_EPEL/home:CZ-NIC:knot-resolver-build.repo
dnf install -y knot
dnf upgrade -y
