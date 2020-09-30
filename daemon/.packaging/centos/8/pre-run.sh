# SPDX-License-Identifier: GPL-3.0-or-later

dnf install -y wget 'dnf-command(config-manager)' epel-release centos-release

dnf config-manager --enable PowerTools
dnf config-manager --add-repo https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-latest/CentOS_8_EPEL/home:CZ-NIC:knot-resolver-latest.repo
dnf upgrade -y
