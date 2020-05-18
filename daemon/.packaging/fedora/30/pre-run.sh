# SPDX-License-Identifier: GPL-3.0-or-later

dnf install -y wget 'dnf-command(config-manager)'

dnf config-manager --add-repo https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-latest/Fedora_30/home:CZ-NIC:knot-resolver-latest.repo
dnf upgrade -y
