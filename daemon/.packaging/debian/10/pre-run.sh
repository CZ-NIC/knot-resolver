# SPDX-License-Identifier: GPL-3.0-or-later

apt-get update
apt-get install -y wget gnupg apt-utils

echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/knot-resolver-latest/Debian_10/ /' > /etc/apt/sources.list.d/home:CZ-NIC:knot-resolver-latest.list
wget -nv https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-latest/Debian_10/Release.key -O Release.key
apt-key add - < Release.key

apt-get update
apt-get upgrade -y
