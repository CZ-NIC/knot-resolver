# SPDX-License-Identifier: GPL-3.0-or-later

# add build repository
apt-get update
apt-get install -y wget gnupg apt-utils

echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/knot-resolver-latest/xUbuntu_20.04/ /' > /etc/apt/sources.list.d/home:CZ-NIC:knot-resolver-latest.list
wget -nv https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-latest/xUbuntu_20.04/Release.key -O Release.key
apt-key add - < Release.key

apt-get update
apt-get upgrade -y
