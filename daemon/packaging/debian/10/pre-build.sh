# SPDX-License-Identifier: GPL-3.0-or-later

# add debian build repository
apt-get update
apt-get install -y wget gnupg apt-utils
echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/knot-resolver-build/Debian_10/ /' > /etc/apt/sources.list.d/home:CZ-NIC:knot-resolver-build.list
wget https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-build/Debian_Next/Release.key -O Release.key
apt-key add - < Release.key

apt-get update
apt-get upgrade -y
